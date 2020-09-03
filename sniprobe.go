/*
Copyright 2017 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

// sniprobe is a tool for probing websites and making sure the certificate matches.
// It also does basic response content and status checking.

// Does not follow redirects, because we're interested in the initial
// SSL cert.

// basic usage:
// go run sniprobe.go --connect 10.0.100.75:30443 --host noc.perl.org --match "Perl" --proxy

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"

	goflag "flag"

	flag "github.com/spf13/pflag"

	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/golang/glog"
)

// NagiosCode represents the return value of the probe.
type NagiosCode int

const (
	// OK status (probe passed)
	OK NagiosCode = iota
	// WARNING status
	WARNING
	// CRITICAL status (failure)
	CRITICAL
	// UNKNOWN status
	UNKNOWN
)

// NagiosCodeString maps the NagiosCode constants to string values.
var NagiosCodeString = map[NagiosCode]string{
	OK:       "OK",
	WARNING:  "WARNING",
	CRITICAL: "CRITICAL",
	UNKNOWN:  "UNKNOWN",
}

var (
	host     = flag.StringP("host", "h", "", "Hostname to connect to")
	connect  = flag.StringP("connect", "c", "", "host:port to connect to")
	dump     = flag.BoolP("dump", "d", false, "Dump body to stdout")
	match    = flag.StringP("match", "m", "", "String to check for in body")
	status   = flag.IntP("status", "s", 200, "Status code to check for in response")
	path     = flag.StringP("path", "p", "/", "Path of URL")
	useProxy = flag.Bool("proxy", false, "Use HAPRoxy protocol")
	src      = flag.StringP("src", "", "", "source URL")
	dest     = flag.StringP("dest", "", "", "dest URL")
	maxAge   = flag.DurationP("maxage", "M", 0, "max age of result")
)

func noRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

func exit(c NagiosCode, err error) {
	exitF(c, err.Error())
}

func exitF(c NagiosCode, format string, a ...interface{}) {
	fmt.Printf("%s - %s\n", NagiosCodeString[c], fmt.Sprintf(format, a...))
	os.Exit(int(c))
}

func splitAddr(a net.Addr) (host, port string) {
	p := strings.SplitN(a.String(), ":", 2)
	return p[0], p[1]
}

func proxyDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// PROXY protocol is documented at
	// https://www.haproxy.org/download/1.8/doc/useProxy-protocol.txt
	d := &net.Dialer{ // defaults from net/http/transport.go
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	localIP, localPort := splitAddr(conn.LocalAddr())
	remoteIP, remotePort := splitAddr(conn.RemoteAddr())
	fmt.Fprintf(conn, "PROXY TCP4 %s %s %s %s\r\n", localIP, remoteIP, localPort, remotePort)
	return conn, nil
}

var hostPortRe = regexp.MustCompile(`^\w+(?::\d+)$`)

func main() {
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)
	flag.Parse()
	goflag.CommandLine.Parse([]string{}) // workaround for https://github.com/golang/glog/commit/fca8c8854093a154ff1eb580aae10276ad6b1b5f to set parsed bit.

	url := &url.URL{
		Scheme: "https",
		Host:   *connect, // host to connect to
		Path:   *path,
	}

	if len(*src) != 0 {
		u, err := url.Parse(*src)
		if err != nil {
			exitF(UNKNOWN, "parse error on source %q: %v", u, err)
		}
		*host = u.Host
		*path = u.Path
		url = u
	}

	if len(*host) == 0 {
		exitF(UNKNOWN, "required flag --host not provided")
	}

	if len(*connect) == 0 || hostPortRe.MatchString(*connect) {
		// --connect not specified, defaulting to --host
		*connect = *host
	}

	client := newClient(host, *useProxy)
	request := &http.Request{
		Method: "GET", // default
		URL:    url,
		Host:   *host, // Host: header
	}
	glog.V(2).Infof("Request: %+v", request)
	resp, err := client.Do(request)
	if err != nil {
		exitF(CRITICAL, "http client error: %v", err)
	}
	glog.V(2).Infof("Response: %+v", resp)
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		exit(CRITICAL, err)
	}
	if *dump {
		fmt.Printf("%s", body)
	}

	if url.Scheme == "https" {
		cert := resp.TLS.PeerCertificates[0]
		glog.Infof("Certificate CommonName: %s\n", cert.Subject.CommonName)

		err = checkCert(cert, host)
		if err != nil {
			exit(CRITICAL, err)
		}
	}
	if len(*dest) > 0 {
		loc, err := resp.Location()
		if err != nil {
			exit(CRITICAL, err)
		}

		if loc.String() != *dest {
			exitF(CRITICAL, "Location %q doesn't match destination %q", loc, *dest)
		}
	}
	err = checkBodyMatch(body, *match)
	if err != nil {
		exit(CRITICAL, err)
	}

	err = checkFresh(resp.Header, *maxAge)
	if err != nil {
		exit(CRITICAL, err)
	}

	if resp.StatusCode != *status {
		exitF(CRITICAL, "wrong status code: got %d, want %d", resp.StatusCode, *status)
	}

	exitF(OK, "%s%s", *host, *path)
}

func newClient(host *string, useProxy bool) *http.Client {
	tr := &http.Transport{
		IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{
			ServerName: *host, // SNI hostname
		},
	}

	if useProxy {
		tr.DialContext = proxyDialContext
	}

	return &http.Client{
		Transport:     tr,
		CheckRedirect: noRedirect,
	}
}

func checkBodyMatch(body []byte, match string) error {
	if match != "" && !strings.Contains(string(body), match) {
		return fmt.Errorf("%q not found in body", match)
	}
	return nil
}

func matchWildcard(got, want string) bool {
	if want[0:2] == "*." {
		wantParts := strings.Split(want[2:], ".")
		gotParts := strings.Split(got, ".")

		if len(wantParts) > len(gotParts) {
			return false
		}

		gotParts = gotParts[len(gotParts)-len(wantParts):]

		for i := range gotParts {
			if gotParts[i] != wantParts[i] {
				return false
			}
		}
		return true
	}
	return got == want
}

func checkCert(cert *x509.Certificate, host *string) error {

	if matchWildcard(*host, cert.Subject.CommonName) {
		return nil
	}

	for _, n := range cert.DNSNames {
		if matchWildcard(*host, n) { // if n == *host {
			return nil
		}
	}

	return fmt.Errorf("Cert CN != hostname: want %s, got %s", cert.Subject.CommonName, *host)
}

func checkFresh(hs http.Header, max time.Duration) error {
	if max == 0 {
		return nil
	}
	lm := hs.Get("Last-Modified")
	if lm == "" {
		return errors.New("no Last-Modified header")
	}
	lmt, err := time.Parse(time.RFC1123, lm)
	if err != nil {
		return err
	}

	sd := hs.Get("Date")
	sdt, err := time.Parse(time.RFC1123, sd)
	if err != nil {
		sdt = time.Now()
	}
	ago := sdt.Sub(lmt)
	if ago > max {
		return fmt.Errorf("modifed %v ago > %v", ago, max)
	}
	return nil
}

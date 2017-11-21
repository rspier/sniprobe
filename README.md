# sniprobe

sniprobe is a nagios-style probe tool for validating hosts that use
TLS with SNI to make sure the certificate configuration is correct.
It can also be used as a generic https probe to test redirects and
simple content.

It's similar to Nagios' `check_http` script.

This is not an official Google project.

## Example Nagios usage

    # Make sure that the host at $ARG1$ (host:port) serves the $ARG2$
    # certificate.
    define command {
        command_name    sniprobe
        command_line    /etc/nagios/commands/sniprobe --connect $ARG1$ --host $ARG2$
    }

    # Same, but connect to a backend at $ARG3$ that expects the PROXY protocol.
    define command {
        command_name    sniprobe_proxy
        command_line    /etc/nagios/commands/sniprobe --connect $ARG1$ --host $ARG2$ --proxy $ARG3$
    }

    # Test a redirect from $ARG1$ to $ARG2$ of status $ARG3$.
    define command {
	    command_name    check_http_redirect_sni
	    command_line    /etc/nagios/commands/sniprobe --src '$ARG1$' --dest '$ARG2$' -s '$ARG3$'
    }

## Why?

Once upon a time, there was a Nagios server running on an older
install of Linux where newer versions of TLS+SNI weren't supported by
it's version of OpenSSL.  Upgrading that box would have required Sam
Sysadmin to go to grandmas house to pick up some hardare.  The direct
route took him through the woods -- where there had been report of
wolves hanging near the the bridge over the river.  He didn't want to
get eaten, and didn't have time to go the long way around.  He had to
get his cow to market.  So instead, he wrote a small go program.
Which grew and grew... until it's what you see today.

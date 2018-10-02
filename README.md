# Active Directory Password App

For those situations where you have infrastructure backed by Microsoft
Active Directory for authentication.  This uses Kerberos and LDAP commands
to work out when your password will expire and notify you of impending lock
outs.

## Requirements

### System Binaries

* heimdal-clients
* ldap-utils
* libsasl2-modules-gssapi-mit

### Python Libraries

* python-gtk
* python-ldap
* python-setuptools

## Building

    make && make install

## Running

To run from the local console simply execute:

    adpasswd --daemonize

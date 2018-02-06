"""
Placeholder
"""

import datetime
import json
import logging
import re
import subprocess
import tempfile

class KerberosTicket(object):
    """
    Container around a Kerberos ticket
    'issued' and 'expires' are python datetime objects
    """

    def __init__(self, issued, expires, principal):
        self.issued = issued
        self.exipres = expires
        self.principal = principal

    @property
    def service(self):
        """Return the service component of the principal"""

        return self.principal.split('@')[0]

    @property
    def realm(self):
        """Return the realm component of the principal"""

        return self.principal.split('@')[1]


class KerberosTickets(object):
    """
    Manages Kerberos tickets on the system
    """

    def __init__(self, realm, username, password):
        self.realm = realm
        self.username = username
        self.password = password
        self.tickets = []
        self.date_format = '%b %d %H:%M:%S %Y'


    def klist(self):
        """
        Lists active tickets on the system, clients need to manually
        check the ticket list to interrogate success state
        """

        # Reset the tickets we know about
        self.tickets = []

        # Run klist to grab the current tickets the system knows about
        command = ['/usr/bin/klist', '--json']
        try:
            output = subprocess.check_output(command)
        except subprocess.CalledProcessError:
            logging.warn('Call to klist failed')
            return
        output = json.loads(output)

        # Parse existing tickets discarding any expired ones e.g.
        # Jan 10 15:48:00 2018  >>>Expired<<<  krbtgt/CORP.COUCHBASE.COM@CORP.COUCHBASE.COM
        for ticket in output['tickets']:
            issued = datetime.datetime.strptime(ticket['Issued'], self.date_format)
            try:
                expires = datetime.datetime.strptime(ticket['Expires'], self.date_format)
            except ValueError:
                # This effectively ignores tickets that have expired
                continue
            ticket = KerberosTicket(issued, expires, ticket['Principal'])
            self.tickets.append(ticket)

        if not self.tickets:
            logging.info('No active tickets found')


    def kinit(self):
        """
        Get a new TGT from the KDC
        """

        # Sadly kinit communicates via /dev/tty so we cannot use
        # Popen.communicate, but it does support a file path...
        password = tempfile.NamedTemporaryFile()
        password.write(self.password)
        password.flush()

        principal = self.username + '@' + self.realm
        command = ['/usr/bin/kinit', '--enterprise', '--password-file=' + password.name, principal]

        try:
            subprocess.check_call(command)
        except subprocess.CalledProcessError:
            logging.warn('Call to kinit failed')


    def has_tgt(self):
        """
        Do we have a valid TGT?
        """

        return any(t.service.startswith('krbtgt/') for t in self.tickets)


# vi: ts=4 et:

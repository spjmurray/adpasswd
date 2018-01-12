from datetime import datetime, timedelta
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from pkg_resources import resource_filename

from dns import resolver
import gtk
import gobject


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
        return self.principal.split('@')[0]

    @property
    def realm(self):
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
        command = ['/usr/bin/klist']
        try:
            output = subprocess.check_output(command)
        except subprocess.CalledProcessError as error:
            logging.warn('Call to klist failed')
            return

        # Parse existing tickets discarding any expired ones e.g.
        # Jan 10 15:48:00 2018  >>>Expired<<<  krbtgt/CORP.COUCHBASE.COM@CORP.COUCHBASE.COM
        entries = output.split("\n")[4:-1]
        for entry in entries:
            issued, expires, principal = re.split(r'\s{2,}', entry)
            issued = datetime.strptime(issued, self.date_format)
            try:
                expires = datetime.strptime(expires, self.date_format)
            except ValueError:
                # This effectively ignores tickets that have expired
                continue
            ticket = KerberosTicket(issued, expires, principal)
            self.tickets.append(ticket)

        if not len(self.tickets):
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


class DNS(object):
    """
    Helper for DNS related functions
    """

    @staticmethod
    def get_services(service, protocol, domain):
        # See RFC 2782
        srv = '_' + service + '._' + protocol + '.' + domain

        # Get all resources for the service
        dns = resolver.Resolver()
        res = dns.query(srv, 'SRV')

        # For now just return the host name, which is required by GSS binding
        # to LDAP
        return [x.target.to_text(omit_final_dot=True) for x in res]


class Configuration(object):
    """
    Basic configuration cache and persistence abstraction
    """

    def __init__(self):
        self.realm = ''
        self.username = ''
        self.password = ''

        self.confdir = os.environ['HOME'] + '/.adpasswd'
        self.conffile = self.confdir + '/' + 'config.json'

        if not os.access(self.confdir, os.F_OK):
            os.mkdir(self.confdir)
        
        if os.access(self.conffile, os.F_OK):
            with open(self.conffile) as conf:
                inp = json.loads(conf.read())
            self.realm = inp['realm']
            self.username = inp['username']
            self.password = inp['password']

    def flush(self):
        out = {
            'realm': self.realm,
            'username': self.username,
            'password': self.password,
        }
        with open(self.conffile, 'w') as conf:
            conf.write(json.dumps(out))


class LDAP(object):
    """
    Helper for AD LDAP related operations
    """

    def __init__(self, realm):
        self.realm = realm

    def base_dn(self):
        return ','.join('dc=' + x for x in self.realm.split('.'))

    def search(self, query='(objectCLass=*)', attributes=[]):
        base = self.base_dn()
        command = ['ldapsearch', '-N', '-LLL', '-b', base, query] + attributes
        try:
            output = subprocess.check_output(command)
        except subprocess.CalledProcessError:
            raise RuntimeError

        # Filter out blank lines or comments
        output = [x for x in output.split("\n") if re.match(r'[\w\d-]+:', x)]

        # Return a dictionary of key/value pairs
        return dict([tuple(x.split(': ', 1)) for x in output])

    @staticmethod
    def datetime_fromtimestamp(timestamp):
        """
        Converts LDAP timestamps into a datetime object
        """

        ldap_epoch = datetime(1601, 1, 1)
        unix_epoch = datetime(1970, 1, 1)

        # LDAP timestamps are in units of 100 nano-seconds, so scale up to seconds
        timestamp /= 10000000

        # Return the timestamp less the difference between the two epochs
        return datetime.fromtimestamp(timestamp) - (unix_epoch - ldap_epoch)


class StartDialog(object):
    """
    Startup dialog responsible for ephemeral configuration
    """

    def submit(self, widget, data=None):
        """Commit text fields, destroy the window and continue execution"""

        # Write out the new configuration
        self.config.realm = self.realm_widget.get_text()
        self.config.username = self.username_widget.get_text()
        self.config.password = self.password_widget.get_text()
        self.config.flush()

        # Destroy the window and leave the event loop
        self.window.destroy()
        gtk.main_quit()

    def delete(self, widget, data=None):
        """Destroy the window cleanly and exit the application"""

        self.window.destroy()
        gtk.main_quit()
        sys.exit()

    def __init__(self, config):
        self.config = config

        # Top level welcome window
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.window.set_title('AD Passwd')
        self.window.set_icon_from_file(resource_filename('adpasswd', 'icons/lock.png'))
        self.window.set_border_width(10)
        self.window.connect('delete_event', self.delete)

        # Contains a vertical box of widgets
        vbox = gtk.VBox(False, 0)

        # First is a table of labels to text fields
        table = gtk.Table(3, 2, False)
        table.set_row_spacings(5)
        table.set_col_spacings(5)

        label = gtk.Label('Realm')
        table.attach(label, 0, 1, 0, 1)

        self.realm_widget = gtk.Entry()
        self.realm_widget.set_text(self.config.realm)
        table.attach(self.realm_widget, 1, 2, 0, 1)

        label = gtk.Label('Username')
        table.attach(label, 0, 1, 1, 2)

        self.username_widget = gtk.Entry()
        self.username_widget.set_text(self.config.username)
        table.attach(self.username_widget, 1, 2, 1, 2)

        label = gtk.Label('Password')
        table.attach(label, 0, 1, 2, 3)

        self.password_widget = gtk.Entry()
        self.password_widget.set_text(self.config.password)
        self.password_widget.set_visibility(False)
        table.attach(self.password_widget, 1, 2, 2, 3)

        # Last is the submit button
        self.button = gtk.Button('Submit')
        self.button.connect('clicked', self.submit, None)

        vbox.pack_start(table, False, False, 0)
        vbox.pack_start(self.button, False, False, 5)

        self.window.add(vbox)
        self.window.show_all()


    def main(self):
        gtk.main()


class MainDialog(object):

    def delete(self, widget, data=None):
        """Destroy the window cleanly and exit the application"""
        self.window.destroy()
        gtk.main_quit()
        sys.exit()

    def error(self, message):
        self.window.set_icon_from_file(resource_filename('adpasswd', 'icons/lock-error.png'))
        self.label.set_text(message)

    def warn(self, message):
        self.window.set_icon_from_file(resource_filename('adpasswd', 'icons/lock-warn.png'))
        self.label.set_text(message)

    def ok(self, message):
        self.window.set_icon_from_file(resource_filename('adpasswd', 'icons/lock-ok.png'))
        self.label.set_text(message)

    def update(self):
        # Initialise the ticketing engine
        tickets = KerberosTickets(self.config.realm, self.config.username, self.config.password)

        # Look for a valid TGT, if none is found try getting a new one from the KDC
        tickets.klist()
        if not tickets.has_tgt():
            tickets.kinit()
            tickets.klist()

        # Still no TGT :/
        if not tickets.has_tgt():
            self.error('Unable to get TGT from KDC')
            return True

        # Next get the LDAP SRV records for the realm
        try:
            servers = DNS.get_services('ldap', 'tcp', self.config.realm)
        except DNSException:
            self.error('Unable to query DNS')
            return True

        # Finally for each server, try get the user entry in LDAP
        for server in servers:
            ldap = LDAP(self.config.realm)
            query = '(sAMAccountName=' + self.config.username + ')'
            attributes = [
                'msDS-UserPasswordExpiryTimeComputed',
            ]
            try:
                result = ldap.search(query, attributes)
                break
            except RuntimeError:
                continue
        else:
            self.error('Unable to query AD LDAP')
            return True

        # Convert the expiry time from LDAP into UNIX, and work out the time left
        expiry = int(result['msDS-UserPasswordExpiryTimeComputed'])
        expires = LDAP.datetime_fromtimestamp(expiry)
        left = expires - datetime.now()

        # Report the freshness of the password
        callback = self.warn if left < timedelta(7) else self.ok
        callback('Password expires in {}'.format(left))

        return True

    def __init__(self, config):
        self.config = config

        # Create the basic main window
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.window.set_title('AD Password')
        self.window.set_icon_from_file(resource_filename('adpasswd', 'icons/lock.png'))
        self.window.set_border_width(10)
        self.window.connect('delete_event', self.delete)

        self.label = gtk.Label('Initializing ...')

        self.window.add(self.label)

        # Get an initial status
        self.update()

        # Show the window (in particular the icon) and minimise the window
        self.window.show_all()
        self.window.iconify()

        # Poll the AD server once every hour
        self.timer = gobject.timeout_add(60 * 60 * 1000, self.update)

    def main(self):
        gtk.main()



def entry():
    # Setup logging to standard out
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    # Load up configuration
    config = Configuration()

    # Fire up the initial dialog for configuration
    dialog = StartDialog(config)
    dialog.main()

    # Fire up the main dialog window
    main = MainDialog(config)
    main.main()


# vi: ts=4 et:

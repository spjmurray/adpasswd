"""
Placeholder
"""

import argparse
from datetime import datetime, timedelta
import logging
import os
import sys

import gtk
import gobject
from pkg_resources import resource_filename

from adpasswd.configuration import Configuration
from adpasswd.dnshelper import DNS
from adpasswd.kerberos import KerberosTickets
from adpasswd.ldap import LDAP


class StartDialog(object):
    """
    Startup dialog responsible for ephemeral configuration
    """

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

        label = gtk.Label('')
        label.set_markup('<b>Please enter your AD credentials</b>')
        label.set_line_wrap(True)
        vbox.pack_start(label, False, False, 0)

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

        vbox.pack_start(table, False, False, 10)
        vbox.pack_start(self.button, False, False, 0)

        self.window.add(vbox)
        self.window.show_all()


    def submit(self, _widget, _data=None):
        """Commit text fields, destroy the window and continue execution"""

        # Write out the new configuration
        self.config.realm = self.realm_widget.get_text()
        self.config.username = self.username_widget.get_text()
        self.config.password = self.password_widget.get_text()
        self.config.flush()

        # Destroy the window and leave the event loop
        self.window.destroy()
        gtk.main_quit()


    def delete(self, _widget, _data=None):
        """Destroy the window cleanly and exit the application"""

        self.window.destroy()
        gtk.main_quit()
        sys.exit()


    @staticmethod
    def run():
        """Run the GTK event loop"""
        gtk.main()


class MainDialog(object):
    """
    Main dialog window showing the time remaining
    """

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


    def delete(self, _widget, _data=None):
        """Destroy the window cleanly and exit the application"""
        self.window.destroy()
        gtk.main_quit()
        sys.exit()


    def error(self, message):
        """Report an error and update the application icon"""
        self.window.set_icon_from_file(resource_filename('adpasswd', 'icons/lock-error.png'))
        self.label.set_text(message)


    def warn(self, message):
        """Report a warning and update the application icon"""
        self.window.set_icon_from_file(resource_filename('adpasswd', 'icons/lock-warn.png'))
        self.label.set_text(message)


    def good(self, message):
        """Report a good health and update the application icon"""
        self.window.set_icon_from_file(resource_filename('adpasswd', 'icons/lock-ok.png'))
        self.label.set_text(message)


    def update(self):
        """Update the application state"""

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
        except RuntimeError:
            self.error('Unable to query DNS')
            return True

        # Finally for each server, try get the user entry in LDAP
        for server in servers:
            ldap = LDAP(self.config.realm, server)
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
        if expiry == 0x7fffffffffffffff:
            self.good('Password never expires')
            return True

        expires = LDAP.datetime_fromtimestamp(expiry)
        left = expires - datetime.now()

        # Report the freshness of the password
        callback = self.warn if left < timedelta(14) else self.good
        callback('Password expires in {}'.format(left))

        return True


    @staticmethod
    def run():
        """Run the GTK eventloop"""
        gtk.main()


def daemonize():
    """Detach from the parent process and run as a daemon"""

    # Fork and exit from the parent
    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    # Become the session and proccess group leader
    os.setsid()

    # Exit the session leader
    pid = os.fork()
    if pid > 0:
        sys.exit()

    # Change to root so we aren't dependant on a mounted file system
    os.chdir('/')

    # Allow open/creat to provide their own masks uncoupled from the parent
    os.umask(0)

    # Close all standard file descriptors and replace with null versions
    stdin = file('/dev/null', 'r')
    stdout = file('/dev/null', 'a+')
    stderr = file('/dev/null', 'a+', 0)
    os.dup2(stdin.fileno(), sys.stdin.fileno())
    os.dup2(stdout.fileno(), sys.stdout.fileno())
    os.dup2(stderr.fileno(), sys.stderr.fileno())


def entry():
    """Main entry point"""

    # Parse command line parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--daemonize', default=False, action='store_true')
    args = parser.parse_args()

    # Deamonize if we should
    if args.daemonize:
        daemonize()

    # Setup logging to standard out
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    # Load up configuration
    config = Configuration()

    # Fire up the initial dialog for configuration
    dialog = StartDialog(config)
    dialog.run()

    # Fire up the main dialog window
    main = MainDialog(config)
    main.run()


# vi: ts=4 et:

"""
Placeholder
"""

import datetime
import re
import subprocess


class LDAP(object):
    """
    Helper for AD LDAP related operations
    """

    def __init__(self, realm, server):
        self.realm = realm
        self.server = server


    def base_dn(self):
        """Splits a realm into parts and 'guesses' the base DN"""

        return ','.join('dc=' + x for x in self.realm.split('.'))


    def search(self, filterstr='(objectCLass=*)', attributes=None):
        """Search the directory with a filter and a set of attributes"""

        base = self.base_dn()
        command = ['ldapsearch', '-Q', '-N', '-LLL', '-h', self.server, '-b', base, filterstr]
        if attributes:
            command += attributes
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

        ldap_epoch = datetime.datetime(1601, 1, 1)
        unix_epoch = datetime.datetime(1970, 1, 1)

        # LDAP timestamps are in units of 100 nano-seconds, so scale up to seconds
        timestamp /= 10000000

        # Return the timestamp less the difference between the two epochs
        return datetime.datetime.fromtimestamp(timestamp) - (unix_epoch - ldap_epoch)


# vi: ts=4 et:

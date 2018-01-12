"""
Placeholder
"""

import json
import os


class Configuration(object):
    """
    Basic configuration cache and persistence abstraction
    """

    # pylint: disable=too-few-public-methods

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
        """Flush configuration to a cache"""

        out = {
            'realm': self.realm,
            'username': self.username,
            'password': self.password,
        }
        with open(self.conffile, 'w') as conf:
            conf.write(json.dumps(out))


# vi: ts=4 et:

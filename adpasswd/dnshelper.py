"""
Placeholder
"""

from dns import resolver


class DNS(object):
    """
    Helper for DNS related functions
    """

    # pylint: disable=too-few-public-methods

    @staticmethod
    def get_services(service, protocol, domain):
        """Lookup n SRV record and return the hosts"""

        # See RFC 2782
        srv = '_' + service + '._' + protocol + '.' + domain

        # Get all resources for the service
        dns = resolver.Resolver()
        try:
            res = dns.query(srv, 'SRV')
        except:
            raise RuntimeError

        # For now just return the host name, which is required by GSS binding
        # to LDAP
        return [x.target.to_text(omit_final_dot=True) for x in res]


# vi: ts=4 et:

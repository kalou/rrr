from xmlrpc import client

from . import config



class Registrar:
    """Base class for a fake registrar"""
    def __init__(self):
        self.rpc = client.Server(config.get('api.url'), allow_none=True)
        self.key = config.get('api.key')

    def has_domain(self, domain):
        """Implement the check for domain here - so we raise
        a 404 when needed"""
        try:
            self.rpc.domain.dnssec.list(self.key, domain)
            return True
        except xmlrpclib.Fault as f:
            if f.faultCode == 510050: # OBJECT_DOMAIN/CAUSE_NORIGHT
                return True
            else:
                print('XmlRpc exception %s' % f)
        except Exception as e:
            print('EXC %s' % e)

    def set_keys(self, domain, dnskeys):
        """dnskeys is a list of keys - set_keys atomically
        replaces the domain's keys with the provided set.
        Eventually returning an operation reference"""
        def pubkey(k):
            return ''.join(k.to_text().split(' ')[3:])
        api_keys = [{'algorithm': k.algorithm,
                     'public_key': pubkey(k), 'flags': k.flags}
                    for k in dnskeys]
        op = self.rpc.domain.dnssec.set(self.key, domain, api_keys)
        return op['id']

    def get_info(self, ref):
        """Maybe that"""
        return self.rpc.operation.info(self.key, ref)

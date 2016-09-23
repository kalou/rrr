class Registrar:
    """Base class for a fake registrar"""
    def has_domain(self, domain):
        """Implement the check for domain here - so we raise
        a 404 when needed"""
        return len(domain) % 2 == 0

    def set_keys(self, domain, dnskeys):
        """dnskeys is a list of keys - set_keys atomically
        replaces the domain's keys with the provided set.
        Eventually returning an operation reference"""
        return 'never_ending_op'

    def get_info(self, ref):
        """Maybe that"""
        opers = {
            'never_ending_op': {'status': 'not_yet'}
        }

        return opers.get(ref)

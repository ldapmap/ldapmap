import requests
from ldapmap_attacker.plugins.base import BaseDetector


class BooleanBasedDetector(BaseDetector):
    def __init__(self, options=None):
        super().__init__(options)
        self.threshold = self.options.get("threshold", 50)

    def detect(self, response, payload, baseline=None):
        txt = response.text
        ln = len(response.content)

        ev = {"detector": "boolean", "code": response.status_code, "len": ln, "diffs": []}

        if baseline:
            base_ln = len(baseline.encode())
            diff = abs(ln - base_ln)

            if diff > self.threshold:
                ev["diffs"].append("len diff: " + str(diff))

            if baseline not in txt and txt not in baseline:
                ev["diffs"].append("struct changed")

        if response.status_code != 200:
            ev["diffs"].append("status: " + str(response.status_code))

        is_vuln = len(ev["diffs"]) > 0
        return is_vuln, ev

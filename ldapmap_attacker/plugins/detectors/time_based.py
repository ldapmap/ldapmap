import time
import requests
from ldapmap_attacker.plugins.base import BaseDetector


class TimeBasedDetector(BaseDetector):
    def __init__(self, options=None):
        super().__init__(options)
        self.delay_thresh = self.options.get("delay_threshold", 2.0)

    def detect(self, response, payload, baseline=None):
        elapsed = getattr(response, 'elapsed', None)
        rt = elapsed.total_seconds() if elapsed else 0

        ev = {"detector": "time", "code": response.status_code, "time": rt, "anoms": []}

        if rt > self.delay_thresh:
            ev["anoms"].append("slow: " + str(round(rt, 2)) + "s")

        is_vuln = len(ev["anoms"]) > 0
        return is_vuln, ev

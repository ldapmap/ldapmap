import time


class AttackResult:
    def __init__(self, payload, payload_type, vulnerable, url, status_code, response_time, evidence=None, error=None):
        self.payload = payload
        self.payload_type = payload_type
        self.vulnerable = vulnerable
        self.url = url
        self.status_code = status_code
        self.response_time = response_time
        self.evidence = evidence or {}
        self.error = error


class Session:
    def __init__(self, target_url, method="GET", post_data=None, injection_point=None,
                 timeout=30, retries=3, threads=5, delay=0, proxy=None,
                 headers=None, cookies=None, verify_ssl=True,
                 detectors=None, payloads=None):
        self.target_url = target_url
        self.method = method
        self.post_data = post_data
        self.injection_point = injection_point
        self.timeout = timeout
        self.retries = retries
        self.threads = threads
        self.delay = delay
        self.proxy = proxy
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.verify_ssl = verify_ssl
        self.detectors = detectors or ["error_based"]
        self.payloads = payloads or ["authentication_bypass"]
        self.results = []
        self.errors = []
        self.start_time = None
        self.end_time = None

    def start(self):
        self.start_time = time.time()

    def stop(self):
        self.end_time = time.time()

    def add_result(self, result):
        self.results.append(result)

    def add_error(self, error):
        self.errors.append(error)

    def get_summary(self):
        dur = (self.end_time or time.time()) - (self.start_time or time.time())
        vulns = sum(1 for r in self.results if r.vulnerable)
        tests_count = len(self.results)
        errors_count = len(self.errors)

        return {
            "target": self.target_url,
            "method": self.method,
            "duration": dur,
            "duration_seconds": dur,
            "tests": tests_count,
            "tests_count": tests_count,
            "vulns": vulns,
            "vulnerabilities_found": vulns,
            "errors": errors_count,
            "errors_count": errors_count,
        }

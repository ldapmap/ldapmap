import requests
import time


class RequestError(Exception):
    pass


class Requester:
    def __init__(self, timeout=30, retries=3, delay=0, proxy=None, headers=None, cookies=None, verify_ssl=True):
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.cookies.update(self.cookies)

    def request(self, method, url, data=None, headers=None):
        request_headers = {**self.headers}
        if headers:
            request_headers.update(headers)

        for attempt in range(self.retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)

                response = self.session.request(
                    method=method,
                    url=url,
                    data=data,
                    headers=request_headers,
                    timeout=self.timeout,
                    proxies=self.proxy,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )
                return response

            except requests.RequestException as e:
                if attempt == self.retries - 1:
                    raise RequestError("Request failed after " + str(self.retries) + " tries: " + str(e))
                time.sleep(1)

    def close(self):
        self.session.close()

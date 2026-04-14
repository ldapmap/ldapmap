import concurrent.futures
import ipaddress
import socket
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter

from ldapmap_attacker.lib.logger import setup_logger
from ldapmap_attacker.plugins.detectors.error_based import ErrorBasedDetector

logger = setup_logger()


class LDAPApplicationScanner:
    def __init__(self, timeout=5, workers=50):
        self.timeout = timeout
        self.workers = workers
        self.detector = ErrorBasedDetector()
        self.discovered_hosts = []

        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _port_is_open(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                return sock.connect_ex((host, port)) == 0
        except OSError:
            return False

    def _probe_web_entrypoints(self, base_url):
        ldap_paths = ["/login", "/auth", "/search", "/directory", "/api/search", "/api/users", "/admin"]

        for path in ldap_paths:
            test_url = urljoin(base_url, path)
            try:
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
            except requests.RequestException as exc:
                logger.debug(f"HTTP probe failed for {test_url}: {exc}")
                continue

            response_text = response.text.lower()
            if not any(marker in response_text for marker in ["ldap", "uid", "cn", "directory", "username"]):
                continue

            injection_probe = self._detect_injection_surface(test_url)
            if injection_probe:
                return {
                    "url": test_url,
                    "is_vulnerable": True,
                    "injection_point": injection_probe["point"],
                    "method": injection_probe["method"],
                }

        return None

    def _detect_injection_surface(self, target_url):
        test_cases = [
            ("*", "GET", {}),
            ("*)(uid=*)", "GET", {}),
            ("admin*)(uid=*)", "POST", {"username": "admin*)(uid=*)", "password": "test"}),
        ]

        for payload, method, data in test_cases:
            try:
                if method == "GET":
                    url = f"{target_url}?username={payload}&password=test"
                    response = self.session.get(url, timeout=self.timeout, verify=False)
                else:
                    response = self.session.post(target_url, data=data, timeout=self.timeout, verify=False)
            except requests.RequestException as exc:
                logger.debug(f"Injection surface probe failed for {target_url}: {exc}")
                continue

            detected, evidence = self.detector.detect(response, payload, None)
            if detected or evidence.get("errors_found"):
                return {
                    "point": "username" if method == "GET" else "form",
                    "method": method,
                }

        return None

    def scan_host(self, host, ports=None):
        if ports is None:
            ports = [80, 443, 8080, 8443, 3000, 5000, 8000]

        open_ports = [port for port in ports if self._port_is_open(host, port)]
        if not open_ports:
            return None

        for port in open_ports:
            scheme = "https" if port in [443, 8443] else "http"
            base_url = f"{scheme}://{host}:{port}"
            hit = self._probe_web_entrypoints(base_url)
            if hit:
                hit["host"] = host
                hit["port"] = port
                return hit

        return {"host": host, "ports": open_ports, "is_vulnerable": False}

    def hunt_network(self, cidr, ports=None):
        logger.info(f"Scanning network range {cidr} for LDAP-facing applications...")

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.error(f"Invalid CIDR range: {cidr}")
            return []

        hosts = [str(ip) for ip in network.hosts()]
        logger.info(f"Checking {len(hosts)} hosts with {self.workers} worker threads")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_host = {executor.submit(self.scan_host, host, ports): host for host in hosts}

            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    result = future.result()
                except Exception as exc:
                    logger.debug(f"Host scan failed for {host}: {exc}")
                    continue

                if result and result.get("is_vulnerable"):
                    self.discovered_hosts.append(result)
                    logger.vuln(f"Potential LDAP injection surface found on {result['host']} -> {result['url']}")
                elif result and result.get("ports"):
                    logger.info(f"Open ports on {host}: {result['ports']}")

        logger.success(f"Network scan complete: {len(self.discovered_hosts)} potentially vulnerable hosts")
        return self.discovered_hosts

    def get_report(self):
        return {
            "summary": {
                "total_vulnerable_hosts": len(self.discovered_hosts),
                "hosts": self.discovered_hosts,
            },
            "recommendations": [
                "Validate and escape LDAP filter input on all search and login endpoints.",
                "Disable verbose LDAP error messages in production responses.",
                "Monitor unusual wildcard-heavy and boolean LDAP filters.",
            ],
        }


NetworkLdapHunter = LDAPApplicationScanner

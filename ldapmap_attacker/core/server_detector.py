
from ldapmap_attacker.lib.logger import setup_logger

logger = setup_logger()


class LDAPServerProfiler:
    def __init__(self, exploiter):
        self.exploiter = exploiter
        self.server_type = None
        self.server_version = None
        self.capabilities = {}

    def fingerprint(self):
        logger.info("Fingerprinting exposed LDAP server characteristics...")

        detection_checks = [
            ("Active Directory", self._profile_active_directory),
            ("OpenLDAP", self._profile_openldap),
            ("389 Directory Server", self._profile_389ds),
            ("ApacheDS", self._profile_apacheds),
            ("Oracle Internet Directory", self._profile_oracle_internet_directory),
            ("IBM Directory Server", self._profile_ibm_directory_server),
            ("Novell eDirectory", self._profile_novell_edirectory),
        ]

        for server_name, check in detection_checks:
            try:
                result = check()
            except Exception as exc:
                logger.debug(f"LDAP fingerprint probe failed for {server_name}: {exc}")
                continue

            if result.get("match"):
                self.server_type = server_name
                self.server_version = result.get("version", "unknown")
                self.capabilities = result.get("capabilities", {})
                logger.success(f"LDAP server identified as {server_name} {self.server_version}")
                break

        if not self.server_type:
            logger.warning("Unable to confidently identify the LDAP server implementation")
            self.server_type = "Unknown LDAP"
            self.server_version = "unknown"

        return self._build_report()

    def _attribute_probe_matches(self, attribute_names, minimum_hits=2):
        hits = 0
        for attribute_name in attribute_names:
            response = self.exploiter._make_request(f"({attribute_name}=*)")
            if response and attribute_name.lower() in response.lower():
                hits += 1
        return hits >= minimum_hits

    def _profile_active_directory(self):
        if not self._attribute_probe_matches(
            ["sAMAccountName", "userPrincipalName", "memberOf", "userAccountControl"]
        ):
            return {"match": False}

        return {
            "match": True,
            "version": self._extract_active_directory_version(),
            "capabilities": {"nested_groups": True, "sid_attributes": True},
        }

    def _profile_openldap(self):
        if not self._attribute_probe_matches(["uidNumber", "gidNumber", "homeDirectory", "cn=config"]):
            return {"match": False}

        return {
            "match": True,
            "version": "OpenLDAP",
            "capabilities": {"ppolicy": self._has_password_policy_overlay()},
        }

    def _profile_389ds(self):
        response = self.exploiter._make_request("(nsAccountLock=*)")
        if response and "ns" in response.lower():
            return {"match": True, "version": "389DS", "capabilities": {}}
        return {"match": False}

    def _profile_apacheds(self):
        response = self.exploiter._make_request("(apacheCatalog=*)")
        if response and "apache" in response.lower():
            return {"match": True, "version": "ApacheDS", "capabilities": {}}
        return {"match": False}

    def _profile_oracle_internet_directory(self):
        response = self.exploiter._make_request("(orclGUID=*)")
        if response and "orcl" in response.lower():
            return {"match": True, "version": "Oracle", "capabilities": {}}
        return {"match": False}

    def _profile_ibm_directory_server(self):
        response = self.exploiter._make_request("(ibm-entryUUID=*)")
        if response and "ibm" in response.lower():
            return {"match": True, "version": "IBM", "capabilities": {}}
        return {"match": False}

    def _profile_novell_edirectory(self):
        response = self.exploiter._make_request("(GUID=*)")
        if response and "novell" in response.lower():
            return {"match": True, "version": "Novell", "capabilities": {}}
        return {"match": False}

    def _has_password_policy_overlay(self):
        response = self.exploiter._make_request("(pwdPolicySubentry=*)")
        return bool(response and "pwd" in response.lower())

    def _extract_active_directory_version(self):
        response = self.exploiter._make_request("(objectClass=domain)")
        if not response:
            return "unknown"

        version_mapping = {"2019": "Win2019", "2016": "Win2016", "2012": "Win2012"}
        for marker, label in version_mapping.items():
            if marker in response:
                return label

        return "Active Directory"

    def _build_report(self):
        return {
            "type": self.server_type,
            "ver": self.server_version,
            "caps": self.capabilities,
            "payloads": self._recommended_payloads(),
            "notes": self._assessment_notes(),
        }

    def _recommended_payloads(self):
        payloads = {
            "Active Directory": ["(sAMAccountName=*)", "(memberOf=*)"],
            "OpenLDAP": ["(uid=*)", "(objectClass=inetOrgPerson)"],
        }
        return payloads.get(self.server_type or "", ["(uid=*)"])

    def _assessment_notes(self):
        notes = {
            "Active Directory": ["Prefer sAMAccountName enumeration and inspect memberOf exposure."],
            "OpenLDAP": ["Check overlay configuration and review inetOrgPerson search exposure."],
        }
        return notes.get(self.server_type or "", ["Apply generic LDAP injection probes."])


LdapServerFingerprinter = LDAPServerProfiler

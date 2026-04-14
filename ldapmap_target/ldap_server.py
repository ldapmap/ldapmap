import re
from typing import Dict, List, Optional, Any


class FakeLDAPServer:
    def __init__(self):
        self.users = {
            "admin": {
                "uid": "admin",
                "cn": "Administrator",
                "sn": "Admin",
                "mail": "admin@example.com",
                "password": "admin123",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "ou": "admins",
                "role": "admin",
                "ssn": "123-45-6789",
                "salary": "150000",
                "apiKey": "sk-admin-1234567890abcdef",
                "sshKey": "ssh-rsa AAAAB3NzaC1 admin@corp.com",
                "phone": "+1-555-0100",
                "address": "123 Admin St, DC",
                "department": "IT Security",
                "employeeID": "EMP001",
                "manager": "ceo"
            },
            "john_doe": {
                "uid": "john_doe",
                "cn": "John Doe",
                "sn": "Doe",
                "mail": "john@example.com",
                "password": "password123",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "ou": "engineering",
                "role": "developer",
                "ssn": "987-65-4321",
                "salary": "85000",
                "apiKey": "sk-dev-0987654321fedcba",
                "sshKey": "ssh-rsa BBBBC3NzaC2 john@dev.com",
                "phone": "+1-555-0200",
                "address": "456 Dev Ave, SF",
                "department": "Engineering",
                "employeeID": "EMP002",
                "manager": "admin"
            },
            "jane_smith": {
                "uid": "jane_smith",
                "cn": "Jane Smith",
                "sn": "Smith",
                "mail": "jane@example.com",
                "password": "secret456",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "ou": "finance",
                "role": "analyst",
                "ssn": "456-78-9123",
                "salary": "95000",
                "apiKey": "sk-fin-1122334455aabbcc",
                "sshKey": "ssh-rsa CCCCD3NzaC3 jane@fin.com",
                "phone": "+1-555-0300",
                "address": "789 Finance Blvd, NY",
                "department": "Finance",
                "employeeID": "EMP003",
                "manager": "cfo"
            },
            "bob_wilson": {
                "uid": "bob_wilson",
                "cn": "Bob Wilson",
                "sn": "Wilson",
                "mail": "bob@example.com",
                "password": "bob789",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "ou": "hr",
                "role": "manager",
                "ssn": "789-12-3456",
                "salary": "110000",
                "apiKey": "sk-hr-6677889900ddeeff",
                "sshKey": "ssh-rsa DDDDE4NzaC4 bob@hr.com",
                "phone": "+1-555-0400",
                "address": "321 HR Road, Chicago",
                "department": "Human Resources",
                "employeeID": "EMP004",
                "manager": "admin"
            },
            "alice_brown": {
                "uid": "alice_brown",
                "cn": "Alice Brown",
                "sn": "Brown",
                "mail": "alice@example.com",
                "password": "alice000",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "ou": "marketing",
                "role": "specialist",
                "ssn": "321-54-9876",
                "salary": "75000",
                "apiKey": "sk-mkt-2233445566gghhii",
                "sshKey": "ssh-rsa EEEEF5NzaC5 alice@mkt.com",
                "phone": "+1-555-0500",
                "address": "654 Marketing Way, LA",
                "department": "Marketing",
                "employeeID": "EMP005",
                "manager": "cmo"
            },
            "ceo": {
                "uid": "ceo",
                "cn": "CEO Executive",
                "sn": "Executive",
                "mail": "ceo@example.com",
                "password": "ceoTopSecret2024",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson", "topSecret"],
                "ou": "executives",
                "role": "ceo",
                "ssn": "000-00-0001",
                "salary": "500000",
                "apiKey": "sk-ceo-TOPSECRET999999",
                "sshKey": "ssh-rsa FFFFG6NzaC6 ceo@corp.com",
                "phone": "+1-555-CEO-001",
                "address": "1 Executive Tower, NYC",
                "department": "Executive",
                "employeeID": "EMP000",
                "manager": "board"
            },
            "cfo": {
                "uid": "cfo",
                "cn": "CFO Finance",
                "sn": "Finance",
                "mail": "cfo@example.com",
                "password": "cfoMoney2024",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "ou": "executives",
                "role": "cfo",
                "ssn": "111-11-1111",
                "salary": "400000",
                "apiKey": "sk-cfo-FINANCE888888",
                "sshKey": "ssh-rsa GGGGH7NzaC7 cfo@corp.com",
                "phone": "+1-555-CFO-002",
                "address": "2 Finance Tower, NYC",
                "department": "Executive",
                "employeeID": "EMP006",
                "manager": "ceo"
            },
            "cmo": {
                "uid": "cmo",
                "cn": "CMO Marketing",
                "sn": "Marketing",
                "mail": "cmo@example.com",
                "password": "cmoBrand2024",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "ou": "executives",
                "role": "cmo",
                "ssn": "222-22-2222",
                "salary": "350000",
                "apiKey": "sk-cmo-MARKET777777",
                "sshKey": "ssh-rsa HHHHI8NzaC8 cmo@corp.com",
                "phone": "+1-555-CMO-003",
                "address": "3 Marketing Tower, NYC",
                "department": "Executive",
                "employeeID": "EMP007",
                "manager": "ceo"
            },
            "developer1": {
                "uid": "developer1",
                "cn": "Dev One",
                "sn": "One",
                "mail": "dev1@example.com",
                "password": "devPassword1",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "ou": "engineering",
                "role": "junior_dev",
                "ssn": "333-33-3333",
                "salary": "65000",
                "apiKey": "sk-junior-DEV111111",
                "sshKey": "ssh-rsa IIIIJ9NzaC9 dev1@corp.com",
                "phone": "+1-555-0600",
                "address": "111 Dev Street",
                "department": "Engineering",
                "employeeID": "EMP008",
                "manager": "john_doe"
            },
            "developer2": {
                "uid": "developer2",
                "cn": "Dev Two",
                "sn": "Two",
                "mail": "dev2@example.com",
                "password": "devPassword2",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "ou": "engineering",
                "role": "senior_dev",
                "ssn": "444-44-4444",
                "salary": "120000",
                "apiKey": "sk-senior-DEV222222",
                "sshKey": "ssh-rsa JJJJK0NzaC0 dev2@corp.com",
                "phone": "+1-555-0700",
                "address": "222 Senior Ave",
                "department": "Engineering",
                "employeeID": "EMP009",
                "manager": "john_doe"
            },
            "dba": {
                "uid": "dba",
                "cn": "Database Admin",
                "sn": "DBA",
                "mail": "dba@example.com",
                "password": "dbRootAccess99",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson", "dbAdmin"],
                "ou": "it",
                "role": "dba",
                "ssn": "555-55-5555",
                "salary": "140000",
                "apiKey": "sk-dba-ROOT333333",
                "sshKey": "ssh-rsa KKKKL1NzaC1 dba@corp.com",
                "phone": "+1-555-0800",
                "address": "DB Server Room",
                "department": "IT Operations",
                "employeeID": "EMP010",
                "manager": "admin"
            },
            "sysadmin": {
                "uid": "sysadmin",
                "cn": "System Admin",
                "sn": "SysAdmin",
                "mail": "sysadmin@example.com",
                "password": "sysRoot4444",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson", "sysAdmin"],
                "ou": "it",
                "role": "sysadmin",
                "ssn": "666-66-6666",
                "salary": "135000",
                "apiKey": "sk-sys-ROOT444444",
                "sshKey": "ssh-rsa LLLLM2NzaC2 sysadmin@corp.com",
                "phone": "+1-555-0900",
                "address": "Server Room B",
                "department": "IT Operations",
                "employeeID": "EMP011",
                "manager": "admin"
            },
            "intern": {
                "uid": "intern",
                "cn": "Summer Intern",
                "sn": "Intern",
                "mail": "intern@example.com",
                "password": "intern2024",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "ou": "interns",
                "role": "intern",
                "ssn": "777-77-7777",
                "salary": "25000",
                "apiKey": "sk-intern-TEMP555",
                "sshKey": "ssh-rsa MMMMN3NzaC3 intern@corp.com",
                "phone": "+1-555-1000",
                "address": "Intern Corner",
                "department": "Various",
                "employeeID": "EMP099",
                "manager": "hr"
            },
            "contractor": {
                "uid": "contractor",
                "cn": "External Contractor",
                "sn": "Contractor",
                "mail": "contractor@external.com",
                "password": "contractPass666",
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson", "external"],
                "ou": "contractors",
                "role": "contractor",
                "ssn": "888-88-8888",
                "salary": "90000",
                "apiKey": "sk-contractor-EXT666",
                "sshKey": "ssh-rsa NNNNO4NzaC4 contractor@ext.com",
                "phone": "+1-555-1100",
                "address": "External Office",
                "department": "External",
                "employeeID": "EMP998",
                "manager": "procurement"
            }
        }
    
    def search(self, filter_str: str) -> List[Dict[str, Any]]:
        results = []
        
        if not filter_str:
            return list(self.users.values())
        
        try:
            for uid, user in self.users.items():
                if self._evaluate_filter(filter_str, user):
                    results.append(user)
        except Exception as e:
            return [{"error": f"LDAP search error: {str(e)}"}]
        
        return results
    
    def _evaluate_filter(self, filter_str: str, user: Dict) -> bool:
        filter_str = filter_str.strip()

        if filter_str == "*":
            return True

        if "=" in filter_str:
            return self._parse_equality(filter_str, user)

        return False
    
    def _parse_equality(self, filter_str: str, user: Dict) -> bool:
        if filter_str.startswith("("):
            filter_str = filter_str[1:]
        if filter_str.endswith(")"):
            filter_str = filter_str[:-1]

        if filter_str.startswith("|"):
            return self._evaluate_or(filter_str[1:], user)

        if filter_str.startswith("&"):
            return self._evaluate_and(filter_str[1:], user)

        if filter_str.startswith("!"):
            return not self._parse_equality(filter_str[1:], user)

        if "=" in filter_str:
            parts = filter_str.split("=", 1)
            if len(parts) == 2:
                attr = parts[0].strip()
                value = parts[1].strip()
                return self._match_attribute(user, attr, value)
        
        return False
    
    def _evaluate_or(self, filter_str: str, user: Dict) -> bool:
        sub_filters = self._split_filters(filter_str)
        return any(self._parse_equality(f"({sf})", user) for sf in sub_filters if sf)
    
    def _evaluate_and(self, filter_str: str, user: Dict) -> bool:
        sub_filters = self._split_filters(filter_str)
        return all(self._parse_equality(f"({sf})", user) for sf in sub_filters if sf)
    
    def _split_filters(self, filter_str: str) -> List[str]:
        filters = []
        depth = 0
        current = ""
        
        for char in filter_str:
            if char == '(':
                if depth == 0 and current.strip():
                    filters.append(current.strip())
                    current = ""
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    filters.append(current.strip())
                    current = ""
                    continue
            current += char
        
        if current.strip():
            filters.append(current.strip())
        
        return [f for f in filters if f]
    
    def _match_attribute(self, user: Dict, attr: str, value: str) -> bool:
        if value == "*":
            return attr in user or attr in ["objectClass", "ou", "role"]
        
        if attr == "objectClass":
            return value in user.get("objectClass", [])
        
        if attr == "password":
            return user.get("password") == value
        
        user_value = user.get(attr, "")

        if value.endswith("*"):
            prefix = value[:-1]
            return user_value.startswith(prefix)

        if value.startswith("*"):
            suffix = value[1:]
            return user_value.endswith(suffix)

        if "*" in value:
            pattern = value.replace("*", ".*")
            return bool(re.search(pattern, user_value, re.IGNORECASE))

        return user_value == value
    
    def authenticate(self, uid: str, password: str) -> bool:
        user = self.users.get(uid)
        if user:
            return user.get("password") == password
        return False

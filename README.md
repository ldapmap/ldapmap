[![English](https://flagcdn.com/w40/gb.png)](./README.md)
[![Français](https://flagcdn.com/w40/fr.png)](./readme/translate/fr.md)

# ldapmap

[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org/downloads/release/python-3120/) [![GitHub Repo](https://img.shields.io/badge/GitHub-idormap-black?logo=github)](https://github.com/idormapproject/idormap/) ![Version](https://img.shields.io/badge/Version-1.0.0-purple)

ldapmap is an open-source security testing tool designed to detect and test LDAP injection vulnerabilities in applications using LDAP directories. It helps security researchers and penetration testers identify insecure LDAP query handling, where user input is improperly sanitized, potentially allowing authentication bypass, unauthorized directory access, or data leakage from LDAP/Active Directory systems.

## features

- Automatic detection of LDAP injection vulnerabilities
- Multiple detection engines:
  - Error-based detection
  - Boolean-based detection
  - Time-based detection (optional)
- Exploitation engine for confirmed injection points:
  - Authentication bypass testing
  - LDAP directory enumeration
  - Data extraction
- Structured parsing of LDAP responses
- Automatic reconstruction of directory entries (uid, cn, mail, ou, role)
- CSV export for reporting and analysis
- Multi-threaded scanning support
- Support for custom headers, cookies, and proxy configuration
- Verbose mode for debugging and payload tracking

## work methods 

ldapmap injects controlled payloads into user-supplied LDAP query parameters and analyzes application responses to detect insecure LDAP query handling.

The tool operates in the following phases:

1. Baseline analysis  
   Establishes a stable response baseline for comparison.

2. Injection testing  
   Sends LDAP-specific payloads to detect input sanitization weaknesses.

3. Detection phase  
   Confirms vulnerabilities using:
   - Response size variations
   - Boolean logic evaluation
   - Error leakage analysis

4. Exploitation phase (optional)  
   If a vulnerability is confirmed, ldapmap can attempt controlled exploitation to extract directory data.

## screenshot

<img width="1315" height="722" alt="image" src="https://github.com/user-attachments/assets/0bb8326a-135c-4497-a1dd-20f083eb4b5a" />

## help

```
options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL with INPUT placeholder (ex: http://target/search?cn=INPUT)
  -m {GET,POST,PUT,DELETE}, --method {GET,POST,PUT,DELETE}
                        HTTP method (default: GET)
  --data DATA           POST data (ex: username=admin&password=INPUT)
  -d {error_based,boolean_based,time_based} [{error_based,boolean_based,time_based} ...], --detector {error_based,boolean_based,time_based} [{error_based,boolean_based,time_based} ...]
                        Detectors to use (default: error_based boolean_based)
  -p {authentication_bypass,data_extraction,blind} [{authentication_bypass,data_extraction,blind} ...], --payload {authentication_bypass,data_extraction,blind} [{authentication_bypass,data_extraction,blind} ...]
                        Payload types to use (default: authentication_bypass data_extraction)
  --threads THREADS, -T THREADS
                        Number of threads (default: 5)
  --timeout TIMEOUT     Request timeout in seconds (default: 30)
  --delay DELAY         Delay between requests in seconds (default: 0)
  --retries RETRIES     Number of retries (default: 3)
  -H HEADER [HEADER ...], --header HEADER [HEADER ...]
                        HTTP headers (ex: 'Authorization: Bearer token')
  --cookie COOKIE       Cookies (ex: sessionid=abc123; auth=xyz)
  --proxy PROXY         Proxy HTTP (ex: http://127.0.0.1:8080)
  --no-verify-ssl       Disable SSL verification
  -v, --verbose         Verbose mode
  --no-banner           Hide banner
  --version             Show version

Exploitation:
  --exploit             Enable exploitation mode after detection
  --enum-users          Enumerate LDAP users
  --dump                Full LDAP database dump
  --csv                 Export results to CSV
  --output OUTPUT       Output directory for exports (default: ./output)
```

## example dump output dashboard

[ EXTRACTED USERS (14) ]

| UID          | CN            | Email                 | OU           | Role        |
|--------------|---------------|----------------------|--------------|-------------|
| admin        | Administrator | admin@example.com    | admins       | admin       |
| john_doe     | John          | john@example.com     | engineering  | developer   |
| jane_smith   | Jane          | jane@example.com     | finance      | analyst     |
| bob_wilson   | Bob           | bob@example.com      | hr           | manager     |
| alice_brown  | Alice         | alice@example.com    | marketing    | specialist  |
| ceo          | CEO           | ceo@example.com      | executives   | ceo         |
| cfo          | CFO           | cfo@example.com      | executives   | cfo         |
| cmo          | CMO           | cmo@example.com      | executives   | cmo         |
| developer1   | Dev           | dev1@example.com     | engineering  | junior_dev  |
| developer2   | Dev           | dev2@example.com     | engineering  | senior_dev  |
| dba          | Database      | dba@example.com      | it           | dba         |
| sysadmin     | System        | sysadmin@example.com  | it           | sysadmin    |
| intern       | Summer        | intern@example.com    | interns      | intern      |
| contractor   | External      | contractor@external.com | contractors | contractor |

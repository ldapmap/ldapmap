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


[![English](https://img.shields.io/badge/language-English-blue?style=for-the-badge)](./README.md)
;
[![Français](https://img.shields.io/badge/language-Français-blue?style=for-the-badge)](./readme/translate/fr.md)
;
[![Deutsch](https://img.shields.io/badge/language-Deutsch-blue?style=for-the-badge)](./readme/translate/de.md)

# ldapmap

[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org/downloads/release/python-3120/) [![GitHub Repo](https://img.shields.io/badge/GitHub-idormap-black?logo=github)](https://github.com/idormapproject/idormap/) ![Version](https://img.shields.io/badge/Version-1.0.0-purple)

ldapmap ist ein Open-Source-Sicherheitstool zur Erkennung und Analyse von LDAP-Injection-Schwachstellen in Anwendungen, die LDAP-Verzeichnisse verwenden. Es hilft Sicherheitsexperten und Pentestern dabei, unsichere LDAP-Abfragen zu identifizieren, bei denen Benutzereingaben nicht korrekt validiert werden. Dies kann zu Authentifizierungsumgehung, unbefugtem Zugriff auf Verzeichnisse oder Datenlecks in LDAP-/Active-Directory-Systemen führen.

## funktionen

- Automatische Erkennung von LDAP-Injection-Schwachstellen
- Mehrere Erkennungsmechanismen:
  - Fehlerbasierte Erkennung
  - Boolesche Erkennung
  - Zeitbasierte Erkennung (optional)
- Exploit-Engine für bestätigte Schwachstellen:
  - Test auf Authentifizierungsumgehung
  - LDAP-Verzeichnis-Aufzählung
  - Datenextraktion
- Strukturierte Analyse von LDAP-Antworten
- Automatische Rekonstruktion von Einträgen (uid, cn, mail, ou, role)
- CSV-Export für Analyse und Reporting
- Multi-Threading-Unterstützung für schnellere Scans
- Unterstützung für Header, Cookies und Proxy-Konfiguration
- Verbose-Modus für Debugging und Nachverfolgung von Payloads

## funktionsweise

ldapmap injiziert kontrollierte Payloads in benutzerdefinierte LDAP-Parameter und analysiert die Antworten der Anwendung, um unsichere LDAP-Abfragen zu erkennen.

Der Ablauf erfolgt in mehreren Phasen:

1. Baseline-Analyse  
   Ermittelt eine stabile Referenzantwort.

2. Injection-Tests  
   Sendet LDAP-spezifische Payloads zur Identifikation von Schwachstellen.

3. Erkennungsphase  
   Bestätigt Schwachstellen anhand von:
   - Antwortgrößen-Unterschieden
   - Boolescher Logik
   - Fehlerausgaben (LDAP Errors)

4. Exploit-Phase (optional)  
   Nach Bestätigung wird eine kontrollierte Ausnutzung durchgeführt, um Verzeichnisdaten zu extrahieren.

## screenshot

<img width="1315" height="722" alt="image" src="https://github.com/user-attachments/assets/0bb8326a-135c-4497-a1dd-20f083eb4b5a" />

## hilfe

```

optionen:
-h, --help            Hilfe anzeigen
-u URL, --url URL     Ziel-URL mit INPUT-Placeholder (z. B. [http://target/search?cn=INPUT](http://target/search?cn=INPUT))
-m {GET,POST,PUT,DELETE}
HTTP-Methode (Standard: GET)
--data DATA           POST-Daten (z. B. username=admin&password=INPUT)
-d ...                Erkennungsmechanismen
-p ...                Payload-Typen
--threads             Anzahl der Threads (Standard: 5)
--timeout             Timeout in Sekunden (Standard: 30)
--delay               Verzögerung zwischen Anfragen
--retries             Anzahl der Wiederholungen
-H                    HTTP-Header
--cookie              Cookies
--proxy               HTTP-Proxy
--no-verify-ssl       SSL-Verifikation deaktivieren
-v                    Verbose-Modus
--no-banner           Banner ausblenden
--version             Version anzeigen

Exploitation:
--exploit             Exploit-Modus aktivieren
--enum-users          LDAP-Benutzer auflisten
--dump                Vollständiger LDAP-Dump
--csv                 Export als CSV
--output              Ausgabeordner

```

## beispielausgabe (dump)

[ EXTRAHIERTE BENUTZER (14) ]

| UID          | CN            | Email                 | OU           | Rolle       |
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


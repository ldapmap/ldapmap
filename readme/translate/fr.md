[![English](https://img.shields.io/badge/language-English-blue?style=for-the-badge)](../../README.md)
;
[![Français](https://img.shields.io/badge/language-Français-blue?style=for-the-badge)](./fr.md)
;
[![Deutsch](https://img.shields.io/badge/language-Deutsch-blue?style=for-the-badge)](./de.md)

# ldapmap

[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org/downloads/release/python-3120/) [![GitHub Repo](https://img.shields.io/badge/GitHub-ldapmap-black?logo=github)](https://github.com/ldapmap/ldapmap) ![Version](https://img.shields.io/badge/Version-1.0.0-purple)

ldapmap est un outil open-source de test de sécurité conçu pour détecter et analyser les vulnérabilités d'injection LDAP dans les applications utilisant des annuaires LDAP. Il aide les chercheurs en sécurité et les pentesters à identifier les requêtes LDAP mal sécurisées, où les entrées utilisateur sont insuffisamment filtrées, pouvant permettre un contournement d’authentification, un accès non autorisé à l’annuaire ou une fuite de données depuis des systèmes LDAP / Active Directory.

## fonctionnalités

- Détection automatique des vulnérabilités d’injection LDAP
- Plusieurs moteurs de détection :
  - Détection basée sur les erreurs
  - Détection basée sur la logique booléenne
  - Détection basée sur le temps (optionnel)
- Moteur d’exploitation pour les points d’injection confirmés :
  - Test de contournement d’authentification
  - Énumération de l’annuaire LDAP
  - Extraction de données
- Analyse structurée des réponses LDAP
- Reconstruction automatique des entrées (uid, cn, mail, ou, role)
- Export CSV pour analyse et reporting
- Support du multi-thread pour accélérer les scans
- Support des headers, cookies et proxy
- Mode verbeux pour debug et suivi des payloads

## méthode de fonctionnement

ldapmap injecte des payloads contrôlés dans les paramètres LDAP fournis par l’utilisateur et analyse les réponses de l’application afin de détecter des failles de sécurité.

L’outil fonctionne en plusieurs phases :

1. Analyse de baseline  
   Établit une réponse stable de référence.

2. Tests d’injection  
   Envoie des payloads LDAP pour détecter les faiblesses de filtrage.

3. Phase de détection  
   Confirme les vulnérabilités via :
   - variations de taille de réponse
   - logique booléenne
   - fuite d’erreurs LDAP

4. Phase d’exploitation (optionnelle)  
   Si une vulnérabilité est confirmée, ldapmap tente une exploitation contrôlée pour extraire des données.

## capture

<img width="1315" height="722" alt="image" src="https://github.com/user-attachments/assets/0bb8326a-135c-4497-a1dd-20f083eb4b5a" />

## aide

```

options:
-h, --help            afficher l’aide
-u URL, --url URL     URL cible avec placeholder INPUT (ex: [http://target/search?cn=INPUT](http://target/search?cn=INPUT))
-m {GET,POST,PUT,DELETE}
méthode HTTP (défaut: GET)
--data DATA           données POST (ex: username=admin&password=INPUT)
-d ...                moteurs de détection
-p ...                types de payloads
--threads             nombre de threads (défaut: 5)
--timeout             timeout des requêtes (défaut: 30)
--delay               délai entre requêtes
--retries             nombre de retries
-H                    headers HTTP
--cookie              cookies
--proxy               proxy HTTP
--no-verify-ssl       désactiver SSL
-v                    mode verbeux
--no-banner           cacher la bannière
--version             afficher la version

Exploitation:
--exploit             activer l’exploitation
--enum-users          énumérer les utilisateurs LDAP
--dump                dump complet LDAP
--csv                 export CSV
--output              dossier de sortie

```

## exemple de sortie (dump)

[ UTILISATEURS EXTRAITS (14) ]

| UID          | CN            | Email                 | OU           | Rôle        |
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


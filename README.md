# 🔍 SSH Log Analyzer

Mini-SIEM en Python qui analyse un `auth.log` OpenSSH et détecte les comportements d'attaque,
avec correspondance **MITRE ATT&CK**.

## Règles de détection
| Règle | Logique | MITRE ATT&CK |
|---|---|---|
| `BRUTE_FORCE` | ≥ N échecs d'une même IP dans une fenêtre glissante | T1110.001 |
| `PASSWORD_SPRAYING` | 1 IP essaie ≥ N comptes différents | T1110.003 |
| `SUCCESS_AFTER_FAILURES` | Connexion réussie après une rafale d'échecs (**CRITICAL**) | T1078 |

## Utilisation
```bash
python3 generate_sample_log.py                    # crée un log de test (IP RFC 5737)
python3 analyzer.py sample_auth.log --year 2026   # rapport Markdown
python3 analyzer.py /var/log/auth.log --format json --threshold 8
python3 -m pytest tests/ -v
```
Aucune dépendance externe (Python 3.8+ ; `pytest` uniquement pour les tests).

## Choix de conception
- Fenêtre glissante (deux pointeurs) → O(n) par IP, évite les faux positifs d'un utilisateur qui se trompe de mot de passe.
- Seuils configurables pour ajuster le ratio faux positifs / faux négatifs.
- Sortie JSON pour intégration dans un SIEM (Splunk, Wazuh, ELK).

## Pistes d'amélioration
Géolocalisation / réputation des IP (AbuseIPDB), blocage auto (fail2ban), support `journald`, alertes Slack/mail.

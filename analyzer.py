#!/usr/bin/env python3
"""SSH Log Analyzer : détecte brute-force, password spraying et compromission probable
dans un fichier auth.log (format syslog OpenSSH). Mini-SIEM pédagogique."""
import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta

PREFIX = r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s\S+\ssshd\[\d+\]:\s"
FAILED = re.compile(PREFIX + r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+")
ACCEPTED = re.compile(PREFIX + r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+")


def parse_line(line, year):
    """Retourne (datetime, 'fail'|'ok', user, ip) ou None."""
    for regex, kind in ((FAILED, "fail"), (ACCEPTED, "ok")):
        m = regex.match(line)
        if m:
            ts = datetime.strptime(f"{year} {' '.join(m['ts'].split())}", "%Y %b %d %H:%M:%S")
            return ts, kind, m["user"], m["ip"]
    return None


def parse_file(path, year=None):
    year = year or datetime.now().year
    with open(path, errors="replace") as f:
        events = [e for e in (parse_line(l, year) for l in f) if e]
    return sorted(events)


def detect(events, threshold=5, window_min=5, spray_users=4):
    """Applique 3 règles de détection. Retourne une liste d'alertes."""
    window = timedelta(minutes=window_min)
    fails, oks = defaultdict(list), defaultdict(list)
    for ts, kind, user, ip in events:
        (fails if kind == "fail" else oks)[ip].append((ts, user))
    alerts = []

    for ip, items in fails.items():
        times = [t for t, _ in items]
        # Règle 1 : brute-force = >= threshold échecs dans une fenêtre glissante
        best, left = (0, 0, 0), 0
        for right in range(len(times)):
            while times[right] - times[left] > window:
                left += 1
            if right - left + 1 > best[0]:
                best = (right - left + 1, left, right)
        if best[0] >= threshold:
            alerts.append({"rule": "BRUTE_FORCE", "severity": "HIGH", "ip": ip,
                           "count": best[0], "first": str(times[best[1]]), "last": str(times[best[2]]),
                           "mitre": "T1110.001 - Password Guessing"})
        # Règle 2 : password spraying = beaucoup de comptes différents depuis une IP
        users = {u for _, u in items}
        if len(users) >= spray_users:
            alerts.append({"rule": "PASSWORD_SPRAYING", "severity": "HIGH", "ip": ip,
                           "count": len(users), "users": sorted(users),
                           "mitre": "T1110.003 - Password Spraying"})
        # Règle 3 : connexion réussie après une rafale d'échecs = compromission probable
        for ts_ok, user in oks.get(ip, []):
            before = [t for t in times if t < ts_ok]
            if len(before) >= threshold:
                alerts.append({"rule": "SUCCESS_AFTER_FAILURES", "severity": "CRITICAL", "ip": ip,
                               "user": user, "time": str(ts_ok), "count": len(before),
                               "mitre": "T1078 - Valid Accounts"})
    return alerts


def to_markdown(alerts):
    if not alerts:
        return "# Rapport SSH\n\nAucune alerte.\n"
    out = ["# Rapport d'analyse SSH", "", f"**{len(alerts)} alerte(s)**", "",
           "| Sévérité | Règle | IP | Détail | MITRE ATT&CK |", "|---|---|---|---|---|"]
    for a in sorted(alerts, key=lambda a: a["severity"] != "CRITICAL"):
        detail = f"{a['count']} évènements"
        if "user" in a:
            detail += f", compte `{a['user']}`"
        out.append(f"| {a['severity']} | {a['rule']} | {a['ip']} | {detail} | {a['mitre']} |")
    out += ["", "## Actions recommandées",
            "- Bloquer les IP concernées (pare-feu / fail2ban)",
            "- Désactiver `PasswordAuthentication` et utiliser des clés SSH",
            "- Pour toute alerte CRITICAL : forcer le changement du mot de passe et investiguer le compte"]
    return "\n".join(out) + "\n"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("logfile")
    p.add_argument("--threshold", type=int, default=5)
    p.add_argument("--window", type=int, default=5, help="fenêtre en minutes")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.add_argument("--year", type=int)
    a = p.parse_args()
    alerts = detect(parse_file(a.logfile, a.year), a.threshold, a.window)
    print(json.dumps(alerts, indent=2) if a.format == "json" else to_markdown(alerts))


if __name__ == "__main__":
    main()

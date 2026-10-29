#!/usr/bin/env python3
"""Génère un auth.log synthétique (IP de documentation RFC 5737) pour tester l'analyseur."""
import random
from datetime import datetime, timedelta

random.seed(42)
t0 = datetime(2026, 10, 26, 8, 0, 0)
lines = []


def add(t, msg):
    stamp = f"{t.strftime('%b')} {t.day:2d} {t.strftime('%H:%M:%S')}"
    lines.append((t, f"{stamp} srv01 sshd[{random.randint(1000, 9999)}]: {msg}"))


# trafic légitime
for i in range(15):
    add(t0 + timedelta(minutes=random.randint(0, 600)), f"Accepted publickey for alice from 192.0.2.10 port {random.randint(40000, 60000)} ssh2")
# brute-force sur root puis succès (scénario critique)
for i in range(30):
    add(t0 + timedelta(seconds=i * 4), f"Failed password for root from 203.0.113.5 port {random.randint(40000, 60000)} ssh2")
add(t0 + timedelta(seconds=125), "Accepted password for root from 203.0.113.5 port 51234 ssh2")
# password spraying
for u in ["admin", "test", "oracle", "ubuntu", "postgres", "git"]:
    add(t0 + timedelta(minutes=90), f"Failed password for invalid user {u} from 198.51.100.77 port {random.randint(40000, 60000)} ssh2")
# faute de frappe légitime (ne doit PAS alerter)
for i in range(2):
    add(t0 + timedelta(minutes=200 + i), "Failed password for bob from 192.0.2.20 port 40022 ssh2")

with open("sample_auth.log", "w") as f:
    f.write("\n".join(l for _, l in sorted(lines)) + "\n")
print("sample_auth.log généré")

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from analyzer import parse_line, detect
from datetime import datetime, timedelta


def ev(sec, kind, user, ip):
    return (datetime(2026, 1, 1) + timedelta(seconds=sec), kind, user, ip)


def test_parse_failed():
    l = "Oct  5 10:15:32 h sshd[12]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
    assert parse_line(l, 2026)[1:] == ("fail", "admin", "1.2.3.4")


def test_bruteforce_detected():
    events = [ev(i, "fail", "root", "1.1.1.1") for i in range(6)]
    assert any(a["rule"] == "BRUTE_FORCE" for a in detect(events))


def test_slow_attempts_not_detected():
    events = [ev(i * 600, "fail", "root", "1.1.1.1") for i in range(6)]  # 1 échec / 10 min
    assert detect(events) == []


def test_spraying():
    events = [ev(i, "fail", f"u{i}", "2.2.2.2") for i in range(5)]
    assert any(a["rule"] == "PASSWORD_SPRAYING" for a in detect(events))


def test_success_after_failures_is_critical():
    events = [ev(i, "fail", "root", "3.3.3.3") for i in range(6)] + [ev(100, "ok", "root", "3.3.3.3")]
    assert any(a["severity"] == "CRITICAL" for a in detect(events))

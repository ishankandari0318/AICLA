"""Generates the SYNTHETIC sample logs in this folder. Nothing here is real data.

Run:  python generate_samples.py
The random seed is fixed, so the output is identical every time.
IPs come from the documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x),
which are reserved and never belong to real hosts, plus private 10.x / 192.168.x ranges."""

import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent
rng = random.Random(42)
BASE = datetime(2026, 9, 22, 8, 0, 0)
HOURS = 8

# ------------------------------------------------------------------ SSH / syslog
USERS = {"alice": "192.168.1.21", "bob": "192.168.1.34", "carol": "192.168.1.40", "deploy": "10.0.0.5"}


def stamp(dt):
    return f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S}"


def line(dt, service, message, host="web01"):
    return dt, f"{stamp(dt)} {host} {service}[{rng.randint(1000, 30000)}]: {message}"


def normal_auth_events(sessions=60):
    events = []
    for _ in range(sessions):
        user, ip = rng.choice(list(USERS.items()))
        t = BASE + timedelta(seconds=rng.randint(0, HOURS * 3600))
        port = rng.randint(40000, 60000)
        method = "publickey" if user == "deploy" else "password"
        if rng.random() < 0.12:  # an ordinary typo before logging in correctly
            events.append(line(t, "sshd", f"Failed password for {user} from {ip} port {port} ssh2"))
            t += timedelta(seconds=rng.randint(3, 10))
        events.append(line(t, "sshd", f"Accepted {method} for {user} from {ip} port {port} ssh2"))
        events.append(line(t, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)"))
        if rng.random() < 0.3:
            events.append(line(t + timedelta(minutes=1), "sudo",
                               f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update"))
        end = t + timedelta(minutes=rng.randint(2, 90))
        events.append(line(end, "sshd", f"Disconnected from user {user} {ip} port {port}"))
        events.append(line(end, "sshd", f"pam_unix(sshd:session): session closed for user {user}"))
    for hour in range(HOURS):
        t = BASE + timedelta(hours=hour, minutes=17)
        events.append(line(t, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))
        events.append(line(t + timedelta(seconds=1), "CRON", "pam_unix(cron:session): session closed for user root"))
    return events


def brute_force_events(attacker="203.0.113.50", attempts=327, duration=235):
    """327 'Failed password' lines in under four minutes, then one accepted login."""
    start = BASE + timedelta(hours=6, minutes=2, seconds=10)
    names = ["root", "admin", "oracle", "test", "ubuntu", "postgres", "user", "pi", "ftpuser", "git"]
    events = []
    for i in range(attempts):
        t = start + timedelta(seconds=int(i * duration / attempts))
        user, port = rng.choice(names), rng.randint(30000, 65000)
        if user == "root":
            events.append(line(t, "sshd", f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={attacker}  user=root"))
            events.append(line(t, "sshd", f"Failed password for root from {attacker} port {port} ssh2"))
        else:
            events.append(line(t, "sshd", f"Invalid user {user} from {attacker} port {port}"))
            events.append(line(t, "sshd", f"Failed password for invalid user {user} from {attacker} port {port} ssh2"))
        if i % 5 == 0:
            events.append(line(t, "sshd", f"Connection closed by authenticating user {user} {attacker} port {port} [preauth]"))
    t = start + timedelta(seconds=duration + 25)
    events.append(line(t, "sshd", f"Accepted password for deploy from {attacker} port 51012 ssh2"))
    events.append(line(t, "sshd", "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)"))
    return events


def write_syslog(name, events):
    events.sort(key=lambda e: e[0])
    (OUT / name).write_text("\n".join(text for _, text in events) + "\n", encoding="utf-8")


# ------------------------------------------------------------------ web access logs
PATHS = [("/", 30), ("/index.html", 10), ("/about", 6), ("/products", 12), ("/products/42", 8),
         ("/static/app.js", 10), ("/static/style.css", 10), ("/api/items", 8), ("/contact", 3), ("/login", 4)]
CLIENTS = [f"192.0.2.{n}" for n in range(10, 40)] + [f"198.51.100.{n}" for n in range(10, 30)]
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]


def access(dt, ip, method, path, status, size, agent, user="-"):
    return dt, f'{ip} - {user} [{dt:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'


def normal_web_events(count=400):
    paths, weights = zip(*PATHS)
    events = []
    for _ in range(count):
        t = BASE + timedelta(seconds=rng.randint(0, HOURS * 3600))
        status = rng.choices([200, 304, 301, 404, 500], weights=[88, 6, 2.5, 3, 0.5])[0]
        events.append(access(t, rng.choice(CLIENTS), "GET", rng.choices(paths, weights)[0], status,
                             rng.randint(300, 40000) if status != 304 else 0, rng.choice(BROWSERS)))
    return events


def suspicious_web_events():
    events = []
    # 1) vulnerability scanner: 250 probes in 90 s, mostly 404
    probes = ["/admin", "/wp-login.php", "/.env", "/phpmyadmin/", "/.git/config", "/backup.zip", "/server-status",
              "/products?id=1%27%20OR%20%271%27=%271", "/cgi-bin/test.cgi", "/config.php", "/xmlrpc.php", "/console"]
    start = BASE + timedelta(hours=3, minutes=20)
    for i in range(250):
        t = start + timedelta(seconds=int(i * 90 / 250))
        status = rng.choices([404, 403, 200], weights=[85, 12, 3])[0]
        events.append(access(t, "198.51.100.99", "GET", probes[i % len(probes)], status, rng.randint(150, 600), "Nikto/2.5.0"))
    # 2) password guessing against /login: 120 x 401 in two minutes, then one success
    start = BASE + timedelta(hours=5, minutes=40)
    for i in range(120):
        t = start + timedelta(seconds=i)
        events.append(access(t, "203.0.113.77", "POST", "/login", 401, 512, "python-requests/2.31.0"))
    events.append(access(start + timedelta(seconds=121), "203.0.113.77", "POST", "/login", 302, 0, "python-requests/2.31.0"))
    # 3) request flood: 900 requests for "/" in 60 s, server starts failing at the end
    start = BASE + timedelta(hours=6, minutes=30)
    for i in range(900):
        t = start + timedelta(seconds=int(i * 60 / 900))
        events.append(access(t, "192.0.2.200", "GET", "/", 503 if i >= 860 else 200, 1200, "Mozilla/5.0 (compatible; loadgen/1.0)"))
    return events


def write_access(name, events):
    events.sort(key=lambda e: e[0])
    (OUT / name).write_text("\n".join(text for _, text in events) + "\n", encoding="utf-8")


# ------------------------------------------------------------------ generic CSV / JSON / JSONL
def generic_rows():
    rows = []
    for i in range(18):  # normal logins
        t = BASE + timedelta(minutes=i * 7)
        user, ip = rng.choice(list(USERS.items()))
        rows.append({"time": t, "src": ip, "dst": "10.0.0.10", "dport": 22, "user": user,
                     "action": "login_success", "result": "success"})
    for i in range(12):  # one outside host failing repeatedly, probing different ports
        t = BASE + timedelta(hours=2, seconds=i * 4)
        rows.append({"time": t, "src": "203.0.113.9", "dst": "10.0.0.10", "dport": [22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5900, 8080][i],
                     "user": rng.choice(["root", "admin"]), "action": "login_failed", "result": "failure"})
    return sorted(rows, key=lambda r: r["time"])


def write_generic():
    rows = generic_rows()
    with open(OUT / "sample_events.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Time", "Src IP", "Dst IP", "Dst Port", "User", "Action", "Result"])
        for r in rows:
            writer.writerow([f"{r['time']:%Y-%m-%d %H:%M:%S}", r["src"], r["dst"], r["dport"], r["user"], r["action"], r["result"]])

    nested = [{"@timestamp": f"{r['time']:%Y-%m-%dT%H:%M:%S}Z", "source": {"ip": r["src"]},
               "destination": {"ip": r["dst"], "port": r["dport"]}, "user": {"name": r["user"]},
               "event": {"action": r["action"], "outcome": r["result"]}, "host": {"name": "fw01"}} for r in rows]
    (OUT / "sample_events.json").write_text(json.dumps(nested, indent=2) + "\n", encoding="utf-8")

    with open(OUT / "sample_events.jsonl", "w", encoding="utf-8") as f:
        for r in rows:  # flat records with epoch-second timestamps
            epoch = int((r["time"] - datetime(1970, 1, 1)).total_seconds())
            f.write(json.dumps({"time": epoch, "src_ip": r["src"], "dst_ip": r["dst"], "dst_port": r["dport"],
                                "username": r["user"], "event_type": r["action"]}) + "\n")


# ------------------------------------------------------------------ malformed
MALFORMED = """this is not a log file
{{{{ broken [[[[
Sep 22 invalid line without a host or message
2026-13-45 99:99:99 ???
\x1b[31mpretend terminal colour codes\x1b[0m
<script>alert('hello')</script>
just some text, with commas, but, no real, structure
"""

if __name__ == "__main__":
    write_syslog("normal_ssh_auth.log", normal_auth_events())
    write_syslog("bruteforce_ssh_auth.log", normal_auth_events(40) + brute_force_events())
    write_access("normal_web_access.log", normal_web_events())
    write_access("suspicious_web_access.log", normal_web_events(300) + suspicious_web_events())
    write_generic()
    (OUT / "malformed_sample.log").write_text(MALFORMED, encoding="utf-8")
    print("Sample files written to", OUT)

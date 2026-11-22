"""Module 7: the response engine.

Turns each risk-scored Finding into a ThreatDetail: a plain-language explanation, possible impact,
recommended solutions and immediate mitigation steps.

How the advice is produced
  * It is written per DETECTION RULE (an SSH brute-force needs different advice than a web
    login attack) and filled in with the finding's real facts: IP, counts, accounts, URLs.
  * No AI model is involved. The same finding always gets the same advice.
  * It RECOMMENDS only. Nothing here changes a firewall, blocks an address or edits a configuration.
    `reference_commands` are examples for a human to review.
  * Wording is deliberately hedged ("indicators", "may", "consistent with"): a log pattern is
    evidence of suspicious behaviour, not proof of an attack. Each playbook also lists harmless
    explanations that could produce the same pattern.
  * Only values the parsers already validated (IP addresses) are ever placed inside example
    commands. Usernames and URLs from the log appear in prose only, never in commands."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from app.classification.models import Finding
from app.response.models import EvidenceItem, ReferenceCommands, ThreatDetail

PRIORITY = {
    "CRITICAL": "Act now: investigate immediately.",
    "HIGH": "Investigate today.",
    "MEDIUM": "Review soon.",
    "LOW": "Review when convenient.",
}
METHOD_LABEL = {
    ("rule",): "Rule-based detection",
    ("rule", "isolation_forest"): "Rule-based detection, corroborated by statistical analysis (Isolation Forest)",
    ("isolation_forest",): "Statistical analysis (Isolation Forest) only",
}
MAX_SHOWN = 5


@dataclass
class Playbook:
    name: str
    why: str
    benign: list[str]
    impact: list[str]
    solutions: list[str]
    mitigation: list[str]
    commands: list[ReferenceCommands] = field(default_factory=list)


# ------------------------------------------------------------------ small formatting helpers
def _safe_ip(value: str | None) -> str | None:
    """Only a syntactically valid IP address may ever be placed in an example command."""
    try:
        return str(ipaddress.ip_address(value)) if value else None
    except ValueError:
        return None


def _list(values: list, limit: int = MAX_SHOWN) -> str:
    shown = ", ".join(str(v) for v in values[:limit])
    return shown + (f" and {len(values) - limit} more" if len(values) > limit else "")


def _duration(start: str | None, end: str | None) -> str:
    if not (start and end):
        return "an unknown period"
    fmt = "%Y-%m-%d %H:%M:%S"
    seconds = int((datetime.strptime(end, fmt) - datetime.strptime(start, fmt)).total_seconds())
    if seconds < 60:
        return "under a minute" if seconds >= 0 else "an unknown period"
    if seconds < 3600:
        minutes = round(seconds / 60)
        return f"about {minutes} minute{'s' if minutes != 1 else ''}"
    hours = round(seconds / 3600, 1)
    return f"about {hours:g} hours"


def _period(f: Finding) -> str:
    return f"between {f.start} and {f.end}" if f.start and f.end else "in the uploaded log"


# ------------------------------------------------------------------ playbooks (one per detection rule)
def _failed_login_burst(f: Finding) -> Playbook:
    ip, m = f.source_ip or "the source", f.metrics
    ssh = "sshd" in f.services
    safe = _safe_ip(f.source_ip)
    commands = []
    if ssh:
        commands.append(ReferenceCommands(label="SSH hardening (example, review before applying)", lines=[
            "# /etc/ssh/sshd_config, then reload the SSH service",
            "PasswordAuthentication no", "PermitRootLogin no"]))
    if safe:
        commands.append(ReferenceCommands(label="Firewall (example, Linux ufw; only after confirming the IP is not legitimate)", lines=[
            f"sudo ufw deny from {safe}"]))
    return Playbook(
        name="SSH Brute Force Indicators" if ssh else "Brute Force Login Indicators",
        why=(f"{ip} produced {f.occurrences} failed logins {_period(f)}, up to {m.get('peak_failed_per_window')} within a single "
             f"{m.get('window_seconds', 60)}-second window, trying {m.get('distinct_usernames', '?')} different username(s). "
             "People who mistype a password rarely fail this often this quickly; automated tools that try many passwords do."),
        benign=["A script or service with an outdated saved password can generate repeated failures.",
                "Many users behind one shared (NAT) address can add up to a high failure count."],
        impact=["If a guess succeeds, the attacker gains access to that account and anything it can reach.",
                "Sustained attempts can lock out legitimate users and consume server resources.",
                "A compromised account can be used to steal data or as a foothold for further attacks."],
        solutions=[f"Investigate {ip}: check whether it belongs to you, a partner or a known scanner (reputation lookup, whois).",
                   "Review successful logins from this IP, and for the targeted accounts, after the failed attempts.",
                   "Limit repeated authentication failures (for example with fail2ban or firewall rate limits).",
                   "Disable password authentication where possible and use key-based authentication.",
                   "Disable direct root login and restrict remote access to known networks or a VPN.",
                   "Enable multi-factor authentication for remote access where available."],
        mitigation=[f"Check right away whether {ip} has a successful login in the same period (see related findings).",
                    f"Consider blocking or rate-limiting {ip} at the firewall, after confirming it is not a legitimate system.",
                    "Force a password reset for any account that shows a successful login from this IP.",
                    "Keep a copy of the original log file as evidence."],
        commands=commands)


def _repeated_failed_logins(f: Finding) -> Playbook:
    ip = f.source_ip or "the source"
    safe = _safe_ip(f.source_ip)
    return Playbook(
        name="Persistent Failed Login Indicators (Slow Brute Force)",
        why=(f"{ip} produced {f.occurrences} failed logins over {_duration(f.start, f.end)}, at a pace too slow to trigger the "
             "burst rule. Spreading attempts out is a common way to avoid rate-based alerts."),
        benign=["A service or user with a stale saved password retrying periodically.",
                "A monitoring or backup job that authenticates regularly with wrong credentials."],
        impact=["If a guess eventually succeeds, the attacker gains access to the account.",
                "Slow attempts are easy to overlook, so access may go unnoticed for longer."],
        solutions=[f"Investigate {ip} and confirm whether the failing logins come from a system you own.",
                   "Review successful logins from this IP over the same period.",
                   "Use account lockout or temporary bans based on failures over a longer period, not only per minute.",
                   "Use key-based authentication or multi-factor authentication for remote access."],
        mitigation=[f"Check whether {ip} has any successful login.",
                    "If the source is not recognised, rate-limit or block it after confirming it is not legitimate.",
                    "Fix or remove any automated job that is failing to authenticate."],
        commands=[ReferenceCommands(label="Firewall (example, Linux ufw)", lines=[f"sudo ufw deny from {safe}"])] if safe else [])


def _many_usernames(f: Finding) -> Playbook:
    ip, m = f.source_ip or "the source", f.metrics
    ssh = "sshd" in f.services
    return Playbook(
        name="SSH Username Guessing Indicators" if ssh else "Username Guessing / Password Spraying Indicators",
        why=(f"{ip} failed to log in as {m.get('distinct_failed_usernames')} different usernames ({m.get('failed_logins')} failed attempts)"
             + (f", including {_list(f.usernames)}" if f.usernames else "")
             + ". A real user has one username; trying many suggests a tool guessing account names or spraying common passwords."),
        benign=["A shared jump host or NAT address used by many people who each mistyped.",
                "A misconfigured integration trying several service-account names."],
        impact=["Valid account names may be discovered, which makes later password attacks easier.",
                "Weak or default passwords on any of those accounts could be guessed."],
        solutions=["Find out which of the tried usernames actually exist, and check whether any of them logged in successfully.",
                   "Disable or remove unused and default accounts.",
                   "Enforce strong, unique passwords and multi-factor authentication.",
                   "Restrict who may log in remotely (for example an SSH allow-list of approved users)."],
        mitigation=[f"Check for successful logins from {ip} under any username.",
                    "Reset passwords for accounts that were tried and are in use if there is any sign of a successful login.",
                    "Rate-limit or block the source after confirming it is not legitimate."],
        commands=[ReferenceCommands(label="SSH allow-list (example, review before applying)", lines=[
            "# /etc/ssh/sshd_config, then reload the SSH service", "AllowUsers <approved-users>"])] if ssh else [])


def _success_after_failures(f: Finding) -> Playbook:
    ip, m = f.source_ip or "the source", f.metrics
    accounts = _list(f.usernames) if f.usernames else "the account"
    safe = _safe_ip(f.source_ip)
    commands = [ReferenceCommands(label="Investigation (example, Linux)", lines=[
        "last -i | head -50", "sudo grep 'Accepted' /var/log/auth.log | tail -50"])]
    if safe:
        commands[0].lines.append(f'sudo grep "{safe}" /var/log/auth.log')
    return Playbook(
        name="Successful Login After Repeated Failures",
        why=(f"A successful login for {accounts} from {ip} at {m.get('first_success_at', 'an unknown time')} followed "
             f"{m.get('failures_before_first_success')} failed logins from the same IP in the previous "
             f"{m.get('lookback_seconds', 0) // 60} minutes. This is what a successful password guess looks like, so the account is "
             "possibly compromised."),
        benign=["A real user who mistyped their password many times before getting it right.",
                "An automated job that retried with the wrong credentials and then used the correct ones."],
        impact=["If the login was an attacker, they may have an authenticated session: access to files and data, the ability to run commands, "
                "and a route to escalate privileges.",
                "The attacker may add persistence (new SSH keys, accounts or scheduled tasks) so access survives a password change."],
        solutions=[f"Treat {accounts} as possibly compromised until the owner confirms the login from {ip} was theirs.",
                   "Reset the credentials, revoke SSH keys and end active sessions for the account.",
                   "Review what the account did after the login: commands run, sudo use, new files, changed configuration.",
                   "Check for persistence: new or changed authorized_keys, new users, new cron jobs or services.",
                   "Apply the brute-force protections listed for the related finding (rate limiting, key-based or multi-factor authentication)."],
        mitigation=[f"Contact the owner of {accounts} and ask whether they logged in from {ip} at {m.get('first_success_at', 'that time')}.",
                    "If they cannot confirm it, lock the account and terminate its active sessions.",
                    f"Block {ip} at the firewall if it is not a recognised system.",
                    "Preserve the log file and any session records before making changes."],
        commands=commands)


def _ssh_probing(f: Finding) -> Playbook:
    ip = f.source_ip or "the source"
    safe = _safe_ip(f.source_ip)
    return Playbook(
        name="SSH Service Probing Indicators",
        why=(f"{ip} opened {f.occurrences} connections that ended before completing a normal SSH handshake {_period(f)}. "
             "Scanners and bots do this when checking which services a host exposes."),
        benign=["A port or vulnerability scan run by your own team or monitoring service.",
                "A health check that connects to the SSH port without logging in."],
        impact=["Reconnaissance: the source is mapping exposed services, which often comes before a targeted attack.",
                "An exposed, unpatched SSH service could be exploited."],
        solutions=["Confirm whether the source is an approved scanner or monitoring system.",
                   "Limit SSH exposure: allow only known networks or a VPN at the firewall.",
                   "Keep the SSH server patched and use key-based authentication.",
                   "Monitor for follow-up login attempts from the same source."],
        mitigation=[f"Check whether {ip} also appears in failed or successful login events.",
                    "If the source is unknown, consider blocking it after confirming it is not legitimate."],
        commands=[ReferenceCommands(label="Firewall (example, Linux ufw)", lines=[f"sudo ufw deny from {safe}"])] if safe else [])


def _port_scan(f: Finding) -> Playbook:
    ip, m = f.source_ip or "the source", f.metrics
    safe = _safe_ip(f.source_ip)
    ports = f" (ports such as {_list(f.destination_ports, 8)})" if f.destination_ports else ""
    return Playbook(
        name="Port Scan Indicators",
        why=(f"{ip} contacted {m.get('peak_ports_per_window')} different destination ports within one {m.get('window_seconds', 60)}-second window "
             f"({f.occurrences} connections {_period(f)}){ports}. Touching many ports quickly is how port scanners find open services."),
        benign=["An approved vulnerability scanner or network inventory tool.",
                "A busy internal client that legitimately uses many services."],
        impact=["Reconnaissance: open services found by the scan can become targets for later attacks.",
                "Unneeded exposed services increase the attack surface."],
        solutions=["Confirm whether the source is an approved scanner.",
                   "Close or firewall every port that does not need to be reachable (default-deny inbound).",
                   "Use an intrusion detection or prevention system, or firewall rate limits for new connections.",
                   "Review the list of services actually exposed and patch them."],
        mitigation=[f"Check whether {ip} also shows failed logins or other suspicious findings.",
                    "If the source is not approved, block it at the perimeter.",
                    "Verify which of the contacted ports are actually open."],
        commands=[ReferenceCommands(label="Firewall (example, Linux ufw)", lines=[f"sudo ufw deny from {safe}"])] if safe else [])


def _http_flood(f: Finding) -> Playbook:
    ip, m = f.source_ip or "the source", f.metrics
    safe = _safe_ip(f.source_ip)
    commands = [ReferenceCommands(label="nginx rate limiting (example, review before applying)", lines=[
        "# in the http block", "limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;",
        "# in the server or location block", "limit_req zone=perip burst=20 nodelay;"])]
    if safe:
        commands.append(ReferenceCommands(label="Firewall (example, Linux ufw)", lines=[f"sudo ufw deny from {safe}"]))
    return Playbook(
        name="HTTP Request Flood (DoS-like Activity)",
        why=(f"{ip} sent {f.occurrences} HTTP requests {_period(f)}, up to {m.get('peak_requests_per_window')} in one "
             f"{m.get('window_seconds', 60)}-second window (about {m.get('requests_per_second_at_peak')} per second). "
             "That is far more than a normal visitor sends, and is consistent with a flood or an aggressive automated client."),
        benign=["A load test or monitoring probe.", "A misbehaving crawler or API integration.",
                "Many real users behind one shared (NAT) address."],
        impact=["The service may slow down or become unavailable for real users.",
                "Resource exhaustion can cost money (bandwidth, compute) and can hide other attacks."],
        solutions=[f"Confirm whether {ip} is an expected client (partner, crawler, load test).",
                   "Apply per-client rate limiting at the reverse proxy, load balancer or web application firewall.",
                   "Use a CDN or DDoS protection service for public sites.",
                   "Cache static and frequently requested content, and set connection limits.",
                   "Add alerts on request rate and server load."],
        mitigation=["Check the server's health and response times now.",
                    f"Apply a temporary rate limit to {ip}, or block it if it is not a legitimate client.",
                    "Look for server errors (5xx) in the same period: a related finding would show an actual impact."],
        commands=commands)


def _http_probing(f: Finding) -> Playbook:
    ip, m = f.source_ip or "the source", f.metrics
    agents = f" User agent(s): {_list(m.get('user_agents', []))}." if m.get("user_agents") else ""
    probed = f" Examples of URLs requested: {_list(f.paths, 4)}." if f.paths else ""
    safe = _safe_ip(f.source_ip)
    return Playbook(
        name="Web Probing / Vulnerability Scan Indicators",
        why=(f"{m.get('http_4xx')} of {m.get('http_requests')} requests from {ip} returned client errors across {m.get('distinct_urls')} "
             f"different URLs.{agents}{probed} Automated scanners request many URLs like this to look for admin pages, configuration files and "
             "known vulnerable paths."),
        benign=["A security scan run by your own team.", "A search-engine or SEO crawler following many stale links."],
        impact=["Any probed page that returned success (2xx) exists and is exposed; exposed admin panels, backups or configuration files "
                "can lead to data leaks or compromise.",
                "Injection attempts in URLs, if present, could exploit weak input handling."],
        solutions=["Check the responses to the probed URLs: any 2xx answer means that page is reachable by the public.",
                   "Make sure sensitive files (.env, .git, backups, configuration) are never served by the web server.",
                   "Restrict admin interfaces to a VPN or an IP allow-list.",
                   "Keep the web server and application up to date, and consider a web application firewall.",
                   "Rate-limit or block clients that generate large numbers of errors."],
        mitigation=[f"Search the log for requests from {ip} that did NOT return an error; those reached real pages.",
                    f"Rate-limit or block {ip} if it is not an approved scanner.",
                    "Confirm that no sensitive file or admin page is publicly reachable."],
        commands=[ReferenceCommands(label="Firewall (example, Linux ufw)", lines=[f"sudo ufw deny from {safe}"])] if safe else [])


def _http_auth_failures(f: Finding) -> Playbook:
    ip, m = f.source_ip or "the source", f.metrics
    targets = f" targeting {_list(f.paths, 3)}" if f.paths else ""
    safe = _safe_ip(f.source_ip)
    return Playbook(
        name="Web Login Credential Guessing Indicators",
        why=(f"{ip} received {m.get('http_401')} HTTP 401 (unauthorized) responses {_period(f)}{targets}. Many 'unauthorized' answers to "
             "one client are consistent with automated password guessing against a login endpoint."),
        benign=["A client or script that has an outdated saved password.", "Many real users behind one shared (NAT) address."],
        impact=["If a guess succeeds, the attacker gains access to a user account and its data.",
                "Credential-stuffing attacks reuse leaked passwords and succeed against reused passwords."],
        solutions=["Add rate limiting, temporary lockout or a CAPTCHA to login endpoints.",
                   "Require multi-factor authentication.",
                   "Check new passwords against lists of breached passwords.",
                   f"Search the log for a successful login response (for example a redirect after the failed attempts) from {ip}.",
                   "Alert on repeated failed web logins."],
        mitigation=[f"Check whether {ip} has any successful login after the failures.",
                    "If so, reset the password of the affected account and review its activity.",
                    f"Rate-limit or block {ip} if it is not a legitimate client."],
        commands=[ReferenceCommands(label="Firewall (example, Linux ufw)", lines=[f"sudo ufw deny from {safe}"])] if safe else [])


def _http_error_spike(f: Finding) -> Playbook:
    m = f.metrics
    return Playbook(
        name="Spike in HTTP Server Errors",
        why=(f"{m.get('http_5xx')} of {m.get('http_requests')} requests returned server errors (5xx) {_period(f)}. The service itself was failing "
             "for a large share of requests; the log alone cannot show whether the cause is an attack, a software fault or overload."),
        benign=["A faulty deployment or a crashed dependency such as a database.", "Planned maintenance or a restart."],
        impact=["Users could not use the service during this period.",
                "If caused by a flood, the service may fail again while the attack continues."],
        solutions=["Check application and server logs and resource use (CPU, memory, connections) for the same period.",
                   "Compare the time with recent deployments or configuration changes.",
                   "Check whether a traffic surge or flood finding overlaps with this period.",
                   "Add monitoring and alerting on the 5xx rate; review capacity."],
        mitigation=["Verify the service is healthy now.", "Roll back a recent change if one lines up with the start of the errors.",
                    "Look at the related findings for a traffic flood from a single source."])


def _unknown_anomaly(f: Finding) -> Playbook:
    return Playbook(
        name="Unusual Activity Pattern (Unclassified)",
        why=(f"{f.summary} Statistically this period differs from the rest of the log, but no detection rule matched, so the cause cannot be "
             "determined from the log alone."),
        benign=["A scheduled job, batch import or backup.", "A deployment, marketing campaign or other legitimate surge in traffic."],
        impact=["Unknown: it may be harmless, or an early sign of something worth investigating."],
        solutions=["Compare this period with known events: deployments, campaigns, scheduled jobs.",
                   "Read the raw log lines for this period (evidence below) and look for anything unexpected.",
                   "Collect more logs for context (authentication, firewall, application).",
                   "If this pattern recurs and is malicious, consider adding a specific detection rule."],
        mitigation=["No emergency action is indicated by this finding alone.",
                    "Review the period and confirm whether it matches expected activity."])


PLAYBOOKS: dict[str, Callable[[Finding], Playbook]] = {
    "failed_login_burst": _failed_login_burst,
    "repeated_failed_logins": _repeated_failed_logins,
    "many_usernames_from_ip": _many_usernames,
    "success_after_failures": _success_after_failures,
    "ssh_probing": _ssh_probing,
    "port_scan_like": _port_scan,
    "http_request_flood": _http_flood,
    "http_probing": _http_probing,
    "http_auth_failures": _http_auth_failures,
    "http_server_error_spike": _http_error_spike,
    "isolation_forest_window": _unknown_anomaly,
}


def build_threat_detail(finding: Finding) -> ThreatDetail:
    """The primary rule decides the playbook (a finding merged from several episodes shares one rule)."""
    playbook = PLAYBOOKS[finding.rule_ids[0]](finding)
    risk = finding.risk
    return ThreatDetail(
        finding_id=finding.finding_id,
        threat_name=playbook.name,
        category=finding.category,
        severity=risk.severity,
        risk_score=risk.score,
        priority=PRIORITY[risk.severity],
        confidence=finding.confidence,
        confidence_basis=finding.confidence_basis,
        description=finding.summary,
        why_suspicious=playbook.why,
        classification_basis=finding.classification_basis,
        possible_benign_explanations=playbook.benign,
        source_ip=finding.source_ip,
        destination_ips=finding.destination_ips,
        destination_ports=finding.destination_ports,
        affected_services=finding.services,
        affected_hosts=finding.hosts,
        accounts_involved=finding.usernames,
        urls_involved=finding.paths,
        first_seen=finding.start,
        last_seen=finding.end,
        occurrences=finding.occurrences,
        detection_method=METHOD_LABEL[tuple(finding.detection_methods)],
        detection_methods=finding.detection_methods,
        rule_ids=finding.rule_ids,
        evidence=[EvidenceItem(**item) for item in finding.evidence],
        evidence_total=finding.evidence_total,
        possible_impact=playbook.impact,
        recommended_solutions=playbook.solutions,
        immediate_mitigation=playbook.mitigation,
        reference_commands=playbook.commands,
        risk_explanation=risk.explanation,
        risk_factors=risk.factors,
        risk_caps=risk.caps_applied,
        related_finding_ids=finding.related_finding_ids,
    )


def build_threat_details(findings: list[Finding]) -> list[ThreatDetail]:
    return [build_threat_detail(finding) for finding in findings]

import copy
import functools
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.classification.models import SEVERITIES
from app.ingestion.log_reader import read_upload
from app.pipeline import analyze_log
from app.reporting.markdown_report import render_markdown
from app.reporting.report_generator import CLEAN_MESSAGE, MAX_CHART_POINTS, build_report
from app.response.response_engine import PLAYBOOKS, PRIORITY, _duration, _safe_ip, build_threat_detail, build_threat_details

REF = datetime(2026, 11, 2)
SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"
SAMPLE_NAMES = ["normal_ssh_auth.log", "bruteforce_ssh_auth.log", "normal_web_access.log", "suspicious_web_access.log", "sample_events.csv"]


def analyze(text, name="x.log"):
    return analyze_log(read_upload(name, text.encode()), None, REF)


@functools.lru_cache(maxsize=None)
def sample(name):
    """Analysis of a sample file, computed once per test run. Tests must treat it as read-only
    (anything that modifies a finding works on copy.deepcopy)."""
    return analyze_log(read_upload(name, (SAMPLES / name).read_bytes()), None, REF)


def report_for(name, **kwargs):
    return build_report(sample(name), **kwargs)


def texts(detail):
    """Every human-readable string in a ThreatDetail."""
    parts = [detail.threat_name, detail.description, detail.why_suspicious, detail.priority, detail.risk_explanation]
    for group in (detail.possible_impact, detail.recommended_solutions, detail.immediate_mitigation,
                  detail.possible_benign_explanations, detail.confidence_basis):
        parts += group
    return parts


def syslog(minute, message, second=0):
    t = datetime(2026, 9, 22, 10, 0, 0) + timedelta(minutes=minute, seconds=second)
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S} h sshd[1]: {message}"


# ================================================================ response engine
def test_every_rule_has_a_playbook():
    from app.classification.attack_classifier import RULE_CATEGORY
    assert set(RULE_CATEGORY) | {"isolation_forest_window"} == set(PLAYBOOKS)


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_every_finding_gets_complete_advice(name):
    analysis = sample(name)
    for detail in build_threat_details(analysis.findings):
        assert detail.threat_name and detail.why_suspicious and detail.description
        assert detail.possible_impact and detail.recommended_solutions and detail.immediate_mitigation
        assert detail.possible_benign_explanations
        assert detail.priority == PRIORITY[detail.severity]
        assert detail.evidence and detail.evidence_total >= len(detail.evidence)
        assert all(isinstance(text, str) and text.strip() for text in texts(detail))


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_advice_never_claims_a_confirmed_attack_or_compromise(name):
    forbidden = re.compile(r"(has been|was|were|is|are) (compromised|hacked|breached)|attack (is )?confirmed|you (were|have been) hacked", re.I)
    for detail in build_threat_details(sample(name).findings):
        for text in texts(detail):
            assert not forbidden.search(text), text


def test_suspicious_login_is_worded_as_possible_compromise():
    detail = next(d for d in build_threat_details(sample("bruteforce_ssh_auth.log").findings) if d.category == "Suspicious Login Activity")
    assert "possibly compromised" in detail.why_suspicious
    assert detail.accounts_involved == ["deploy"]
    assert "deploy" in detail.recommended_solutions[0] and "203.0.113.50" in detail.recommended_solutions[0]
    assert any("2026-09-22 14:06:30" in step for step in detail.immediate_mitigation)


def test_ssh_brute_force_advice_matches_the_spec_example():
    detail = build_threat_details(sample("bruteforce_ssh_auth.log").findings)[0]
    assert detail.threat_name == "SSH Brute Force Indicators" and detail.severity == "CRITICAL"
    solutions = " ".join(detail.recommended_solutions).lower()
    for expected in ("investigate", "successful logins", "limit repeated", "disable password authentication", "key-based", "multi-factor"):
        assert expected in solutions
    assert "203.0.113.50" in detail.recommended_solutions[0]
    assert "327 failed logins" in detail.why_suspicious
    lines = [line for commands in detail.reference_commands for line in commands.lines]
    assert "PasswordAuthentication no" in lines and "sudo ufw deny from 203.0.113.50" in lines


def test_web_findings_advice_uses_real_facts():
    by_ip = {d.source_ip: d for d in build_threat_details(sample("suspicious_web_access.log").findings)}
    flood, guesser, scanner = by_ip["192.0.2.200"], by_ip["203.0.113.77"], by_ip["198.51.100.99"]
    assert flood.threat_name.startswith("HTTP Request Flood") and "900 HTTP requests" in flood.why_suspicious
    assert any("limit_req" in line for c in flood.reference_commands for line in c.lines)
    assert "/login" in guesser.why_suspicious and "120" in guesser.why_suspicious
    assert "Nikto/2.5.0" in scanner.why_suspicious and "/admin" in scanner.why_suspicious
    assert scanner.urls_involved[0] == "/admin"


def test_destination_information_is_carried_through():
    port_scan = next(d for d in build_threat_details(sample("sample_events.csv").findings) if d.category == "Port Scanning")
    assert port_scan.source_ip == "203.0.113.9" and port_scan.destination_ips == ["10.0.0.10"]
    assert port_scan.destination_ports == sorted([22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5900, 8080])[:10]
    assert "ports such as" in port_scan.why_suspicious


def test_unknown_anomaly_advice_is_honest_and_has_no_commands():
    start = datetime(2026, 9, 22, 10, 0, 0)
    line = lambda t, ip: f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +0000] "GET / HTTP/1.1" 200 10 "-" "ua"'
    lines = [line(start + timedelta(minutes=m, seconds=s), f"10.1.{m % 200}.{s + 1}") for m in range(60) for s in (0, 20)]
    lines += [line(start + timedelta(minutes=30, seconds=s % 60), f"172.16.{s}.1") for s in range(60)]
    detail = build_threat_details(analyze("\n".join(lines)).findings)[0]
    assert detail.category == "Unknown Anomaly" and detail.detection_method == "Statistical analysis (Isolation Forest) only"
    assert "cannot be determined" in detail.why_suspicious
    assert detail.reference_commands == [] and "No emergency action" in detail.immediate_mitigation[0]
    assert detail.confidence == "low"


def test_only_validated_ips_are_ever_placed_in_commands():
    assert _safe_ip("203.0.113.50") == "203.0.113.50"
    assert _safe_ip("1.2.3.4; rm -rf /") is None and _safe_ip("$(whoami)") is None and _safe_ip(None) is None
    finding = copy.deepcopy(sample("bruteforce_ssh_auth.log").findings[0])
    finding.source_ip = "1.2.3.4; rm -rf /"                       # cannot occur via the parsers, but defend anyway
    detail = build_threat_detail(finding)
    commands = [line for c in detail.reference_commands for line in c.lines]
    assert commands and not any("rm -rf" in line for line in commands)
    assert not any(line.startswith("sudo ufw deny") for line in commands)


def test_log_derived_text_never_reaches_a_command_line():
    """Inject unmistakable canary values as usernames, URLs and user agents. They may appear in the
    explanatory prose, but must never appear in any example command."""
    canaries = ("CANARY_USER", "/CANARY_PATH", "CANARY_AGENT", "CANARY_HOST")
    checked = 0
    for name in SAMPLE_NAMES:
        for finding in sample(name).findings:
            tainted = copy.deepcopy(finding)
            tainted.usernames, tainted.paths, tainted.hosts = ["CANARY_USER"], ["/CANARY_PATH"], ["CANARY_HOST"]
            if "user_agents" in tainted.metrics:
                tainted.metrics["user_agents"] = ["CANARY_AGENT"]
            detail = build_threat_detail(tainted)
            commands = "\n".join(line for c in detail.reference_commands for line in c.lines)
            checked += len(detail.reference_commands)
            assert not any(canary in commands for canary in canaries), (name, finding.rule_ids, commands)
    assert checked > 5                                           # the test really exercised command blocks


def test_duration_wording():
    assert _duration("2026-09-22 10:00:00", "2026-09-22 10:00:30") == "under a minute"
    assert _duration("2026-09-22 10:00:00", "2026-09-22 10:04:00") == "about 4 minutes"
    assert _duration("2026-09-22 10:00:00", "2026-09-22 13:00:00") == "about 3 hours"
    assert _duration(None, None) == "an unknown period"


def test_response_is_deterministic():
    first = [d.model_dump() for d in build_threat_details(sample("suspicious_web_access.log").findings)]
    second = [d.model_dump() for d in build_threat_details(sample("suspicious_web_access.log").findings)]
    assert first == second


# ================================================================ report: clean log
def test_clean_report_for_normal_logs():
    for name in ("normal_ssh_auth.log", "normal_web_access.log"):
        report = report_for(name)
        assert report.status.overall_status == "clean" and report.status.status_label == "CLEAN / NO ANOMALIES DETECTED"
        assert report.status.message == CLEAN_MESSAGE
        assert "does not prove the system is secure" in report.status.note
        assert report.overview.total_anomalies == 0 and report.overview.suspicious_events == 0 and report.findings == []
        assert report.remediation_summary == [] and report.category_distribution == {}
        assert report.charts["activity_over_time"] and report.activity_summary
        assert report.charts["severity_distribution"]["values"] == [0, 0, 0, 0]
        assert sum(report.charts["suspicious_timeline"]["values"]) == 0 and report.charts["top_suspicious_ips"] == []


def test_analysis_timestamp_is_utc_and_injectable():
    moment = datetime(2026, 11, 3, 12, 30, 5, tzinfo=timezone.utc)
    assert report_for("normal_ssh_auth.log", analyzed_at=moment).meta.analyzed_at == "2026-11-03 12:30:05 UTC"
    assert report_for("normal_ssh_auth.log").meta.analyzed_at.endswith(" UTC")


# ================================================================ report: attack logs
def test_overview_counts_distinct_suspicious_events_not_a_sum():
    analysis = sample("bruteforce_ssh_auth.log")
    report = build_report(analysis)
    assert report.overview.total_anomalies == 3
    assert report.overview.suspicious_events == 328          # 327 failed logins + 1 success; NOT 327 + 327 + 1
    assert sum(f.occurrences for f in report.findings) == 655
    assert (report.overview.critical_alerts, report.overview.high_risk_events) == (2, 1)
    assert report.overview.total_logs_processed == analysis.parsed.parsed_count == 913
    assert report.overview.unique_source_ips == analysis.parsed.records["source_ip"].nunique() == 5
    assert report.status.overall_status == "critical" and "including 2 rated CRITICAL" in report.status.message


def test_web_report_numbers():
    report = report_for("suspicious_web_access.log")
    assert report.overview.suspicious_events == 242 + 120 + 900
    assert report.status.overall_status == "suspicious" and report.severity_distribution == {"LOW": 0, "MEDIUM": 0, "HIGH": 3, "CRITICAL": 0}
    assert report.overview.unique_source_ips == 53
    assert report.log_summary["authentication"] is None and report.log_summary["http"]["requests"] == 1571


def test_distributions_and_top_ips():
    report = report_for("bruteforce_ssh_auth.log")
    assert list(report.severity_distribution) == SEVERITIES and sum(report.severity_distribution.values()) == 3
    assert report.category_distribution == {"Brute Force Attack": 1, "Credential Attack Indicators": 1, "Suspicious Login Activity": 1}
    assert report.charts["top_suspicious_ips"] == [{"source_ip": "203.0.113.50", "findings": 3, "max_risk_score": 77, "severity": "CRITICAL", "occurrences": 655}]
    web = report_for("suspicious_web_access.log").charts["top_suspicious_ips"]
    assert [e["source_ip"] for e in web] == ["192.0.2.200", "203.0.113.77", "198.51.100.99"]


def test_remediation_summary_follows_priority_order():
    report = report_for("suspicious_web_access.log")
    assert [r.finding_id for r in report.remediation_summary] == [f.finding_id for f in report.findings]
    assert [r.priority for r in report.remediation_summary] == [1, 2, 3]
    assert all(1 <= len(r.actions) <= 3 for r in report.remediation_summary)
    assert report.remediation_summary[0].actions == report.findings[0].immediate_mitigation[:3]


def test_capability_aware_log_summary():
    ssh, web = report_for("bruteforce_ssh_auth.log"), report_for("normal_web_access.log")
    assert ssh.log_summary["http"] is None and ssh.log_summary["authentication"]["failed_logins"] == 330
    assert ssh.log_summary["network"] is None
    assert web.log_summary["authentication"] is None and web.log_summary["http"]["rate_5xx"] is not None
    assert ssh.log_summary["most_active_source_ips"][0]["source_ip"] == "203.0.113.50"
    assert ssh.charts["activity_over_time"]["http_4xx"] is None and web.charts["activity_over_time"]["failed_logins"] is None


def test_csv_report_has_network_summary_and_no_ml():
    report = report_for("sample_events.csv")
    assert report.log_summary["network"] == {"unique_destination_ips": 1, "unique_destination_ports": 12}
    assert report.analysis_details["machine_learning"]["ran"] is False
    skipped = [r for r in report.analysis_details["rules"] if not r["ran"]]
    assert skipped and all(r["skipped_reason"] for r in skipped)


# ================================================================ report: charts are consistent with the data
@pytest.mark.parametrize("name", ["bruteforce_ssh_auth.log", "suspicious_web_access.log"])
def test_chart_series_are_aligned_and_add_up(name):
    analysis = sample(name)
    report = build_report(analysis)
    activity, suspicious = report.charts["activity_over_time"], report.charts["suspicious_timeline"]
    n = len(activity["labels"])
    assert 0 < n <= MAX_CHART_POINTS and len(activity["events"]) == len(suspicious["values"]) == len(suspicious["labels"]) == n
    assert sum(activity["events"]) == analysis.parsed.records["timestamp"].notna().sum()
    assert sum(suspicious["values"]) == report.overview.suspicious_events
    events = report.charts["event_type_distribution"]
    assert sum(events["values"]) == analysis.parsed.parsed_count and len(events["labels"]) == len(events["values"])


def test_long_logs_are_bucketed_without_losing_events():
    start = datetime(2026, 9, 22, 0, 0, 0)
    lines = [f'10.0.0.1 - - [{start + timedelta(minutes=m):%d/%b/%Y:%H:%M:%S} +0000] "GET / HTTP/1.1" 200 10 "-" "ua"' for m in range(700)]
    report = build_report(analyze("\n".join(lines)))
    activity = report.charts["activity_over_time"]
    assert activity["bucket_seconds"] == 180 and len(activity["labels"]) <= MAX_CHART_POINTS
    assert sum(activity["events"]) == 700


def test_log_without_timestamps_has_no_time_charts_and_no_invented_values():
    report = build_report(analyze("src_ip,user,action\n1.1.1.1,a,login_failed\n1.1.1.1,b,login_failed\n2.2.2.2,c,login_success\n", "a.csv"))
    assert report.charts["activity_over_time"] is None and report.charts["suspicious_timeline"] is None
    assert report.meta.time_range is None and report.overview.total_logs_processed == 3
    assert report.overview.unique_source_ips == 2


def test_overview_hides_metrics_the_log_cannot_provide():
    report = build_report(analyze("time,message\n2026-09-22 10:00:00,hello\n2026-09-22 10:00:05,world\n", "a.csv"))
    assert report.overview.unique_source_ips is None
    assert report.log_summary["authentication"] is None and report.log_summary["http"] is None
    assert report.log_summary["most_active_source_ips"] is None


def test_report_is_json_serializable_and_deterministic():
    moment = datetime(2026, 11, 3, tzinfo=timezone.utc)
    first = report_for("suspicious_web_access.log", analyzed_at=moment).model_dump()
    json.dumps(first)
    assert first == report_for("suspicious_web_access.log", analyzed_at=moment).model_dump()


# ================================================================ markdown
def test_markdown_report_contains_the_essentials():
    markdown = render_markdown(report_for("bruteforce_ssh_auth.log"))
    for expected in ("# Security Log Analysis Report", "CRITICAL SECURITY ISSUES DETECTED", "F-001: SSH Brute Force Indicators",
                     "203.0.113.50", "Immediate mitigation", "Recommended solutions", "Evidence", "indicators",
                     "never changes firewalls", "bruteforce_ssh_auth.log"):
        assert expected in markdown
    assert "PasswordAuthentication no" in markdown


def test_markdown_for_clean_log():
    markdown = render_markdown(report_for("normal_ssh_auth.log"))
    assert "CLEAN / NO ANOMALIES DETECTED" in markdown and CLEAN_MESSAGE in markdown and "## Findings" not in markdown


def test_markdown_cannot_be_broken_by_hostile_log_content():
    hostile = "\n".join(syslog(0, "Failed password for `evil` from 9.9.9.9 port 22 ssh2 ``` # injected [click](http://evil.example)", s) for s in range(15))
    markdown = render_markdown(build_report(analyze(hostile)))
    evidence_block = markdown.split("**Evidence**")[1].split("**Risk breakdown**")[0]
    assert evidence_block.count("```") == 2                  # only OUR opening and closing fences
    assert "`evil`" not in evidence_block and "'evil'" in evidence_block


# ================================================================ API
def test_report_endpoints():
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    data = (SAMPLES / "bruteforce_ssh_auth.log").read_bytes()

    response = client.post("/api/report", files={"file": ("../../bruteforce.log", data)})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["meta"]["filename"] == "bruteforce.log"                       # sanitized
    assert body["status"]["overall_status"] == "critical" and body["overview"]["suspicious_events"] == 328
    assert body["findings"][0]["threat_name"] == "SSH Brute Force Indicators"
    assert body["charts"]["activity_over_time"]["labels"] and body["analysis_details"]["rules"]

    md = client.post("/api/report/markdown", files={"file": ("x.log", data)})
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    assert md.headers["content-disposition"] == 'attachment; filename="security-report.md"'
    assert "# Security Log Analysis Report" in md.text

    clean = client.post("/api/report", files={"file": ("n.log", (SAMPLES / "normal_ssh_auth.log").read_bytes())}).json()
    assert clean["status"]["overall_status"] == "clean" and clean["findings"] == []


def test_report_endpoints_reuse_upload_validation():
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    assert client.post("/api/report", files={"file": ("x.exe", b"MZ")}).status_code == 415
    assert client.post("/api/report/markdown", files={"file": ("e.log", b"")}).status_code == 422
    bad = client.post("/api/report", files={"file": ("m.log", (SAMPLES / "malformed_sample.log").read_bytes())})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "unknown_format"

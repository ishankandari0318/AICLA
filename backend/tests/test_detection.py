import json
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.detection.anomaly_detector import detect
from app.detection.models import METHOD_ML, METHOD_RULE, Thresholds
from app.features.feature_engineering import extract_features
from app.ingestion.log_reader import read_upload
from app.parsing.log_parser import parse_log

REF = datetime(2026, 11, 2)
SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"


def run(text, name="x.log", thresholds=None):
    records = parse_log(read_upload(name, text.encode()), REF).records
    return detect(records, extract_features(records), thresholds)


def run_sample(name, thresholds=None):
    records = parse_log(read_upload(name, (SAMPLES / name).read_bytes()), REF).records
    return detect(records, extract_features(records), thresholds)


def by_rule(result, rule_id):
    return [d for d in result.detections if d.rule_id == rule_id]


def syslog(minutes_offset, message, seconds=0):
    t = datetime(2026, 9, 22, 10, 0, 0) + timedelta(minutes=minutes_offset, seconds=seconds)
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S} h sshd[1]: {message}"


def apache(t, ip, status=200, path="/", method="GET"):
    return f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} 10 "-" "ua"'


# ================================================================ normal logs must stay clean
@pytest.mark.parametrize("name", ["normal_ssh_auth.log", "normal_web_access.log"])
def test_normal_logs_produce_no_findings(name):
    result = run_sample(name)
    assert result.detections == []
    assert result.ml["ran"] is True            # the model did run...
    assert result.ml["windows_reported"] == 0  # ...and the materiality gate kept the result clean


def test_the_gate_matters_the_model_alone_would_have_flagged_normal_windows():
    result = run_sample("normal_web_access.log")
    assert result.ml["windows_flagged_by_model"] > 0       # Isolation Forest always flags some windows
    assert result.detections == []                         # but none is material


# ================================================================ SSH brute force sample
def test_bruteforce_sample_findings():
    result = run_sample("bruteforce_ssh_auth.log")
    rule_ids = {d.rule_id for d in result.detections}
    assert rule_ids == {"failed_login_burst", "many_usernames_from_ip", "success_after_failures", "isolation_forest_window"}

    burst = by_rule(result, "failed_login_burst")[0]
    assert (burst.method, burst.source_ip, burst.occurrences) == (METHOD_RULE, "203.0.113.50", 327)
    assert burst.metrics["peak_failed_per_window"] >= 70
    assert burst.start == "2026-09-22 14:02:10" and burst.end <= "2026-09-22 14:06:30"

    spray = by_rule(result, "many_usernames_from_ip")[0]
    assert spray.metrics["distinct_failed_usernames"] == 10

    compromise = by_rule(result, "success_after_failures")[0]
    assert compromise.source_ip == "203.0.113.50"
    assert "deploy" in compromise.usernames
    assert compromise.occurrences == 1
    assert compromise.metrics["failures_before_first_success"] == 327

    # Internal users are never reported
    assert {d.source_ip for d in result.detections} == {"203.0.113.50"}


def test_ml_and_rule_findings_are_distinguishable_and_linked():
    result = run_sample("bruteforce_ssh_auth.log")
    ml = [d for d in result.detections if d.method == METHOD_ML]
    rules = [d for d in result.detections if d.method == METHOD_RULE]
    assert len(ml) == 1 and len(rules) == 3
    assert set(ml[0].related_detection_ids) == {d.detection_id for d in rules}     # ML corroborated by all three
    assert "not a confirmed attack" in ml[0].description
    assert ml[0].metrics["anomaly_score"] > 0.5 and ml[0].metrics["top_deviations"]
    assert ml[0].source_ip == "203.0.113.50"                                        # one IP dominated those windows


def test_no_rule_for_web_runs_on_an_ssh_log_and_vice_versa():
    ssh = {s.rule_id: s for s in run_sample("bruteforce_ssh_auth.log").rules}
    assert not ssh["http_request_flood"].ran and "HTTP request data" in ssh["http_request_flood"].skipped_reason
    assert not ssh["port_scan_like"].ran and "destination ports" in ssh["port_scan_like"].skipped_reason
    web = {s.rule_id: s for s in run_sample("suspicious_web_access.log").rules}
    assert not web["failed_login_burst"].ran and "login" in web["failed_login_burst"].skipped_reason
    assert web["http_probing"].ran


# ================================================================ HTTP sample
def test_suspicious_web_sample_findings():
    result = run_sample("suspicious_web_access.log")
    rules = {d.rule_id: d for d in result.detections if d.method == METHOD_RULE}
    assert set(rules) == {"http_probing", "http_auth_failures", "http_request_flood"}

    probing = rules["http_probing"]
    assert (probing.source_ip, probing.occurrences, probing.metrics["distinct_urls"]) == ("198.51.100.99", 242, 12)
    assert probing.metrics["user_agents"] == ["Nikto/2.5.0"]
    assert (rules["http_auth_failures"].source_ip, rules["http_auth_failures"].occurrences) == ("203.0.113.77", 120)
    flood = rules["http_request_flood"]
    assert (flood.source_ip, flood.occurrences, flood.metrics["requests_per_second_at_peak"]) == ("192.0.2.200", 900, 15.0)

    # every reported IP is one of the three attackers; none of the ~50 ordinary visitors
    assert {d.source_ip for d in result.detections} == {"198.51.100.99", "203.0.113.77", "192.0.2.200"}
    # and the login guesser is NOT mislabelled as a URL scanner (it only hits one URL)
    assert all(d.source_ip != "203.0.113.77" for d in by_rule(result, "http_probing"))


# ================================================================ CSV sample (no ML, port scan)
def test_csv_sample_port_scan_and_small_data_handling():
    result = run_sample("sample_events.csv")
    rules = {d.rule_id: d for d in result.detections}
    assert set(rules) == {"failed_login_burst", "port_scan_like"}
    assert all(d.source_ip == "203.0.113.9" for d in result.detections)
    assert rules["port_scan_like"].metrics["distinct_ports_total"] == 12
    assert result.ml["ran"] is False and "active time windows" in result.ml["reason"]
    assert any("Machine-learning detection did not run" in n for n in result.notes)


# ================================================================ evidence is real
@pytest.mark.parametrize("name", ["bruteforce_ssh_auth.log", "suspicious_web_access.log"])
def test_evidence_matches_the_uploaded_file_line_for_line(name):
    lines = (SAMPLES / name).read_text(encoding="utf-8").split("\n")
    result = run_sample(name)
    assert result.detections
    for detection in result.detections:
        assert detection.evidence and 0 < len(detection.evidence) <= 5
        assert detection.evidence_total >= len(detection.evidence)
        for item in detection.evidence:
            assert lines[item["line_no"] - 1].strip() == item["raw_line"]      # the exact line from the file
            if detection.method == METHOD_RULE and detection.source_ip:
                assert detection.source_ip in item["raw_line"]


def test_detections_are_json_serializable_and_have_unique_ordered_ids():
    result = run_sample("suspicious_web_access.log")
    json.dumps([asdict(d) for d in result.detections])
    ids = [d.detection_id for d in result.detections]
    assert ids == [f"D-{i:03d}" for i in range(1, len(ids) + 1)]
    starts = [d.start for d in result.detections]
    assert starts == sorted(starts)


def test_detection_is_deterministic():
    first = [asdict(d) for d in run_sample("suspicious_web_access.log").detections]
    second = [asdict(d) for d in run_sample("suspicious_web_access.log").detections]
    assert first == second


# ================================================================ individual rules on small synthetic logs
def test_slow_brute_force_is_caught_by_the_repeated_failures_rule_not_the_burst_rule():
    text = "\n".join(syslog(i * 5, "Failed password for admin from 9.9.9.9 port 22 ssh2") for i in range(25))
    result = run(text)
    assert not by_rule(result, "failed_login_burst")
    finding = by_rule(result, "repeated_failed_logins")[0]
    assert (finding.source_ip, finding.occurrences) == ("9.9.9.9", 25)


def test_burst_ip_is_not_double_reported_as_slow_brute_force():
    result = run_sample("bruteforce_ssh_auth.log")
    assert not by_rule(result, "repeated_failed_logins")


def test_ssh_probing_rule():
    text = "\n".join(syslog(0, "Did not receive identification string from 7.7.7.7 port 4000", s) for s in range(6))
    finding = by_rule(run(text), "ssh_probing")[0]
    assert (finding.source_ip, finding.occurrences) == ("7.7.7.7", 6)


def test_few_failures_do_not_trigger_anything():
    text = "\n".join(syslog(i, "Failed password for bob from 1.2.3.4 port 22 ssh2") for i in range(4))
    assert run(text).detections == []


def test_success_after_failures_needs_failures_from_the_same_ip_just_before():
    failures = [syslog(0, "Failed password for bob from 1.2.3.4 port 22 ssh2", s) for s in range(6)]
    quick = run("\n".join(failures + [syslog(1, "Accepted password for bob from 1.2.3.4 port 22 ssh2")]))
    assert len(by_rule(quick, "success_after_failures")) == 1
    too_late = run("\n".join(failures + [syslog(90, "Accepted password for bob from 1.2.3.4 port 22 ssh2")]))   # 90 min later
    assert not by_rule(too_late, "success_after_failures")
    other_ip = run("\n".join(failures + [syslog(1, "Accepted password for bob from 5.6.7.8 port 22 ssh2")]))
    assert not by_rule(other_ip, "success_after_failures")


def test_http_server_error_spike_rule():
    start = datetime(2026, 9, 22, 10, 0, 0)
    lines = [apache(start + timedelta(seconds=i), f"10.0.0.{i + 1}", 503 if i < 12 else 200) for i in range(30)]
    finding = by_rule(run("\n".join(lines)), "http_server_error_spike")[0]
    assert finding.source_ip is None and finding.occurrences == 12 and finding.metrics["http_requests"] == 30


def test_thresholds_can_be_changed():
    loose = run_sample("bruteforce_ssh_auth.log")
    strict = run_sample("bruteforce_ssh_auth.log", Thresholds(failed_login_burst_per_window=500))
    assert by_rule(loose, "failed_login_burst") and not by_rule(strict, "failed_login_burst")


# ================================================================ ML on its own
def test_isolation_forest_finds_what_rules_cannot_a_distributed_spike():
    """60 quiet minutes (2 requests each), then ONE minute with 60 requests from 60 DIFFERENT IPs.
    No single IP is noisy, so no rule fires; only the statistical model sees the surge."""
    start = datetime(2026, 9, 22, 10, 0, 0)
    lines = [apache(start + timedelta(minutes=m, seconds=s), f"10.1.{m % 200}.{s + 1}") for m in range(60) for s in (0, 20)]
    spike_minute = start + timedelta(minutes=30)
    lines += [apache(spike_minute + timedelta(seconds=s % 60), f"172.16.{s}.1") for s in range(60)]
    result = run("\n".join(lines))
    assert [d for d in result.detections if d.method == METHOD_RULE] == []
    ml = [d for d in result.detections if d.method == METHOD_ML]
    assert len(ml) == 1
    assert ml[0].start == "2026-09-22 10:30:00" and ml[0].source_ip is None       # no single dominant IP
    assert {m["feature"] for m in ml[0].metrics["top_deviations"]} >= {"events", "unique_source_ips"}


def test_ml_does_not_run_on_small_logs():
    text = "\n".join(syslog(i, "Accepted password for bob from 1.2.3.4 port 22 ssh2") for i in range(5))
    result = run(text)
    assert result.ml["ran"] is False and result.ml["windows_analyzed"] == 5


def test_log_with_no_usable_fields_runs_no_rules_and_says_so():
    result = run("time,message\n2026-09-22 10:00:00,hello\n2026-09-22 10:00:05,world\n", "a.csv")
    assert result.detections == [] and not any(s.ran for s in result.rules if s.rule_id != "ssh_probing")
    assert result.ml["ran"] is False


def test_removing_the_gate_makes_normal_logs_noisy_proving_the_gate_is_what_keeps_them_clean():
    ungated = run_sample("normal_web_access.log", Thresholds(ml_min_deviation=0.0))
    assert any(d.method == METHOD_ML for d in ungated.detections)       # the raw model flags ordinary windows
    gated = run_sample("normal_web_access.log")
    assert gated.detections == []

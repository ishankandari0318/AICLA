import copy
import json
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.classification.attack_classifier import classify, strength_of
from app.classification.models import (
    BRUTE_FORCE, CATEGORIES, CREDENTIAL_ATTACK, DOS_LIKE, PORT_SCANNING, SUSPICIOUS_LOGIN, UNKNOWN_ANOMALY, UNUSUAL_HTTP,
)
from app.detection.models import METHOD_ML, Thresholds
from app.ingestion.log_reader import read_upload
from app.pipeline import analyze_log
from app.risk.risk_engine import MAX_POINTS, assess, severity_for, summarize

REF = datetime(2026, 11, 2)
SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"


def analyze(text, name="x.log", thresholds=None):
    return analyze_log(read_upload(name, text.encode()), thresholds, REF)


def analyze_sample(name, thresholds=None):
    return analyze_log(read_upload(name, (SAMPLES / name).read_bytes()), thresholds, REF)


def by_category(analysis, category):
    return [f for f in analysis.findings if f.category == category]


def syslog(minute, message, second=0):
    t = datetime(2026, 9, 22, 10, 0, 0) + timedelta(minutes=minute, seconds=second)
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S} h sshd[1]: {message}"


def apache(t, ip, status=200, path="/"):
    return f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +0000] "GET {path} HTTP/1.1" {status} 10 "-" "ua"'


# ================================================================ severity bands
@pytest.mark.parametrize("score,expected", [(0, "LOW"), (24, "LOW"), (25, "MEDIUM"), (49, "MEDIUM"),
                                            (50, "HIGH"), (74, "HIGH"), (75, "CRITICAL"), (100, "CRITICAL")])
def test_severity_bands_match_the_specification(score, expected):
    assert severity_for(score) == expected


# ================================================================ classification of the samples
def test_normal_logs_have_no_findings_and_a_clean_status():
    for name in ("normal_ssh_auth.log", "normal_web_access.log"):
        analysis = analyze_sample(name)
        assert analysis.findings == []
        assert analysis.risk_summary["overall_status"] == "clean"
        assert analysis.risk_summary["total_findings"] == 0 and analysis.risk_summary["highest_score"] == 0


def test_ssh_bruteforce_sample_is_classified_into_three_categories_for_one_ip():
    analysis = analyze_sample("bruteforce_ssh_auth.log")
    assert {f.category for f in analysis.findings} == {BRUTE_FORCE, CREDENTIAL_ATTACK, SUSPICIOUS_LOGIN}
    assert {f.source_ip for f in analysis.findings} == {"203.0.113.50"}
    assert len(analysis.findings) == 3                          # the ML detection is absorbed, not a 4th threat
    assert not by_category(analysis, UNKNOWN_ANOMALY)
    brute = by_category(analysis, BRUTE_FORCE)[0]
    assert brute.occurrences == 327 and brute.rule_ids == ["failed_login_burst"]
    assert brute.detection_methods == ["rule", METHOD_ML] and len(brute.supporting_ml_detection_ids) == 1
    assert set(brute.related_finding_ids) == {f.finding_id for f in analysis.findings} - {brute.finding_id}


def test_web_sample_classification():
    analysis = analyze_sample("suspicious_web_access.log")
    got = {f.source_ip: f.category for f in analysis.findings}
    assert got == {"192.0.2.200": DOS_LIKE, "203.0.113.77": CREDENTIAL_ATTACK, "198.51.100.99": UNUSUAL_HTTP}


def test_csv_sample_classification():
    analysis = analyze_sample("sample_events.csv")
    assert {f.category for f in analysis.findings} == {BRUTE_FORCE, PORT_SCANNING}
    assert all(f.source_ip == "203.0.113.9" for f in analysis.findings)


# ================================================================ risk scores and severities
def test_expected_scores_for_the_ssh_attack():
    scores = {f.category: f.risk for f in analyze_sample("bruteforce_ssh_auth.log").findings}
    assert (scores[BRUTE_FORCE].score, scores[BRUTE_FORCE].severity) == (77, "CRITICAL")
    assert (scores[SUSPICIOUS_LOGIN].score, scores[SUSPICIOUS_LOGIN].severity) == (75, "CRITICAL")
    assert (scores[CREDENTIAL_ATTACK].score, scores[CREDENTIAL_ATTACK].severity) == (69, "HIGH")


def test_expected_severities_for_the_web_and_csv_samples():
    web = analyze_sample("suspicious_web_access.log")
    assert {f.risk.severity for f in web.findings} == {"HIGH"}
    assert web.risk_summary["overall_status"] == "suspicious"          # HIGH only -> not "critical"
    csv_analysis = analyze_sample("sample_events.csv")
    assert {f.risk.severity for f in csv_analysis.findings} == {"MEDIUM"}


def test_scores_are_the_sum_of_their_factors_and_within_limits():
    for name in ("bruteforce_ssh_auth.log", "suspicious_web_access.log", "sample_events.csv"):
        for finding in analyze_sample(name).findings:
            risk = finding.risk
            assert [f["name"] for f in risk.factors] == list(MAX_POINTS)
            assert risk.raw_score == sum(f["points"] for f in risk.factors)
            assert risk.score == min(risk.raw_score, 100) and 0 <= risk.score <= 100
            assert all(0 <= f["points"] <= f["max_points"] for f in risk.factors)
            assert risk.severity == severity_for(risk.score)
            assert risk.explanation.startswith(f"Risk {risk.score}/100 ({risk.severity})")
    assert sum(MAX_POINTS.values()) == 100


def test_findings_are_sorted_worst_first_with_sequential_ids():
    for name in ("bruteforce_ssh_auth.log", "suspicious_web_access.log"):
        findings = analyze_sample(name).findings
        scores = [f.risk.score for f in findings]
        assert scores == sorted(scores, reverse=True)
        assert [f.finding_id for f in findings] == [f"F-{i:03d}" for i in range(1, len(findings) + 1)]


def test_summary_counts_are_consistent():
    summary = analyze_sample("bruteforce_ssh_auth.log").risk_summary
    assert summary["overall_status"] == "critical" and summary["status_label"] == "CRITICAL SECURITY ISSUES DETECTED"
    assert summary["severity_counts"] == {"LOW": 0, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 2}
    assert sum(summary["severity_counts"].values()) == summary["total_findings"] == 3
    assert summary["highest_score"] == 77
    assert list(summary["category_counts"]) == sorted(summary["category_counts"], key=CATEGORIES.index)


# ================================================================ the score behaves sensibly
def _failed_logins(count, ip="9.9.9.9", user="bob"):
    return "\n".join(syslog(0, f"Failed password for {user} from {ip} port 22 ssh2", s % 60) for s in range(count))


def test_more_failures_means_a_higher_score():
    small = analyze(_failed_logins(12)).findings[0].risk.score
    medium = analyze(_failed_logins(60)).findings[0].risk.score
    # 59 per minute is the maximum a single minute can show with one line per second
    assert small < medium


def test_scoring_is_deterministic():
    first = [asdict(f) for f in analyze_sample("suspicious_web_access.log").findings]
    second = [asdict(f) for f in analyze_sample("suspicious_web_access.log").findings]
    assert first == second


def test_privileged_account_raises_the_score_target_factor():
    root = analyze(_failed_logins(30, user="root")).findings[0].risk
    bob = analyze(_failed_logins(30, user="bob")).findings[0].risk
    points = lambda risk: next(f["points"] for f in risk.factors if f["name"] == "Target importance")
    assert points(root) == 6 and points(bob) == 0
    assert root.score - bob.score == 6


def test_same_ip_wider_pattern_raises_attack_pattern_factor():
    attack = analyze_sample("bruteforce_ssh_auth.log").findings
    pattern_text = next(f["explanation"] for f in attack[0].risk.factors if f["name"] == "Attack pattern")
    assert pattern_text.startswith("Same IP also flagged for")          # "IP" keeps its capitals
    assert all(next(f["points"] for f in x.risk.factors if f["name"] == "Attack pattern") == 15 for x in attack)
    lone = analyze(_failed_logins(30)).findings
    assert len(lone) == 1 and next(f["points"] for f in lone[0].risk.factors if f["name"] == "Attack pattern") == 0


# ================================================================ confidence is honest
def test_confidence_levels():
    assert {f.confidence for f in analyze_sample("bruteforce_ssh_auth.log").findings} == {"high"}
    csv_findings = analyze_sample("sample_events.csv").findings          # barely over thresholds, no ML available
    assert {f.confidence for f in csv_findings} == {"low"}
    assert any("just over the line" in reason for f in csv_findings for reason in f.confidence_basis)
    brute = analyze_sample("bruteforce_ssh_auth.log").findings[0]
    assert any("Isolation Forest" in reason for reason in brute.confidence_basis)


# ================================================================ unknown anomalies are not forced into a category
def _distributed_spike_log():
    start = datetime(2026, 9, 22, 10, 0, 0)
    lines = [apache(start + timedelta(minutes=m, seconds=s), f"10.1.{m % 200}.{s + 1}") for m in range(60) for s in (0, 20)]
    lines += [apache(start + timedelta(minutes=30, seconds=s % 60), f"172.16.{s}.1") for s in range(60)]
    return "\n".join(lines)


def test_statistical_only_anomaly_becomes_unknown_anomaly_with_capped_risk():
    analysis = analyze(_distributed_spike_log())
    assert len(analysis.findings) == 1
    finding = analysis.findings[0]
    assert finding.category == UNKNOWN_ANOMALY and finding.detection_methods == [METHOD_ML] and finding.rule_ids == ["isolation_forest_window"]
    assert finding.confidence == "low" and "Statistical anomaly only" in finding.confidence_basis[0]
    assert finding.risk.severity in ("LOW", "MEDIUM") and finding.risk.score <= 49
    assert "cannot be determined" in finding.classification_basis
    assert analysis.risk_summary["overall_status"] == "suspicious"


def test_unknown_anomaly_is_capped_even_if_the_raw_score_is_higher():
    """On its own an ML-only finding cannot pass 38 raw points (no confidence/pattern points).
    The cap is the safety net for when it also shares an IP with another finding and hits privileged targets."""
    unknown = analyze(_distributed_spike_log()).findings[0]
    boosted = copy.deepcopy(unknown)
    boosted.source_ip, boosted.occurrences, boosted.strength = "1.2.3.4", 10_000, 50.0
    boosted.usernames, boosted.paths = ["root"], ["/admin"]
    sibling = copy.deepcopy(boosted)
    sibling.category = BRUTE_FORCE                      # another finding from the same IP -> attack-pattern points
    scored = {f.category: f for f in assess([boosted, sibling])}
    result = scored[UNKNOWN_ANOMALY].risk
    assert result.raw_score > 49 and result.score == 49 and result.severity == "MEDIUM"
    assert result.caps_applied and "statistical anomaly alone" in result.caps_applied[0]
    assert scored[BRUTE_FORCE].risk.caps_applied == []       # the cap only applies to the statistical-only finding


def test_the_isolation_forest_anomaly_score_never_changes_the_risk():
    """Anomaly score is a statistical outlier measure, NOT an attack probability."""
    finding = analyze(_distributed_spike_log()).findings[0]
    low, high = copy.deepcopy(finding), copy.deepcopy(finding)
    low.metrics["anomaly_score"], high.metrics["anomaly_score"] = 0.51, 0.99
    assert assess([low])[0].risk.score == assess([high])[0].risk.score


def test_network_wide_findings_stay_separate_from_ip_findings():
    start = datetime(2026, 9, 22, 10, 0, 0)
    lines = [apache(start + timedelta(seconds=i), f"10.0.0.{i + 1}", 503 if i < 12 else 200) for i in range(30)]
    findings = analyze("\n".join(lines)).findings
    assert len(findings) == 1 and findings[0].source_ip is None and findings[0].category == UNUSUAL_HTTP
    assert findings[0].related_finding_ids == []


def test_slow_brute_force_is_classified_as_brute_force():
    text = "\n".join(syslog(i * 5, "Failed password for admin from 9.9.9.9 port 22 ssh2") for i in range(25))
    finding = analyze(text).findings[0]
    assert finding.category == BRUTE_FORCE and finding.rule_ids == ["repeated_failed_logins"]


def test_two_episodes_from_the_same_ip_merge_into_one_finding():
    first = [syslog(0, "Failed password for bob from 9.9.9.9 port 22 ssh2", s) for s in range(15)]
    second = [syslog(120, "Failed password for bob from 9.9.9.9 port 22 ssh2", s) for s in range(15)]
    findings = analyze("\n".join(first + second)).findings
    assert len(findings) == 1
    assert findings[0].occurrences == 30 and len(findings[0].detection_ids) == 2
    assert findings[0].summary.startswith("2 separate episodes")


def test_strength_of_defaults_to_one_when_metrics_are_missing():
    detection = analyze_sample("bruteforce_ssh_auth.log").detection.detections[0]
    broken = copy.deepcopy(detection)
    broken.metrics = {}
    assert strength_of(broken) == 1.0


# ================================================================ evidence survives the whole pipeline
@pytest.mark.parametrize("name", ["bruteforce_ssh_auth.log", "suspicious_web_access.log"])
def test_finding_evidence_is_real_log_lines(name):
    lines = (SAMPLES / name).read_text(encoding="utf-8").split("\n")
    for finding in analyze_sample(name).findings:
        assert finding.evidence and finding.evidence_total >= len(finding.evidence)
        for item in finding.evidence:
            assert lines[item["line_no"] - 1].strip() == item["raw_line"]
            assert finding.source_ip in item["raw_line"]


def test_findings_serialize_to_json():
    json.dumps([asdict(f) for f in analyze_sample("bruteforce_ssh_auth.log").findings])


def test_thresholds_flow_through_the_pipeline():
    # With the burst rule effectively switched off, the slower "repeated failures" rule takes over:
    # still Brute Force, but explained by a different rule.
    strict = analyze_sample("bruteforce_ssh_auth.log", Thresholds(failed_login_burst_per_window=500))
    brute = by_category(strict, BRUTE_FORCE)[0]
    assert brute.rule_ids == ["repeated_failed_logins"]
    default = by_category(analyze_sample("bruteforce_ssh_auth.log"), BRUTE_FORCE)[0]
    assert default.rule_ids == ["failed_login_burst"]
    # Switch both off and nothing is classified as brute force.
    off = analyze_sample("bruteforce_ssh_auth.log", Thresholds(failed_login_burst_per_window=500, repeated_failed_logins_total=5000))
    assert not by_category(off, BRUTE_FORCE)

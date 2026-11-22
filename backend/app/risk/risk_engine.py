"""Module 6: risk engine.

Every finding gets a score from 0 to 100 that is the SUM of six factors. The maximums add up to
exactly 100, and each factor reports its own points and a one-line reason, so a score can always
be explained and is always reproducible.

  Factor                         Max   Question it answers
  -----------------------------  ---   ---------------------------------------------------------
  Type of activity                35   How dangerous is this kind of behaviour in itself?
  Number of occurrences           15   How many log records support it? (log scale)
  Intensity                       15   How far past the rule threshold was it? (log scale)
  Attack pattern                  15   Does the same IP show a wider pattern (e.g. failures, then a success)?
  Detection confidence            10   How well-supported is the finding? (see the classifier)
  Target importance               10   Were privileged accounts or sensitive URLs targeted? (if known)

Severity bands:  0-24 LOW | 25-49 MEDIUM | 50-74 HIGH | 75-100 CRITICAL.

Important: the Isolation Forest's anomaly score is NOT an input. It is a statistical outlier
measure, not a probability of attack, so it never feeds the risk score directly. A finding that
rests on statistics alone (Unknown Anomaly) is additionally capped at MEDIUM."""

from __future__ import annotations

import math

from app.classification.models import (
    BRUTE_FORCE, CATEGORIES, CREDENTIAL_ATTACK, DOS_LIKE, PORT_SCANNING, SEVERITIES, SUSPICIOUS_LOGIN, UNKNOWN_ANOMALY,
    UNUSUAL_HTTP, Finding, RiskAssessment,
)

MAX_POINTS = {"Type of activity": 35, "Number of occurrences": 15, "Intensity": 15,
              "Attack pattern": 15, "Detection confidence": 10, "Target importance": 10}

CATEGORY_BASE = {
    SUSPICIOUS_LOGIN: 35,       # a possibly successful intrusion is the most serious
    DOS_LIKE: 28,
    BRUTE_FORCE: 22,
    CREDENTIAL_ATTACK: 22,
    PORT_SCANNING: 12,          # reconnaissance: no harm done yet
    UNUSUAL_HTTP: 12,
    UNKNOWN_ANOMALY: 8,
}
CONFIDENCE_POINTS = {"high": 10, "medium": 5, "low": 0}
INTENSITY_CAP_RATIO = 20.0      # 20x the threshold already earns the maximum
STATISTICAL_ONLY_CAP = 49       # top of MEDIUM

PRIVILEGED_ACCOUNTS = {"root", "admin", "administrator", "sa"}
SENSITIVE_PATH_MARKERS = ("/admin", "/login", "/wp-login", "/.env", "/.git", "phpmyadmin", "/config", "/backup", "/console", "xmlrpc")

PATTERN_MULTI_CATEGORY = 7
PATTERN_SUCCESS_FOLLOWED_FAILURES = 8
TARGET_PRIVILEGED_ACCOUNT = 6
TARGET_SENSITIVE_URL = 6


def severity_for(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _sentence(parts: list[str]) -> str:
    """'a; b' -> 'A; b.'  (only the first letter is capitalized, so "IP" stays "IP")."""
    text = "; ".join(parts)
    return text[0].upper() + text[1:] + "."


def _factor(name: str, points: int, explanation: str) -> dict:
    return {"name": name, "points": int(points), "max_points": MAX_POINTS[name], "explanation": explanation}


def _occurrence_points(occurrences: int) -> tuple[int, str]:
    points = min(15, round(5 * math.log10(max(occurrences, 1))))
    return points, f"{occurrences} supporting log record(s) (log scale: 10 records = 5 points, 1,000 = 15)."


def _intensity_points(strength: float) -> tuple[int, str]:
    points = min(15, round(15 * math.log10(max(strength, 1.0)) / math.log10(INTENSITY_CAP_RATIO)))
    return points, f"{strength:.1f}x the rule threshold (log scale: {INTENSITY_CAP_RATIO:.0f}x the threshold = 15 points)."


def _pattern_points(finding: Finding, same_ip: list[Finding]) -> tuple[int, str]:
    points, reasons = 0, []
    categories = {f.category for f in same_ip if f is not finding} - {finding.category}
    if categories:
        points += PATTERN_MULTI_CATEGORY
        reasons.append("same IP also flagged for " + ", ".join(sorted(categories)))
    if any(f.category == SUSPICIOUS_LOGIN for f in same_ip):
        points += PATTERN_SUCCESS_FOLLOWED_FAILURES
        reasons.append("a successful login followed many failures from this IP (the guessing may have worked)")
    return min(points, MAX_POINTS["Attack pattern"]), (_sentence(reasons) if reasons else "No wider pattern from this IP.")


def _target_points(finding: Finding) -> tuple[int, str]:
    points, reasons = 0, []
    privileged = sorted({u for u in finding.usernames if u.lower() in PRIVILEGED_ACCOUNTS})
    if privileged:
        points += TARGET_PRIVILEGED_ACCOUNT
        reasons.append("privileged account(s) targeted: " + ", ".join(privileged))
    sensitive = [p for p in finding.paths if any(marker in p.lower() for marker in SENSITIVE_PATH_MARKERS)]
    if sensitive:
        points += TARGET_SENSITIVE_URL
        reasons.append("sensitive URL(s) targeted, e.g. " + ", ".join(sensitive[:3]))
    return min(points, MAX_POINTS["Target importance"]), (
        _sentence(reasons) if reasons else "No privileged account or sensitive URL identified (asset importance is otherwise unknown).")


def assess_finding(finding: Finding, same_ip: list[Finding]) -> RiskAssessment:
    occurrence_points, occurrence_reason = _occurrence_points(finding.occurrences)
    intensity_points, intensity_reason = _intensity_points(finding.strength)
    pattern_points, pattern_reason = _pattern_points(finding, same_ip)
    target_points, target_reason = _target_points(finding)
    factors = [
        _factor("Type of activity", CATEGORY_BASE[finding.category], f"{finding.category}."),
        _factor("Number of occurrences", occurrence_points, occurrence_reason),
        _factor("Intensity", intensity_points, intensity_reason),
        _factor("Attack pattern", pattern_points, pattern_reason),
        _factor("Detection confidence", CONFIDENCE_POINTS[finding.confidence], f"Confidence is {finding.confidence}."),
        _factor("Target importance", target_points, target_reason),
    ]
    raw = sum(f["points"] for f in factors)
    score, caps = min(raw, 100), []
    if finding.category == UNKNOWN_ANOMALY and score > STATISTICAL_ONLY_CAP:
        score = STATISTICAL_ONLY_CAP
        caps.append(f"Capped at {STATISTICAL_ONLY_CAP} (MEDIUM): the finding rests on a statistical anomaly alone.")
    severity = severity_for(score)
    top = sorted(factors, key=lambda f: f["points"], reverse=True)[:3]
    explanation = (f"Risk {score}/100 ({severity}). Largest contributors: "
                   + ", ".join(f"{f['name'].lower()} (+{f['points']})" for f in top if f["points"] > 0) + ".")
    return RiskAssessment(score=score, severity=severity, factors=factors, raw_score=raw, caps_applied=caps, explanation=explanation)


def assess(findings: list[Finding]) -> list[Finding]:
    """Score every finding, sort by risk (highest first) and number them F-001, F-002, ..."""
    for finding in findings:
        same_ip = [f for f in findings if finding.source_ip and f.source_ip == finding.source_ip]
        finding.risk = assess_finding(finding, same_ip)

    findings.sort(key=lambda f: (-f.risk.score, CATEGORIES.index(f.category), f.source_ip or "", f.start or ""))
    for number, finding in enumerate(findings, start=1):
        finding.finding_id = f"F-{number:03d}"
    for finding in findings:
        finding.related_finding_ids = [f.finding_id for f in findings
                                       if f is not finding and finding.source_ip and f.source_ip == finding.source_ip]
    return findings


def summarize(findings: list[Finding]) -> dict:
    """Headline risk numbers for the dashboard and report."""
    severity_counts = {severity: 0 for severity in SEVERITIES}
    category_counts: dict[str, int] = {}
    for finding in findings:
        severity_counts[finding.risk.severity] += 1
        category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
    if not findings:
        status, label = "clean", "CLEAN / NO ANOMALIES DETECTED"
    elif severity_counts["CRITICAL"]:
        status, label = "critical", "CRITICAL SECURITY ISSUES DETECTED"
    else:
        status, label = "suspicious", "SUSPICIOUS ACTIVITY DETECTED"
    return {
        "overall_status": status,
        "status_label": label,
        "total_findings": len(findings),
        "highest_score": max((f.risk.score for f in findings), default=0),
        "severity_counts": severity_counts,
        "category_counts": dict(sorted(category_counts.items(), key=lambda item: CATEGORIES.index(item[0]))),
    }

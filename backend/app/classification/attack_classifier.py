"""Module 5: attack classification.

Turns raw detections into FINDINGS with a category. The rules of this module:

  * The category comes from the EVIDENCE (which rule fired), never from a guess.
  * Several detections from the same IP and category are merged into one finding.
  * A statistical (Isolation Forest) detection that coincides with a rule finding is NOT a
    separate threat: it is recorded as corroboration of that finding.
  * A statistical detection that no rule explains becomes "Unknown Anomaly". We do not force
    it into an attack category.

Confidence is a transparent label (low / medium / high), not a probability. It is built from
points: how far the observation exceeds the rule threshold, whether the statistical model agrees,
and whether the same IP shows other suspicious behaviour."""

from __future__ import annotations

from app.classification.models import (
    BRUTE_FORCE, CREDENTIAL_ATTACK, DOS_LIKE, PORT_SCANNING, SUSPICIOUS_LOGIN, UNKNOWN_ANOMALY, UNUSUAL_HTTP, Finding,
)
from app.detection.models import METHOD_ML, METHOD_RULE, Detection

MAX_LIST = 10

RULE_CATEGORY = {
    "failed_login_burst": BRUTE_FORCE,
    "repeated_failed_logins": BRUTE_FORCE,
    "many_usernames_from_ip": CREDENTIAL_ATTACK,
    "success_after_failures": SUSPICIOUS_LOGIN,
    "ssh_probing": PORT_SCANNING,
    "port_scan_like": PORT_SCANNING,
    "http_request_flood": DOS_LIKE,
    "http_probing": UNUSUAL_HTTP,
    "http_auth_failures": CREDENTIAL_ATTACK,
    "http_server_error_spike": UNUSUAL_HTTP,
}

RULE_BASIS = {
    "failed_login_burst": "Many failed logins from a single IP in a short period match automated password guessing.",
    "repeated_failed_logins": "Many failed logins from one IP, spread over a long period, match slow password guessing.",
    "many_usernames_from_ip": "Failing against many different usernames from one IP matches credential guessing or password spraying.",
    "success_after_failures": ("A successful login from an IP that had just failed many times may mean guessed credentials, "
                               "or a user who mistyped repeatedly; the account needs review."),
    "ssh_probing": "Repeated connections that never complete the SSH handshake match scanners checking which services are exposed.",
    "port_scan_like": "Contacting many different ports in a short time matches port scanning.",
    "http_request_flood": "One IP sending far more requests than a normal client can strain the service (DoS-like behaviour).",
    "http_probing": "Mostly failing requests across many different URLs match probing for pages or vulnerabilities.",
    "http_auth_failures": "Repeated 401 responses mean repeated failed web authentication, matching credential guessing on a login page.",
    "http_server_error_spike": ("A sudden share of server errors means the service is failing; the cause (attack, bug or overload) "
                                "cannot be determined from the log alone."),
}
ML_BASIS = ("No detection rule matched this period, so it is reported as an unknown statistical anomaly. "
            "Its cause cannot be determined from the log alone.")


# observed value / threshold, per rule: "how many times over the line was it?"
_STRENGTH = {
    "failed_login_burst": lambda m: m["peak_failed_per_window"] / m["threshold_per_window"],
    "repeated_failed_logins": lambda m: m["failed_logins"] / m["threshold_total"],
    "many_usernames_from_ip": lambda m: m["distinct_failed_usernames"] / m["threshold_usernames"],
    "success_after_failures": lambda m: m["failures_before_first_success"] / m["threshold_failures"],
    "ssh_probing": lambda m: m["probe_events"] / m["threshold"],
    "port_scan_like": lambda m: m["peak_ports_per_window"] / m["threshold_ports"],
    "http_request_flood": lambda m: m["peak_requests_per_window"] / m["threshold_per_window"],
    "http_probing": lambda m: m["http_4xx"] / m["thresholds"]["min_4xx"],
    "http_auth_failures": lambda m: m["http_401"] / m["threshold"],
    "http_server_error_spike": lambda m: m["peak_5xx_rate"] / m["threshold_rate"],
}


def strength_of(detection: Detection) -> float:
    """How far past its threshold a detection is (1.0 = just reached it)."""
    try:
        if detection.method == METHOD_ML:
            top = detection.metrics["top_deviations"][0]["deviation"]
            return max(1.0, top / detection.metrics["min_deviation"])
        return max(1.0, float(_STRENGTH[detection.rule_id](detection.metrics)))
    except (KeyError, IndexError, ZeroDivisionError):
        return 1.0


def _unique(values: list[list[str]]) -> list[str]:
    seen: dict[str, None] = {}
    for group in values:
        for item in group:
            seen.setdefault(item, None)
    return list(seen)[:MAX_LIST]


def _build_finding(category: str, detections: list[Detection]) -> Finding:
    primary = max(detections, key=lambda d: d.occurrences)
    starts = [d.start for d in detections if d.start]
    ends = [d.end for d in detections if d.end]
    is_ml = primary.method == METHOD_ML
    summary = primary.description
    if len(detections) > 1:
        summary = f"{len(detections)} separate episodes; the largest: {summary}"
    return Finding(
        finding_id="",
        category=category,
        source_ip=primary.source_ip,
        start=min(starts) if starts else None,
        end=max(ends) if ends else None,
        occurrences=sum(d.occurrences for d in detections),
        summary=summary,
        classification_basis=ML_BASIS if is_ml else RULE_BASIS[primary.rule_id],
        detection_methods=[METHOD_ML] if is_ml else [METHOD_RULE],
        rule_ids=sorted({d.rule_id for d in detections}),
        detection_ids=[d.detection_id for d in detections],
        supporting_ml_detection_ids=[],
        strength=round(max(strength_of(d) for d in detections), 2),
        confidence="low",
        confidence_basis=[],
        services=_unique([d.services for d in detections]),
        hosts=_unique([d.hosts for d in detections]),
        usernames=_unique([d.usernames for d in detections]),
        paths=_unique([d.paths for d in detections]),
        destination_ips=_unique([d.destination_ips for d in detections]),
        destination_ports=sorted({p for d in detections for p in d.destination_ports})[:MAX_LIST],
        metrics=primary.metrics,
        evidence=primary.evidence,
        evidence_total=primary.evidence_total,
    )


def _corroborates(ml: Detection, rule: Detection) -> bool:
    """Does this statistical detection describe the same episode as a rule detection?
    Same IP, or the rule is network-wide (no IP). A surge spread over many IPs does not
    corroborate a single IP's finding."""
    if rule.detection_id not in ml.related_detection_ids:
        return False
    return rule.source_ip is None or (ml.source_ip is not None and ml.source_ip == rule.source_ip)


def _set_confidence(findings: list[Finding]) -> None:
    for finding in findings:
        others = [f for f in findings if f is not finding and finding.source_ip and f.source_ip == finding.source_ip]
        if finding.detection_methods == [METHOD_ML]:
            finding.confidence = "low"
            finding.confidence_basis = ["Statistical anomaly only: no detection rule matched, so no confirmation from a second signal."]
            continue
        points, reasons = 0, []
        if finding.strength >= 3:
            points += 2
            reasons.append(f"Observed value is {finding.strength:.1f}x the rule threshold (far above it).")
        elif finding.strength >= 1.5:
            points += 1
            reasons.append(f"Observed value is {finding.strength:.1f}x the rule threshold.")
        else:
            reasons.append(f"Observed value is only {finding.strength:.1f}x the rule threshold (just over the line).")
        if finding.supporting_ml_detection_ids:
            points += 1
            reasons.append("The statistical (Isolation Forest) analysis independently flagged the same period.")
        if others:
            points += 1
            reasons.append("The same IP also shows: " + ", ".join(sorted({f.category for f in others})) + ".")
        finding.confidence = "high" if points >= 3 else "medium" if points == 2 else "low"
        finding.confidence_basis = reasons


def classify(detections: list[Detection]) -> list[Finding]:
    """Group detections into categorized findings (not yet risk-scored or numbered)."""
    rule_detections = [d for d in detections if d.method == METHOD_RULE]
    ml_detections = [d for d in detections if d.method == METHOD_ML]

    groups: dict[tuple, list[Detection]] = {}
    for detection in rule_detections:
        category = RULE_CATEGORY[detection.rule_id]
        # Network-wide detections (no IP) stay separate; same IP + same category merge.
        key = (detection.source_ip, category) if detection.source_ip else (None, category, detection.detection_id)
        groups.setdefault(key, []).append(detection)

    built = [(_build_finding(key[1], dets), dets) for key, dets in groups.items()]
    findings = [finding for finding, _ in built]

    for ml in ml_detections:
        matched = [finding for finding, dets in built if any(_corroborates(ml, d) for d in dets)]
        if matched:
            for finding in matched:
                finding.supporting_ml_detection_ids.append(ml.detection_id)
                if METHOD_ML not in finding.detection_methods:
                    finding.detection_methods.append(METHOD_ML)
        else:
            findings.append(_build_finding(UNKNOWN_ANOMALY, [ml]))

    _set_confidence(findings)
    return findings

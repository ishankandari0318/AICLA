"""Renders a Report as a Markdown document (the downloadable report).

Log content is untrusted. Everything that comes from the log is placed in code spans or code
blocks, and backticks are removed from it first, so a log line cannot break out of its block and
inject Markdown (or links) into the document."""

from __future__ import annotations

from app.reporting.models import Report


def _code(text) -> str:
    """Inline code span: no backticks and no line breaks allowed inside."""
    return "`" + str(text).replace("`", "'").replace("\n", " ").replace("\r", " ") + "`"


def _block(lines: list[str]) -> list[str]:
    safe = [str(line).replace("`", "'").replace("\r", " ").replace("\n", " ") for line in lines]
    return ["```text", *safe, "```"]


def _bullets(items: list[str]) -> list[str]:
    return [f"- {item}" for item in items]


def _numbered(items: list[str]) -> list[str]:
    return [f"{i}. {item}" for i, item in enumerate(items, start=1)]


def render_markdown(report: Report) -> str:
    meta, overview = report.meta, report.overview
    out = ["# Security Log Analysis Report", "",
           f"**Status: {report.status.status_label}**", "", report.status.message, "", f"_{report.status.note}_", "",
           "## Analysis summary", "",
           f"- File: {_code(meta.filename)} ({meta.detected_format}, {meta.size_bytes:,} bytes)",
           f"- Analyzed: {meta.analyzed_at}",
           f"- Log entries processed: {overview.total_logs_processed:,}" + (f" ({overview.malformed_records:,} could not be parsed)" if overview.malformed_records else ""),
           f"- Time range: {meta.time_range['start']} to {meta.time_range['end']}" if meta.time_range else "- Time range: not available (no usable timestamps)",
           f"- Anomalies (findings): {overview.total_anomalies}",
           f"- Suspicious events (distinct log entries): {overview.suspicious_events:,}",
           f"- Critical: {overview.critical_alerts} | High: {overview.high_risk_events}"
           + (f" | Unique source IPs: {overview.unique_source_ips:,}" if overview.unique_source_ips is not None else ""), ""]
    out += ["### Severity distribution", ""] + [f"- {name}: {count}" for name, count in report.severity_distribution.items()] + [""]
    if report.category_distribution:
        out += ["### Attack categories", ""] + [f"- {name}: {count}" for name, count in report.category_distribution.items()] + [""]

    out += ["## Log activity", ""] + _bullets(report.activity_summary) + [""]

    if report.findings:
        out += ["## Findings", ""]
        for f in report.findings:
            out += [f"### {f.finding_id}: {f.threat_name} ({f.severity}, risk {f.risk_score}/100)", "",
                    f"**{f.priority}** Category: {f.category}. Confidence: {f.confidence}. Detection: {f.detection_method}.", "",
                    f"- Source IP: {_code(f.source_ip) if f.source_ip else 'not applicable'}",
                    f"- Period: {f.first_seen or 'unknown'} to {f.last_seen or 'unknown'}",
                    f"- Occurrences: {f.occurrences:,}"]
            if f.destination_ips or f.destination_ports:
                out.append(f"- Destination: {', '.join(_code(i) for i in f.destination_ips) or 'n/a'}"
                           + (f", ports {', '.join(_code(p) for p in f.destination_ports)}" if f.destination_ports else ""))
            if f.affected_services or f.affected_hosts:
                out.append("- Affected: " + ", ".join(_code(x) for x in [*f.affected_services, *f.affected_hosts]))
            if f.accounts_involved:
                out.append("- Accounts involved: " + ", ".join(_code(a) for a in f.accounts_involved))
            out += ["", "**What was observed**", "", f.description, "", "**Why this is suspicious**", "", f.why_suspicious, "",
                    "**Harmless explanations to rule out**", ""] + _bullets(f.possible_benign_explanations)
            out += ["", "**Possible impact**", ""] + _bullets(f.possible_impact)
            out += ["", "**Immediate mitigation**", ""] + _numbered(f.immediate_mitigation)
            out += ["", "**Recommended solutions**", ""] + _numbered(f.recommended_solutions)
            for commands in f.reference_commands:
                out += ["", f"_{commands.label}_ (reference only; this tool never runs it):", ""] + _block(commands.lines)
            out += ["", f"**Evidence** ({len(f.evidence)} of {f.evidence_total:,} supporting log lines)", ""]
            out += _block([f"{meta.line_label.lower()} {e.line_no}: {e.raw_line}" for e in f.evidence])
            out += ["", f"**Risk breakdown**: {f.risk_explanation}", ""]
            out += [f"- {factor['name']}: {factor['points']}/{factor['max_points']}: {factor['explanation']}" for factor in f.risk_factors]
            out += [""]
        out += ["## Recommended remediation (in priority order)", ""]
        for item in report.remediation_summary:
            out.append(f"{item.priority}. **{item.finding_id} {item.threat_name}** ({item.severity})")
            out += [f"   - {action}" for action in item.actions]
        out.append("")
    out += ["## Analysis details", ""]
    for rule in report.analysis_details["rules"]:
        out.append(f"- {rule['title']}: " + (f"{rule['findings']} finding(s)" if rule["ran"] else f"not applicable. {rule['skipped_reason']}"))
    ml = report.analysis_details["machine_learning"]
    out += [f"- Machine learning (Isolation Forest): " + (f"ran on {ml['windows_analyzed']} active time windows" if ml["ran"] else f"not run. {ml['reason']}"), "",
            "---", "", f"_{report.disclaimer}_", ""]
    return "\n".join(out)

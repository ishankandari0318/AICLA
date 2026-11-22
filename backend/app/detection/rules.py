"""Rule-based detection: known suspicious patterns, each with an explicit threshold.

A rule only describes what was OBSERVED ("327 failed logins from X in 4 minutes").
It does not say "attack confirmed" - naming the category and judging severity is the job of
the classification and risk modules in the next stages.

Each rule lists the `requires` capabilities it needs (see FeatureSet.capabilities); the
orchestrator skips a rule whose information is missing from the uploaded log."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterator

import numpy as np
import pandas as pd

from app.detection.common import Context, merge_windows, span
from app.detection.models import Detection

SSH_PROBE_EVENTS = {"no_identification", "protocol_error", "negotiation_failed"}


# ------------------------------------------------------------------ shared building block
def _window_incidents(ctx: Context, hits: pd.DataFrame, extend_with: str | None = None) -> Iterator[tuple]:
    """Turn per-(IP, window) rows that crossed a threshold into incidents: one per IP per run of
    consecutive windows. Yields (ip, start, end_exclusive, hit_rows).

    `extend_with` names a column: when given, neighbouring windows of the same IP that show ANY
    activity in that column are folded into the incident, so it covers the whole episode and not
    only the loudest minutes."""
    for ip, hit_rows in hits.groupby("source_ip"):
        if extend_with:
            all_windows = ctx.windows_for_ip(ip)
            pool = all_windows.loc[all_windows[extend_with] > 0, "window"]
        else:
            pool = hit_rows["window"]
        for start, end in merge_windows(pool, ctx.window_seconds):
            inside = hit_rows[(hit_rows["window"] >= start) & (hit_rows["window"] < end)]
            if not inside.empty:
                yield ip, start, end, inside


def _is_http(rows: pd.DataFrame) -> pd.Series:
    return rows["status_code"].notna() | rows["http_method"].notna()


def _status_between(low: int, high: int) -> Callable[[pd.DataFrame], pd.Series]:
    return lambda rows: rows["status_code"].between(low, high).fillna(False).astype(bool)


# ------------------------------------------------------------------ authentication rules
def failed_login_burst(ctx: Context) -> list[Detection]:
    """Many failed logins from one IP inside a single window (brute-force-like speed)."""
    t, windows = ctx.t, ctx.features.ip_window_features
    hits = windows[windows["failed_logins"] >= t.failed_login_burst_per_window]
    found = []
    for ip, start, end, inside in _window_incidents(ctx, hits, extend_with="failed_logins"):
        rows = ctx.rows_in_range(ip, start, end, lambda r: r["event"] == "failed_login")
        first, last = span(rows)
        peak = int(inside["failed_logins"].max())
        found.append(ctx.make_detection(
            rule_id="failed_login_burst", source_ip=ip, rows=rows,
            description=(f"{len(rows)} failed logins from {ip} between {first} and {last}, peaking at {peak} "
                         f"within one {ctx.window_seconds}-second window (rule threshold: {t.failed_login_burst_per_window})."),
            metrics={"peak_failed_per_window": peak, "threshold_per_window": t.failed_login_burst_per_window,
                     "window_seconds": ctx.window_seconds, "distinct_usernames": int(rows["username"].nunique())},
        ))
    return found


def repeated_failed_logins(ctx: Context) -> list[Detection]:
    """Slow-and-low: lots of failures from one IP spread over a long time (not already caught as a burst)."""
    t, summary = ctx.t, ctx.features.ip_summary
    already = {d.source_ip for d in ctx.found.get("failed_login_burst", [])}
    found = []
    for row in summary[summary["failed_logins"] >= t.repeated_failed_logins_total].itertuples():
        if row.source_ip in already:
            continue
        rows = ctx.rows_for_ip(row.source_ip)
        rows = rows[rows["event"] == "failed_login"]
        first, last = span(rows)
        found.append(ctx.make_detection(
            rule_id="repeated_failed_logins", source_ip=row.source_ip, rows=rows,
            description=(f"{len(rows)} failed logins from {row.source_ip}"
                         + (f" between {first} and {last}" if first else "")
                         + f" (rule threshold: {t.repeated_failed_logins_total}), at a rate below the burst threshold."),
            metrics={"failed_logins": int(row.failed_logins), "threshold_total": t.repeated_failed_logins_total,
                     "peak_failed_per_window": int(row.peak_failed_logins_per_window)},
        ))
    return found


def many_usernames_from_ip(ctx: Context) -> list[Detection]:
    """One IP failing against many different usernames (guessing or spraying accounts)."""
    t, summary = ctx.t, ctx.features.ip_summary
    hits = summary[(summary["unique_failed_usernames"] >= t.failed_usernames_per_ip)
                   & (summary["failed_logins"] >= t.failed_usernames_per_ip)]
    found = []
    for row in hits.itertuples():
        rows = ctx.rows_for_ip(row.source_ip)
        rows = rows[rows["event"] == "failed_login"]
        found.append(ctx.make_detection(
            rule_id="many_usernames_from_ip", source_ip=row.source_ip, rows=rows,
            description=(f"{row.source_ip} failed to log in as {row.unique_failed_usernames} different usernames "
                         f"({row.failed_logins} failed attempts; rule threshold: {t.failed_usernames_per_ip} usernames)."),
            metrics={"distinct_failed_usernames": int(row.unique_failed_usernames),
                     "failed_logins": int(row.failed_logins), "threshold_usernames": t.failed_usernames_per_ip},
        ))
    return found


def success_after_failures(ctx: Context) -> list[Detection]:
    """A successful login from an IP that had just failed many times (possible guessed credentials)."""
    t, summary = ctx.t, ctx.features.ip_summary
    candidates = summary[(summary["failed_logins"] >= t.success_after_failures_min) & (summary["successful_logins"] >= 1)]
    lookback = np.timedelta64(t.success_lookback_seconds, "s")
    found = []
    for ip in candidates["source_ip"]:
        rows = ctx.rows_for_ip(ip).dropna(subset=["timestamp"]).sort_values("timestamp", kind="stable")
        failed, success = rows[rows["event"] == "failed_login"], rows[rows["event"] == "successful_login"]
        if failed.empty or success.empty:
            continue
        failed_times, success_times = failed["timestamp"].to_numpy(), success["timestamp"].to_numpy()
        # For each success: how many failures from this IP happened in the preceding lookback period?
        preceding = (np.searchsorted(failed_times, success_times, side="left")
                     - np.searchsorted(failed_times, success_times - lookback, side="left"))
        keep = preceding >= t.success_after_failures_min
        if not keep.any():
            continue
        flagged = success[keep]
        first_success_time = flagged["timestamp"].iloc[0]
        prior_failures = failed[failed["timestamp"] < first_success_time].tail(2)
        proof = pd.concat([prior_failures, flagged.head(3)])
        accounts = [str(u) for u in flagged["username"].dropna().unique()]
        found.append(ctx.make_detection(
            rule_id="success_after_failures", source_ip=ip, rows=proof, occurrences=len(flagged), usernames=accounts,
            record_rows=pd.concat([prior_failures, flagged]),
            description=(f"{len(flagged)} successful login(s) from {ip}"
                         + (f" as {', '.join(accounts[:3])}" if accounts else "")
                         + f", the first at {first_success_time:%Y-%m-%d %H:%M:%S}, after {int(preceding[keep][0])} failed logins "
                           f"from the same IP in the previous {t.success_lookback_seconds // 60} minutes."),
            metrics={"failures_before_first_success": int(preceding[keep][0]),
                     "first_success_at": f"{first_success_time:%Y-%m-%d %H:%M:%S}",
                     "lookback_seconds": t.success_lookback_seconds, "threshold_failures": t.success_after_failures_min},
        ))
    return found


def ssh_probing(ctx: Context) -> list[Detection]:
    """Connections that never complete a normal SSH handshake (typical of scanners and bots)."""
    t = ctx.t
    probes = ctx.records[ctx.records["event"].isin(SSH_PROBE_EVENTS)].dropna(subset=["source_ip"])
    found = []
    for ip, rows in probes.groupby("source_ip"):
        if len(rows) < t.ssh_probe_events:
            continue
        first, last = span(rows)
        found.append(ctx.make_detection(
            rule_id="ssh_probing", source_ip=ip, rows=rows,
            description=(f"{len(rows)} connections from {ip} that failed the SSH handshake (no identification string, "
                         f"protocol error or negotiation failure)"
                         + (f" between {first} and {last}" if first else "") + f" (rule threshold: {t.ssh_probe_events})."),
            metrics={"probe_events": len(rows), "threshold": t.ssh_probe_events},
        ))
    return found


# ------------------------------------------------------------------ network rule
def port_scan_like(ctx: Context) -> list[Detection]:
    """One IP touching many different destination ports in a short time."""
    t, windows = ctx.t, ctx.features.ip_window_features
    hits = windows[windows["unique_dest_ports"] >= t.port_scan_ports_per_window]
    found = []
    for ip, start, end, inside in _window_incidents(ctx, hits):
        rows = ctx.rows_in_range(ip, start, end, lambda r: r["destination_port"].notna())
        first, last = span(rows)
        peak = int(inside["unique_dest_ports"].max())
        found.append(ctx.make_detection(
            rule_id="port_scan_like", source_ip=ip, rows=rows,
            description=(f"{ip} contacted {peak} different destination ports within one {ctx.window_seconds}-second "
                         f"window ({len(rows)} connections between {first} and {last}; rule threshold: {t.port_scan_ports_per_window})."),
            metrics={"peak_ports_per_window": peak, "distinct_ports_total": int(rows["destination_port"].nunique()),
                     "distinct_destination_ips": int(rows["destination_ip"].nunique()),
                     "threshold_ports": t.port_scan_ports_per_window, "window_seconds": ctx.window_seconds},
        ))
    return found


# ------------------------------------------------------------------ HTTP rules
def http_request_flood(ctx: Context) -> list[Detection]:
    """Far more requests from one IP than a single user normally makes."""
    t, windows = ctx.t, ctx.features.ip_window_features
    hits = windows[windows["http_requests"] >= t.http_flood_requests_per_window]
    found = []
    for ip, start, end, inside in _window_incidents(ctx, hits):
        rows = ctx.rows_in_range(ip, start, end, _is_http)
        first, last = span(rows)
        peak = int(inside["http_requests"].max())
        found.append(ctx.make_detection(
            rule_id="http_request_flood", source_ip=ip, rows=rows,
            description=(f"{len(rows)} HTTP requests from {ip} between {first} and {last}, peaking at {peak} in one "
                         f"{ctx.window_seconds}-second window (rule threshold: {t.http_flood_requests_per_window})."),
            metrics={"peak_requests_per_window": peak, "requests_per_second_at_peak": round(peak / ctx.window_seconds, 1),
                     "threshold_per_window": t.http_flood_requests_per_window, "window_seconds": ctx.window_seconds},
        ))
    return found


def http_probing(ctx: Context) -> list[Detection]:
    """An IP whose requests mostly fail (4xx) across many different URLs: looks like probing for pages."""
    t, summary = ctx.t, ctx.features.ip_summary
    rate = summary["http_4xx"] / summary["http_requests"].where(summary["http_requests"] > 0)
    hits = summary[(summary["http_4xx"] >= t.http_probe_min_4xx) & (rate >= t.http_probe_min_4xx_rate)
                   & (summary["unique_paths"] >= t.http_probe_min_paths)]
    found = []
    for row in hits.itertuples():
        rows = ctx.rows_for_ip(row.source_ip)
        rows = rows[_status_between(400, 499)(rows)]
        agents = [str(a) for a in rows["user_agent"].dropna().unique()[:3]]
        found.append(ctx.make_detection(
            rule_id="http_probing", source_ip=row.source_ip, rows=rows,
            description=(f"{row.http_4xx} of {row.http_requests} requests from {row.source_ip} "
                         f"({row.http_4xx / row.http_requests:.0%}) returned client errors across {row.unique_paths} different URLs."),
            metrics={"http_4xx": int(row.http_4xx), "http_requests": int(row.http_requests), "distinct_urls": int(row.unique_paths),
                     "user_agents": agents, "thresholds": {"min_4xx": t.http_probe_min_4xx, "min_rate": t.http_probe_min_4xx_rate,
                                                           "min_urls": t.http_probe_min_paths}},
        ))
    return found


def http_auth_failures(ctx: Context) -> list[Detection]:
    """Repeated HTTP 401 (unauthorized) responses to one IP: failed web logins."""
    t, summary = ctx.t, ctx.features.ip_summary
    found = []
    for row in summary[summary["http_401"] >= t.http_401_total].itertuples():
        rows = ctx.rows_for_ip(row.source_ip)
        rows = rows[rows["status_code"] == 401]
        first, last = span(rows)
        found.append(ctx.make_detection(
            rule_id="http_auth_failures", source_ip=row.source_ip, rows=rows,
            description=(f"{len(rows)} HTTP 401 responses to {row.source_ip}"
                         + (f" between {first} and {last}" if first else "")
                         + f", targeting {rows['http_path'].nunique()} URL(s) (rule threshold: {t.http_401_total})."),
            metrics={"http_401": len(rows), "threshold": t.http_401_total, "distinct_urls": int(rows["http_path"].nunique()),
                     "peak_per_window": int(ctx.windows_for_ip(row.source_ip)["http_401"].max())},
        ))
    return found


def http_server_error_spike(ctx: Context) -> list[Detection]:
    """A window in which a large share of ALL requests failed with 5xx (the service itself is struggling)."""
    t, windows = ctx.t, ctx.features.window_features
    hits = windows[(windows["http_requests"] >= t.http_5xx_min_requests) & (windows["http_5xx_rate"] >= t.http_5xx_rate)]
    found = []
    for start, end in merge_windows(hits["window"], ctx.window_seconds):
        rows = ctx.rows_in_range(None, start, end, _status_between(500, 599))
        inside = hits[(hits["window"] >= start) & (hits["window"] < end)]
        total_requests = int(inside["http_requests"].sum())
        first, last = span(rows)
        found.append(ctx.make_detection(
            rule_id="http_server_error_spike", source_ip=None, rows=rows,
            description=(f"{len(rows)} of {total_requests} requests ({len(rows) / total_requests:.0%}) returned server errors "
                         f"(5xx) between {first} and {last} (rule threshold: {t.http_5xx_rate:.0%} of at least "
                         f"{t.http_5xx_min_requests} requests per window)."),
            metrics={"http_5xx": len(rows), "http_requests": total_requests,
                     "peak_5xx_rate": round(float(inside["http_5xx_rate"].max()), 3), "threshold_rate": t.http_5xx_rate},
        ))
    return found


# ------------------------------------------------------------------ registry
@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    requires: tuple[str, ...]
    run: Callable[[Context], list[Detection]]


RULES = [
    Rule("failed_login_burst", "Burst of failed logins from one IP", ("has_auth_events", "has_source_ips", "has_timestamps"), failed_login_burst),
    Rule("repeated_failed_logins", "Many failed logins from one IP over time", ("has_auth_events", "has_source_ips"), repeated_failed_logins),
    Rule("many_usernames_from_ip", "One IP failing against many usernames", ("has_auth_events", "has_source_ips", "has_usernames"), many_usernames_from_ip),
    Rule("success_after_failures", "Successful login after many failures", ("has_auth_events", "has_source_ips", "has_timestamps"), success_after_failures),
    Rule("ssh_probing", "Connections that fail the SSH handshake", ("has_source_ips",), ssh_probing),
    Rule("port_scan_like", "One IP touching many destination ports", ("has_destination_ports", "has_source_ips", "has_timestamps"), port_scan_like),
    Rule("http_request_flood", "Excessive HTTP requests from one IP", ("has_http", "has_source_ips", "has_timestamps"), http_request_flood),
    Rule("http_probing", "Mostly-failing requests across many URLs", ("has_http", "has_source_ips"), http_probing),
    Rule("http_auth_failures", "Repeated HTTP 401 responses", ("has_http", "has_source_ips"), http_auth_failures),
    Rule("http_server_error_spike", "Spike in HTTP 5xx server errors", ("has_http", "has_timestamps"), http_server_error_spike),
]

REQUIREMENT_TEXT = {
    "has_auth_events": "login (authentication) events",
    "has_source_ips": "source IP addresses",
    "has_timestamps": "usable timestamps",
    "has_usernames": "usernames",
    "has_http": "HTTP request data",
    "has_destination_ports": "destination ports",
}

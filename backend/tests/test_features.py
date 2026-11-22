from datetime import datetime
from pathlib import Path

import pandas as pd
import pytest

from app.features.feature_engineering import (
    IP_SUMMARY_COLUMNS, IP_WINDOW_FEATURE_COLUMNS, WINDOW_FEATURE_COLUMNS,
    extract_features, pick_window_seconds,
)
from app.ingestion.log_reader import read_upload
from app.parsing.log_parser import parse_log
from app.parsing.schema import to_frame

REF = datetime(2026, 11, 2)
SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"


def features_of(text, name="x.log", **kwargs):
    return extract_features(parse_log(read_upload(name, text.encode()), REF).records, **kwargs)


def sample_features(name):
    return extract_features(parse_log(read_upload(name, (SAMPLES / name).read_bytes()), REF).records)


# Hand-built log: every expected number below can be checked by eye.
#   window 10:00 -> 4 events: 3 failed logins from 1.1.1.1 (users a, b, a) + 1 success from 2.2.2.2
#   window 10:01 -> nothing happens (must still appear, with zeros)
#   window 10:02 -> 1 failed login from 1.1.1.1
AUTH = """\
Sep 22 10:00:00 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2
Sep 22 10:00:10 h sshd[1]: Failed password for b from 1.1.1.1 port 2 ssh2
Sep 22 10:00:20 h sshd[1]: Failed password for a from 1.1.1.1 port 3 ssh2
Sep 22 10:00:50 h sshd[1]: Accepted password for c from 2.2.2.2 port 4 ssh2
Sep 22 10:02:05 h sshd[1]: Failed password for a from 1.1.1.1 port 5 ssh2
"""


def test_window_features_match_hand_calculation():
    w = features_of(AUTH).window_features
    assert list(w.columns) == ["window"] + WINDOW_FEATURE_COLUMNS
    assert list(w["window"]) == list(pd.date_range("2026-09-22 10:00", periods=3, freq="60s"))
    first, quiet, last = (w.iloc[i] for i in range(3))
    assert (first["events"], first["failed_logins"], first["successful_logins"]) == (4, 3, 1)
    assert first["failed_login_ratio"] == pytest.approx(0.75)
    assert (first["unique_source_ips"], first["unique_usernames"], first["max_events_per_ip"]) == (2, 3, 3)
    assert first["mean_gap_seconds"] == pytest.approx((10 + 10 + 30) / 3)      # gaps inside the window (first event has none)
    assert (quiet["events"], quiet["failed_logins"], quiet["failed_login_ratio"]) == (0, 0, 0.0)
    assert quiet["mean_gap_seconds"] == 60                                     # no events -> one full window
    assert (last["events"], last["failed_logins"], last["failed_login_ratio"]) == (1, 1, 1.0)


def test_ip_window_features_match_hand_calculation():
    ip = features_of(AUTH).ip_window_features
    assert list(ip.columns) == ["window", "source_ip"] + IP_WINDOW_FEATURE_COLUMNS
    row = ip[(ip["source_ip"] == "1.1.1.1") & (ip["window"] == pd.Timestamp("2026-09-22 10:00"))].iloc[0]
    assert (row["events"], row["failed_logins"], row["unique_usernames"]) == (3, 3, 2)
    assert row["failed_login_ratio"] == 1.0
    assert row["min_gap_seconds"] == 10 and row["mean_gap_seconds"] == pytest.approx(10.0)
    other = ip[ip["source_ip"] == "2.2.2.2"].iloc[0]
    assert (other["events"], other["successful_logins"], other["failed_login_ratio"]) == (1, 1, 0.0)
    assert (other["unique_usernames"], other["unique_failed_usernames"]) == (1, 0)   # logged in fine, never failed
    assert other["min_gap_seconds"] == 60                                      # first event from this IP


def test_ip_summary_uses_raw_records_for_uniques_and_windows_for_peaks():
    s = features_of(AUTH).ip_summary
    assert list(s.columns) == IP_SUMMARY_COLUMNS
    top = s.iloc[0]
    assert top["source_ip"] == "1.1.1.1" and top["events"] == 4 and top["failed_logins"] == 4
    assert top["unique_usernames"] == 2                       # a, b - not 2+1 summed across windows
    assert top["unique_failed_usernames"] == 2                # only usernames that FAILED
    assert top["peak_events_per_window"] == 3 and top["peak_failed_logins_per_window"] == 3
    assert top["peak_window"] == pd.Timestamp("2026-09-22 10:00")
    assert top["first_seen"] == pd.Timestamp("2026-09-22 10:00:00") and top["last_seen"] == pd.Timestamp("2026-09-22 10:02:05")


def test_summary_and_capabilities_for_auth_log():
    f = features_of(AUTH)
    s = f.summary
    assert (s["total_records"], s["failed_logins"], s["successful_logins"]) == (5, 4, 1)
    assert s["failed_login_ratio"] == pytest.approx(0.8)
    assert (s["unique_source_ips"], s["unique_usernames"]) == (2, 3)
    assert (s["start"], s["end"], s["duration_seconds"]) == ("2026-09-22 10:00:00", "2026-09-22 10:02:05", 125.0)
    assert s["http_requests"] == 0 and s["http_4xx_rate"] is None
    assert s["event_counts"] == {"failed_login": 4, "successful_login": 1}
    assert s["top_source_ips"][0] == {"source_ip": "1.1.1.1", "events": 4}
    assert f.capabilities == {"has_timestamps": True, "has_source_ips": True, "has_auth_events": True,
                              "has_http": False, "has_destination_ports": False, "has_usernames": True}


WEB = """\
1.1.1.1 - - [22/Sep/2026:10:00:01 +0000] "GET /a HTTP/1.1" 200 10 "-" "ua"
1.1.1.1 - - [22/Sep/2026:10:00:02 +0000] "GET /b HTTP/1.1" 404 10 "-" "ua"
1.1.1.1 - - [22/Sep/2026:10:00:03 +0000] "GET /c HTTP/1.1" 404 10 "-" "ua"
2.2.2.2 - - [22/Sep/2026:10:00:04 +0000] "POST /login HTTP/1.1" 401 10 "-" "ua"
2.2.2.2 - - [22/Sep/2026:10:00:05 +0000] "GET /a HTTP/1.1" 500 10 "-" "ua"
"""


def test_http_features_and_capabilities():
    f = features_of(WEB)
    w = f.window_features.iloc[0]
    assert (w["http_requests"], w["http_4xx"], w["http_5xx"]) == (5, 3, 1)
    assert w["http_4xx_rate"] == pytest.approx(0.6) and w["http_5xx_rate"] == pytest.approx(0.2)
    one = f.ip_summary.set_index("source_ip").loc["1.1.1.1"]
    assert (one["http_4xx"], one["unique_paths"], one["http_401"]) == (2, 3, 0)
    assert f.ip_summary.set_index("source_ip").loc["2.2.2.2", "http_401"] == 1
    assert f.capabilities["has_http"] and not f.capabilities["has_auth_events"]
    assert f.summary["http_4xx_rate"] == pytest.approx(0.6)


def test_destination_ports_are_counted_per_ip():
    csv = ("time,src_ip,dst_ip,dst_port\n" +
           "".join(f"2026-09-22 10:00:{i:02d},9.9.9.9,10.0.0.1,{p}\n" for i, p in enumerate([22, 23, 80, 22, 443])))
    f = features_of(csv, "a.csv")
    assert f.ip_summary.iloc[0]["unique_dest_ports"] == 4
    assert f.window_features.iloc[0]["unique_dest_ports"] == 4
    assert f.capabilities["has_destination_ports"] and f.summary["unique_destination_ips"] == 1


def test_log_without_timestamps_still_gets_a_summary_but_no_time_features():
    f = features_of("src_ip,user,action\n1.1.1.1,a,login_failed\n1.1.1.1,b,login_failed\n2.2.2.2,c,login_success\n", "a.csv")
    assert f.window_features.empty and f.ip_window_features.empty
    assert f.summary["total_records"] == 3 and f.summary["failed_logins"] == 2
    assert f.summary["start"] is None and f.summary["duration_seconds"] is None
    assert not f.capabilities["has_timestamps"]
    assert f.ip_summary.iloc[0]["events"] == 2 and f.ip_summary.iloc[0]["peak_events_per_window"] == 0


def test_empty_input_does_not_crash():
    f = extract_features(to_frame([]))
    assert f.summary["total_records"] == 0 and f.window_features.empty and f.ip_summary.empty
    assert not any(f.capabilities.values())


def test_window_size_can_be_changed_and_coarsens_for_very_long_logs():
    f = features_of(AUTH, window_seconds=300)
    assert f.window_seconds == 300 and len(f.window_features) == 1 and f.window_features.iloc[0]["events"] == 5
    assert pick_window_seconds(3600) == 60
    assert pick_window_seconds(40 * 86400) == 300
    assert pick_window_seconds(3 * 365 * 86400) > 300
    with pytest.raises(ValueError):
        pick_window_seconds(100, 0)


def test_no_events_are_lost_or_duplicated():
    for name in ("bruteforce_ssh_auth.log", "suspicious_web_access.log", "sample_events.csv"):
        parsed = parse_log(read_upload(name, (SAMPLES / name).read_bytes()), REF).records
        f = extract_features(parsed)
        assert f.window_features["events"].sum() == parsed["timestamp"].notna().sum()
        with_ip = parsed.dropna(subset=["timestamp", "source_ip"])
        assert f.ip_window_features["events"].sum() == len(with_ip)
        assert f.ip_summary["events"].sum() == parsed["source_ip"].notna().sum()
        numeric = f.window_features[WINDOW_FEATURE_COLUMNS]
        assert not numeric.isna().any().any()                 # ML-ready: no missing values


# ---------------------------------------------------------------- the real sample files
def test_bruteforce_sample_attacker_stands_out():
    f = sample_features("bruteforce_ssh_auth.log")
    top = f.ip_summary.iloc[0]
    assert top["source_ip"] == "203.0.113.50" and top["failed_logins"] == 327
    assert top["peak_failed_logins_per_window"] >= 70
    assert f.ip_window_features.query("source_ip == '203.0.113.50' and failed_logins > 0")["window"].nunique() <= 5
    others = f.ip_summary.iloc[1:]
    assert others["peak_failed_logins_per_window"].max() <= 3
    assert f.capabilities["has_auth_events"] and not f.capabilities["has_http"]


def test_normal_ssh_sample_has_no_standout_ip():
    f = sample_features("normal_ssh_auth.log")
    assert f.ip_summary["peak_failed_logins_per_window"].max() <= 2
    assert f.ip_summary["unique_usernames"].max() <= 1
    assert f.window_features["max_events_per_ip"].max() <= 3


def test_suspicious_web_sample_shows_scanner_guesser_and_flood():
    s = sample_features("suspicious_web_access.log").ip_summary.set_index("source_ip")
    assert s.loc["198.51.100.99", "events"] == 250 and s.loc["198.51.100.99", "http_4xx"] >= 200
    assert s.loc["198.51.100.99", "unique_paths"] == 12
    assert s.loc["203.0.113.77", "http_401"] == 120
    assert s.loc["192.0.2.200", "peak_events_per_window"] == 900
    normal = s.drop(["198.51.100.99", "203.0.113.77", "192.0.2.200"])
    assert normal["peak_events_per_window"].max() <= 5 and normal["http_401"].max() == 0


def test_normal_web_sample_has_low_error_rates():
    f = sample_features("normal_web_access.log")
    assert f.summary["http_4xx_rate"] < 0.1 and f.summary["http_5xx_rate"] < 0.05
    assert f.ip_summary["peak_events_per_window"].max() <= 3

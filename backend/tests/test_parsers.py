from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pytest

from app.errors import LogAnalysisError
from app.ingestion.log_reader import read_upload
from app.parsing.log_parser import parse_log

REF = datetime(2026, 11, 2)  # fixed "now" so syslog year inference is deterministic
SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"


def parse(text, name="x.log", ref=REF):
    return parse_log(read_upload(name, text.encode("utf-8")), reference_time=ref)


def sample(name):
    return parse_log(read_upload(name, (SAMPLES / name).read_bytes()), reference_time=REF)


# ---------------------------------------------------------------- syslog
def test_spec_example_line():
    result = parse("Sep 22 10:31:21 server sshd[1234]: Failed password for admin from 192.168.1.50")
    row = result.records.iloc[0]
    assert row["timestamp"] == pd.Timestamp("2026-09-22 10:31:21")
    assert (row["host"], row["service"], row["event"]) == ("server", "sshd", "failed_login")
    assert (row["username"], row["source_ip"], row["auth_status"]) == ("admin", "192.168.1.50", "failure")


def test_ssh_message_variants():
    text = "\n".join([
        "Sep 22 10:00:00 h sshd[1]: Failed password for invalid user oracle from 203.0.113.5 port 4444 ssh2",
        "Sep 22 10:00:01 h sshd[1]: Accepted publickey for deploy from 10.0.0.5 port 5555 ssh2: RSA SHA256:abc",
        "Sep 22 10:00:02 h sshd[1]: Invalid user test from 203.0.113.5 port 4445",
        "Sep 22 10:00:03 h sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5  user=root",
        "Sep 22 10:00:04 h sshd[1]: Connection closed by authenticating user root 203.0.113.5 port 4446 [preauth]",
        "Sep 22 10:00:05 h sshd[1]: Did not receive identification string from 203.0.113.9 port 1234",
        "Sep 22 10:00:06 h sudo[2]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls",
    ])
    df = parse(text).records
    assert list(df["event"]) == ["failed_login", "successful_login", "invalid_user", "pam_auth_failure",
                                 "connection_closed", "no_identification", "sudo_command"]
    assert df.loc[0, "username"] == "oracle" and df.loc[0, "source_port"] == 4444
    assert df.loc[1, "auth_status"] == "success" and df.loc[1, "username"] == "deploy"
    assert df.loc[3, "source_ip"] == "203.0.113.5" and df.loc[3, "username"] == "root"
    assert df.loc[5, "source_ip"] == "203.0.113.9"
    assert df.loc[6, "username"] == "alice"


def test_year_inference_across_new_year():
    text = ("Dec 31 23:59:58 h sshd[1]: Failed password for a from 1.2.3.4\n"
            "Jan  1 00:00:02 h sshd[1]: Failed password for a from 1.2.3.4\n")
    df = parse(text, ref=datetime(2026, 1, 15)).records
    assert df.loc[0, "timestamp"] == pd.Timestamp("2025-12-31 23:59:58")
    assert df.loc[1, "timestamp"] == pd.Timestamp("2026-01-01 00:00:02")


def test_future_date_is_assumed_to_be_last_year():
    df = parse("Dec 20 10:00:00 h sshd[1]: Failed password for a from 1.2.3.4", ref=datetime(2026, 1, 15)).records
    assert df.loc[0, "timestamp"] == pd.Timestamp("2025-12-20 10:00:00")


def test_iso_timestamp_is_converted_to_utc():
    df = parse("2026-09-22T10:31:21+05:30 h sshd[1]: Accepted password for bob from 1.2.3.4 port 22 ssh2").records
    assert df.loc[0, "timestamp"] == pd.Timestamp("2026-09-22 05:01:21")


def test_malformed_lines_are_counted_not_fatal():
    text = ("Sep 22 10:00:00 h sshd[1]: Failed password for a from 1.2.3.4\n"
            "complete nonsense\n"
            "Sep 22 10:00:01 h sshd[1]: Failed password for a from 1.2.3.4\n"
            "Sep 22 10:00:02 h sshd[1]: Failed password for a from 1.2.3.4\n")
    result = parse(text)
    assert (result.parsed_count, result.malformed_count) == (3, 1)
    assert result.malformed_samples[0]["line"] == 2


def test_invalid_ip_is_dropped_not_stored():
    df = parse("Sep 22 10:00:00 h sshd[1]: Failed password for a from not-an-ip port 22 ssh2").records
    assert pd.isna(df.loc[0, "source_ip"])
    assert df.loc[0, "event"] == "failed_login"


def test_hostile_content_is_kept_as_data_and_cleaned():
    payload = "Sep 22 10:00:00 h app[1]: <script>alert(1)</script> \x1b[31mred\x1b[0m " + "A" * 5000
    df = parse(payload).records
    assert "<script>" in df.loc[0, "message"]          # not interpreted or removed (frontend escapes it)
    assert "\x1b" not in df.loc[0, "message"]          # control characters removed
    assert len(df.loc[0, "raw_line"]) <= 1000 and len(df.loc[0, "message"]) <= 1000


# ---------------------------------------------------------------- apache / nginx
APACHE_LINE = ('203.0.113.5 - bob [22/Sep/2026:10:00:00 +0530] "POST /login HTTP/1.1" 401 512 '
               '"https://example.com/" "Mozilla/5.0 (X11)"')


def test_apache_combined_line():
    row = parse(APACHE_LINE).records.iloc[0]
    assert row["timestamp"] == pd.Timestamp("2026-09-22 04:30:00")  # +05:30 -> UTC
    assert (row["source_ip"], row["http_method"], row["http_path"], row["status_code"]) == ("203.0.113.5", "POST", "/login", 401)
    assert (row["event"], row["auth_status"], row["username"]) == ("http_client_error", "failure", "bob")
    assert row["protocol"] == "http/1.1" and row["user_agent"] == "Mozilla/5.0 (X11)"


def test_apache_common_format_and_garbage_request():
    text = ('1.2.3.4 - - [22/Sep/2026:10:00:00 +0000] "GET /a HTTP/1.0" 200 10\n'
            '1.2.3.4 - - [22/Sep/2026:10:00:01 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"\n')
    df = parse(text).records
    assert df.loc[0, "event"] == "http_success" and pd.isna(df.loc[0, "user_agent"])
    assert pd.isna(df.loc[1, "http_method"]) and df.loc[1, "status_code"] == 400


# ---------------------------------------------------------------- csv / json / jsonl
def test_csv_with_unusual_headers():
    text = ("Time,Src IP,Dst IP,Dst Port,User,Action,Result\n"
            "2026-09-22 10:00:00,203.0.113.9,10.0.0.5,22,root,login_failed,failure\n"
            "2026-09-22 10:00:05,192.168.1.2,10.0.0.5,22,bob,login_success,success\n")
    result = parse(text, "a.csv")
    df = result.records
    assert result.detected_format == "csv"
    assert (df.loc[0, "source_ip"], df.loc[0, "destination_port"], df.loc[0, "username"]) == ("203.0.113.9", 22, "root")
    assert (df.loc[0, "event"], df.loc[0, "auth_status"]) == ("failed_login", "failure")
    assert df.loc[1, "event"] == "successful_login"
    assert "source_ip" in result.recognized_fields


def test_csv_status_column_can_be_http_or_login_result():
    http = parse("time,ip,status\n2026-09-22 10:00:00,1.2.3.4,404\n2026-09-22 10:00:01,1.2.3.4,200\n", "a.csv").records
    assert list(http["status_code"]) == [404, 200]
    login = parse("time,ip,status\n2026-09-22 10:00:00,1.2.3.4,Failed\n2026-09-22 10:00:01,1.2.3.4,Success\n", "a.csv").records
    assert list(login["auth_status"]) == ["failure", "success"]


def test_csv_row_with_wrong_column_count_is_malformed():
    good = "".join(f"2026-09-22 10:00:{i:02d},1.2.3.4,bob\n" for i in range(9))
    result = parse("time,src_ip,user\n" + good + "2026-09-22 10:00:30,1.2.3.4\n", "a.csv")
    assert (result.parsed_count, result.malformed_count) == (9, 1)


def test_csv_with_unknown_columns_explains_what_is_needed():
    with pytest.raises(LogAnalysisError) as info:
        parse("foo,bar\n1,2\n3,4\n", "a.csv")
    assert info.value.code == "no_recognized_fields" and "source_ip" in info.value.message


def test_json_nested_ecs_style_records():
    text = '[{"@timestamp": "2026-09-22T10:00:00Z", "source": {"ip": "203.0.113.9"}, "user": {"name": "root"}, "event": {"action": "login_failed", "outcome": "failure"}}]'
    row = parse(text, "a.json").records.iloc[0]
    assert row["timestamp"] == pd.Timestamp("2026-09-22 10:00:00")
    assert (row["source_ip"], row["username"], row["event"], row["auth_status"]) == ("203.0.113.9", "root", "failed_login", "failure")


def test_json_object_wrapping_a_list_of_records():
    text = '{"events": [{"time": "2026-09-22 10:00:00", "src_ip": "1.2.3.4"}, {"time": "2026-09-22 10:00:01", "src_ip": "1.2.3.5"}]}'
    assert parse(text, "a.json").parsed_count == 2


def test_jsonl_with_epoch_timestamps_and_a_bad_line():
    epoch = int(datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc).timestamp())
    text = (f'{{"time": {epoch}, "src_ip": "1.2.3.4", "user": "bob"}}\n'
            'this line is not json\n'
            f'{{"time": {epoch * 1000 + 5000}, "src_ip": "1.2.3.5", "user": "eve"}}\n')
    result = parse(text, "a.jsonl")
    assert (result.parsed_count, result.malformed_count) == (2, 1)
    assert result.records.loc[0, "timestamp"] == pd.Timestamp("2026-09-22 10:00:00")   # seconds
    assert result.records.loc[1, "timestamp"] == pd.Timestamp("2026-09-22 10:00:05")   # milliseconds


def test_auth_message_inside_structured_log_is_classified():
    text = '[{"time": "2026-09-22 10:00:00", "message": "Failed password for root from 203.0.113.5 port 22 ssh2", "host": "web01"}]'
    row = parse(text, "a.json").records.iloc[0]
    assert (row["event"], row["username"], row["source_ip"], row["source_port"]) == ("failed_login", "root", "203.0.113.5", 22)


def test_empty_json_list_is_reported():
    with pytest.raises(LogAnalysisError) as info:
        parse("[]", "a.json")
    assert info.value.code == "no_records"


# ---------------------------------------------------------------- the real sample files
def test_bruteforce_sample_contains_the_documented_attack():
    df = sample("bruteforce_ssh_auth.log").records
    attack = df[(df["event"] == "failed_login") & (df["source_ip"] == "203.0.113.50")]
    assert len(attack) == 327
    assert (attack["timestamp"].max() - attack["timestamp"].min()).total_seconds() < 240
    assert (df["event"] == "successful_login").any()


def test_normal_ssh_sample_has_no_burst_of_failures():
    df = sample("normal_ssh_auth.log").records
    assert (df["event"] == "failed_login").sum() < 15
    assert df["source_ip"].dropna().nunique() <= 4


def test_web_samples_parse_completely():
    normal, suspicious = sample("normal_web_access.log"), sample("suspicious_web_access.log")
    assert normal.malformed_count == 0 and normal.parsed_count == 400
    assert suspicious.malformed_count == 0
    scanner = suspicious.records[suspicious.records["source_ip"] == "198.51.100.99"]
    assert len(scanner) == 250 and (scanner["status_code"] == 404).mean() > 0.7
    assert (suspicious.records["status_code"] == 401).sum() == 120

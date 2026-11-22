from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.ingestion.log_reader import MAX_FILE_SIZE_BYTES
from app.main import app

client = TestClient(app)
SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"


def upload(name, data, content_type="text/plain"):
    return client.post("/api/parse", files={"file": (name, data, content_type)})


@pytest.mark.parametrize("name,expected_format", [
    ("normal_ssh_auth.log", "syslog"),
    ("bruteforce_ssh_auth.log", "syslog"),
    ("normal_web_access.log", "apache_access"),
    ("suspicious_web_access.log", "apache_access"),
    ("sample_events.csv", "csv"),
    ("sample_events.json", "json"),
    ("sample_events.jsonl", "jsonl"),
])
def test_sample_files_upload_and_parse(name, expected_format):
    response = upload(name, (SAMPLES / name).read_bytes())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["detected_format"] == expected_format
    assert body["malformed_records"] == 0
    assert body["parsed_records"] == body["total_records"] > 0
    assert body["time_range"] is not None
    assert 0 < len(body["preview"]) <= 20
    assert body["filename"] == name


def test_preview_shape_for_syslog():
    body = upload("bruteforce_ssh_auth.log", (SAMPLES / "bruteforce_ssh_auth.log").read_bytes()).json()
    first = body["preview"][0]
    assert set(first) >= {"timestamp", "host", "service", "event", "username", "source_ip", "raw_line"}
    assert body["field_coverage"]["timestamp"] == body["parsed_records"]


def test_unrecognized_file_returns_clear_422():
    response = upload("malformed_sample.log", (SAMPLES / "malformed_sample.log").read_bytes())
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "unknown_format" and "Supported formats" in error["message"]


def test_unsupported_extension_returns_415():
    response = upload("payload.exe", b"MZ....")
    assert response.status_code == 415 and response.json()["error"]["code"] == "unsupported_extension"


def test_empty_file_returns_422():
    response = upload("empty.log", b"")
    assert response.status_code == 422 and response.json()["error"]["code"] == "empty_file"


def test_oversized_file_returns_413():
    response = upload("big.log", b"a" * (MAX_FILE_SIZE_BYTES + 10))
    assert response.status_code == 413 and response.json()["error"]["code"] == "file_too_large"


def test_malicious_filename_is_sanitized_in_response():
    data = b"Sep 22 10:00:00 h sshd[1]: Failed password for a from 1.2.3.4\n"
    response = upload("../../../etc/passwd.log", data)
    assert response.status_code == 200 and response.json()["filename"] == "passwd.log"


def test_missing_file_field_is_rejected():
    assert client.post("/api/parse").status_code == 422


# ---------------------------------------------------------------- /api/features (Stage 3)
def test_features_endpoint_for_bruteforce_sample():
    data = (SAMPLES / "bruteforce_ssh_auth.log").read_bytes()
    response = client.post("/api/features", files={"file": ("bruteforce_ssh_auth.log", data)})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["detected_format"] == "syslog" and body["window_seconds"] == 60
    assert body["summary"]["failed_logins"] == 330
    assert body["capabilities"]["has_auth_events"] is True and body["capabilities"]["has_http"] is False
    assert body["top_ips"][0]["source_ip"] == "203.0.113.50" and body["top_ips"][0]["failed_logins"] == 327
    assert body["top_ips"][0]["first_seen"] == "2026-09-22 14:02:10"
    assert len(body["busiest_windows"]) == 5 and body["busiest_windows"][0]["events"] >= 150


def test_features_endpoint_reuses_upload_validation():
    response = client.post("/api/features", files={"file": ("payload.exe", b"MZ")})
    assert response.status_code == 415 and response.json()["error"]["code"] == "unsupported_extension"
    response = client.post("/api/features", files={"file": ("m.log", (SAMPLES / "malformed_sample.log").read_bytes())})
    assert response.status_code == 422 and response.json()["error"]["code"] == "unknown_format"


# ---------------------------------------------------------------- /api/detect (Stage 4)
def post_detect(name):
    return client.post("/api/detect", files={"file": (name, (SAMPLES / name).read_bytes())})


def test_detect_endpoint_bruteforce_sample():
    response = post_detect("bruteforce_ssh_auth.log")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["rule_findings"] == 3 and body["ml_findings"] == 1
    first_rule = next(d for d in body["detections"] if d["rule_id"] == "failed_login_burst")
    assert first_rule["source_ip"] == "203.0.113.50" and first_rule["occurrences"] == 327
    assert first_rule["evidence"][0]["raw_line"].startswith("Sep 22 14:02")
    assert any(not rule["ran"] and rule["skipped_reason"] for rule in body["rules"])
    assert body["ml"]["ran"] is True and body["thresholds"]["failed_login_burst_per_window"] == 10


def test_detect_endpoint_clean_log_has_no_findings():
    body = post_detect("normal_web_access.log").json()
    assert body["detections"] == [] and body["rule_findings"] == 0 and body["ml_findings"] == 0


def test_detect_endpoint_reuses_upload_validation():
    assert client.post("/api/detect", files={"file": ("x.exe", b"MZ")}).status_code == 415
    assert post_detect("malformed_sample.log").status_code == 422


# ---------------------------------------------------------------- /api/findings (Stage 5)
def post_findings(name):
    return client.post("/api/findings", files={"file": (name, (SAMPLES / name).read_bytes())})


def test_findings_endpoint_bruteforce_sample():
    response = post_findings("bruteforce_ssh_auth.log")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["risk_summary"]["overall_status"] == "critical"
    assert body["risk_summary"]["severity_counts"]["CRITICAL"] == 2
    first = body["findings"][0]
    assert first["finding_id"] == "F-001" and first["category"] == "Brute Force Attack"
    assert first["risk"]["score"] == 77 and first["risk"]["severity"] == "CRITICAL"
    assert [f["name"] for f in first["risk"]["factors"]][0] == "Type of activity"
    assert first["confidence"] == "high" and first["evidence"][0]["raw_line"].startswith("Sep 22 14:02")


def test_findings_endpoint_clean_log():
    body = post_findings("normal_ssh_auth.log").json()
    assert body["findings"] == [] and body["risk_summary"]["status_label"] == "CLEAN / NO ANOMALIES DETECTED"


def test_findings_endpoint_reuses_upload_validation():
    assert client.post("/api/findings", files={"file": ("x.exe", b"MZ")}).status_code == 415
    assert post_findings("malformed_sample.log").status_code == 422

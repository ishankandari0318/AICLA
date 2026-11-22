"""The Stage 7 HTTP flow: upload -> job -> poll -> report. Needs fastapi (run from the backend folder)."""

import time
from pathlib import Path

import pytest

fastapi_testclient = pytest.importorskip("fastapi.testclient")

from app.main import app  # noqa: E402

client = fastapi_testclient.TestClient(app)
SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"


def upload(name, data=None, filename=None):
    content = (SAMPLES / name).read_bytes() if data is None else data
    return client.post("/api/analyze", files={"file": (filename or name, content)})


def wait_for(job_id, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = client.get(f"/api/jobs/{job_id}").json()
        if body["status"] in ("done", "error"):
            return body
        time.sleep(0.05)
    raise AssertionError("timeout")


def test_config_matches_backend_limits():
    body = client.get("/api/config").json()
    assert ".log" in body["allowed_extensions"] and body["max_file_size_bytes"] == 10 * 1024 * 1024


def test_full_flow_for_suspicious_log():
    response = upload("bruteforce_ssh_auth.log")
    assert response.status_code == 202
    job = response.json()
    assert [s["id"] for s in job["stages"]] == ["read", "parse", "features", "detect", "classify", "risk", "report"]

    final = wait_for(job["job_id"])
    assert final["status"] == "done"
    report = client.get(f"/api/jobs/{job['job_id']}/report")
    assert report.status_code == 200
    assert report.json()["status"]["overall_status"] == "critical"

    markdown = client.get(f"/api/jobs/{job['job_id']}/report.md")
    assert markdown.status_code == 200
    assert 'filename="security-report.md"' in markdown.headers["content-disposition"]


def test_clean_log_flow():
    job_id = upload("normal_ssh_auth.log").json()["job_id"]
    wait_for(job_id)
    assert client.get(f"/api/jobs/{job_id}/report").json()["status"]["overall_status"] == "clean"


@pytest.mark.parametrize("filename, data, status, code", [
    ("notes.exe", b"hello", 415, "unsupported_extension"),
    ("empty.log", b"", 422, "empty_file"),
    ("big.log", b"a" * (10 * 1024 * 1024 + 1), 413, "file_too_large"),
])
def test_bad_uploads_are_rejected_before_a_job_starts(filename, data, status, code):
    response = upload(filename, data=data)
    assert response.status_code == status
    assert response.json()["error"]["code"] == code


def test_unrecognized_format_fails_the_job_with_a_message():
    job_id = upload("malformed_sample.log").json()["job_id"]
    final = wait_for(job_id)
    assert final["status"] == "error" and final["error"]["message"]
    assert client.get(f"/api/jobs/{job_id}/report").status_code == 409


def test_unknown_job_is_404_and_delete_is_idempotent():
    assert client.get("/api/jobs/not-a-real-job-id-123456").status_code == 404
    assert client.get("/api/jobs/not-a-real-job-id-123456/report").status_code == 404
    assert client.delete("/api/jobs/not-a-real-job-id-123456").status_code == 204


def test_delete_removes_results():
    job_id = upload("normal_ssh_auth.log").json()["job_id"]
    wait_for(job_id)
    assert client.delete(f"/api/jobs/{job_id}").status_code == 204
    assert client.get(f"/api/jobs/{job_id}").status_code == 404


def test_security_headers_are_present():
    response = client.get("/api/health")
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in client.get("/").headers["content-security-policy"]

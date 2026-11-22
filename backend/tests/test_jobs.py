"""The job manager (Stage 7): real progress, isolation between jobs, expiry, and failure handling.
These tests need no web server."""

import threading
import time
from pathlib import Path

import pytest

from app import jobs as jobs_module
from app.errors import LogAnalysisError
from app.ingestion.log_reader import read_upload
from app.jobs import JOB_ID_PATTERN, JobManager
from app.pipeline import STAGES

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"


def raw_sample(name):
    return read_upload(name, (SAMPLES / name).read_bytes())


def wait_until_finished(manager, job_id, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = manager.status(job_id)
        if status["status"] in ("done", "error"):
            return status
        time.sleep(0.02)
    raise AssertionError("job did not finish in time")


@pytest.fixture
def manager():
    m = JobManager(max_workers=2)
    yield m
    m.shutdown()


def test_pipeline_defines_the_seven_stages_in_order():
    assert [label for _, label in STAGES] == [
        "Reading uploaded logs", "Parsing and normalizing records", "Extracting security features", "Running anomaly detection",
        "Classifying suspicious activity", "Calculating risk scores", "Generating the final report"]


def test_job_runs_to_completion_and_all_stages_are_done(manager):
    first = manager.submit(raw_sample("bruteforce_ssh_auth.log"))
    assert JOB_ID_PATTERN.match(first["job_id"])
    assert first["stages"][0]["state"] == "done"            # the upload itself was already read and validated

    final = wait_until_finished(manager, first["job_id"])
    assert final["status"] == "done" and final["error"] is None
    assert all(stage["state"] == "done" for stage in final["stages"])
    report = manager.report(first["job_id"])
    assert report.meta.filename == "bruteforce_ssh_auth.log"
    assert report.status.overall_status == "critical"


def test_clean_log_produces_a_clean_report(manager):
    status = manager.submit(raw_sample("normal_ssh_auth.log"))
    wait_until_finished(manager, status["job_id"])
    assert manager.report(status["job_id"]).status.overall_status == "clean"


def test_progress_is_real_not_simulated(manager, monkeypatch):
    """Block the pipeline in the middle of 'detect' and check the status says exactly that."""
    inside_detect, release = threading.Event(), threading.Event()

    def fake_analyze(raw, on_stage=None, **_):
        for stage in ("parse", "features"):
            on_stage(stage, "running"), on_stage(stage, "done")
        on_stage("detect", "running")
        inside_detect.set()
        assert release.wait(10)
        raise LogAnalysisError("unrecognized_format", "stop here")

    monkeypatch.setattr(jobs_module, "analyze_log", fake_analyze)
    job_id = manager.submit(raw_sample("normal_ssh_auth.log"))["job_id"]
    assert inside_detect.wait(10)

    states = {s["id"]: s["state"] for s in manager.status(job_id)["stages"]}
    assert states == {"read": "done", "parse": "done", "features": "done", "detect": "running",
                      "classify": "pending", "risk": "pending", "report": "pending"}
    assert manager.status(job_id)["status"] == "running"
    assert manager.report(job_id) is None                    # nothing to fetch before the job is done

    release.set()
    final = wait_until_finished(manager, job_id)
    assert final["status"] == "error"
    assert {s["id"]: s["state"] for s in final["stages"]}["detect"] == "failed"      # the stage that was running is marked failed
    assert {s["id"]: s["state"] for s in final["stages"]}["classify"] == "pending"   # later stages never claim to have run


def test_file_problem_is_reported_with_its_own_message(manager):
    status = manager.submit(raw_sample("malformed_sample.log"))
    final = wait_until_finished(manager, status["job_id"])
    assert final["status"] == "error"
    assert final["error"]["code"] and final["error"]["message"]
    assert manager.report(status["job_id"]) is None


def test_unexpected_bug_is_hidden_from_the_user(manager, monkeypatch):
    def boom(raw, on_stage=None, **_):
        raise RuntimeError("secret internal detail /srv/app/file.py")

    monkeypatch.setattr(jobs_module, "analyze_log", boom)
    job_id = manager.submit(raw_sample("normal_ssh_auth.log"))["job_id"]
    final = wait_until_finished(manager, job_id)
    assert final["error"]["code"] == "internal_error"
    assert "secret" not in final["error"]["message"] and "/srv" not in final["error"]["message"]


def test_jobs_are_isolated_from_each_other(manager):
    a = manager.submit(raw_sample("normal_ssh_auth.log"))["job_id"]
    b = manager.submit(raw_sample("bruteforce_ssh_auth.log"))["job_id"]
    assert a != b
    wait_until_finished(manager, a), wait_until_finished(manager, b)
    assert manager.report(a).status.overall_status == "clean"
    assert manager.report(b).status.overall_status == "critical"
    assert manager.report(a).meta.filename == "normal_ssh_auth.log"


def test_unknown_or_malformed_ids_are_not_found(manager):
    assert manager.status("does-not-exist") is None
    assert manager.status("../../etc/passwd") is None
    assert manager.report("A" * 22) is None
    assert manager.delete("../x") is False


def test_delete_forgets_the_job(manager):
    job_id = manager.submit(raw_sample("normal_ssh_auth.log"))["job_id"]
    wait_until_finished(manager, job_id)
    assert manager.delete(job_id) is True
    assert manager.status(job_id) is None and manager.report(job_id) is None


def test_finished_jobs_expire():
    now = [0.0]
    m = JobManager(ttl_seconds=60, clock=lambda: now[0])
    try:
        job_id = m.submit(raw_sample("normal_ssh_auth.log"))["job_id"]
        wait_until_finished(m, job_id)
        now[0] = 30
        assert m.status(job_id) is not None
        now[0] = 200
        assert m.status(job_id) is None
    finally:
        m.shutdown()


def test_storage_is_capped_and_oldest_finished_job_makes_room():
    m = JobManager(max_jobs=2)
    try:
        ids = []
        for _ in range(3):
            ids.append(m.submit(raw_sample("normal_ssh_auth.log"))["job_id"])
            wait_until_finished(m, ids[-1])
        assert m.status(ids[0]) is None                       # evicted
        assert m.status(ids[1]) is not None and m.status(ids[2]) is not None
    finally:
        m.shutdown()


def test_server_busy_when_every_slot_is_still_running(monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(jobs_module, "analyze_log", lambda raw, on_stage=None, **_: release.wait(10) and (_ for _ in ()).throw(LogAnalysisError("x", "y")))
    m = JobManager(max_workers=1, max_jobs=1)
    try:
        m.submit(raw_sample("normal_ssh_auth.log"))
        with pytest.raises(LogAnalysisError) as info:
            m.submit(raw_sample("normal_ssh_auth.log"))
        assert info.value.code == "server_busy"
    finally:
        release.set()
        m.shutdown()

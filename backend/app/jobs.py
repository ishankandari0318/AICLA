"""Background analysis jobs, so the browser can show REAL progress.

Why this exists: analysing a file takes a moment, and the Processing screen must show which stage is
actually running. A single request/response cannot do that, so instead:

    POST /api/analyze        -> validates the upload, starts a job, returns its id immediately
    GET  /api/jobs/{id}      -> the browser polls this; each stage is pending / running / done / failed
    GET  /api/jobs/{id}/report -> the finished report

Design rules:
- Jobs live in MEMORY only. Nothing is written to disk, and the uploaded text is dropped as soon as
  the analysis finishes (only the finished report is kept).
- Job ids are random and unguessable (they are the only "key" to a report; there are no user accounts).
- Finished jobs expire after a while and the number of stored jobs is capped, so memory cannot grow
  without limit.
- Each job is independent, so results from different uploads can never be mixed."""

from __future__ import annotations

import logging
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from app.errors import LogAnalysisError
from app.ingestion.log_reader import RawLog
from app.pipeline import STAGES, analyze_log
from app.reporting.models import Report
from app.reporting.report_generator import build_report

logger = logging.getLogger(__name__)

JOB_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")

MAX_WORKERS = 2               # analyses that may run at once; extra jobs wait ("queued")
MAX_STORED_JOBS = 20
JOB_TTL_SECONDS = 30 * 60     # how long a finished job (and its report) is kept

STATUS_QUEUED, STATUS_RUNNING, STATUS_DONE, STATUS_ERROR = "queued", "running", "done", "error"
STAGE_PENDING, STAGE_RUNNING, STAGE_DONE, STAGE_FAILED = "pending", "running", "done", "failed"


class Job:
    def __init__(self, job_id: str, filename: str, now: float):
        self.job_id = job_id
        self.filename = filename
        self.status = STATUS_QUEUED
        self.stages = [{"id": stage_id, "label": label, "state": STAGE_PENDING} for stage_id, label in STAGES]
        self.error: dict[str, str] | None = None
        self.report: Report | None = None
        self.created = now
        self.finished: float | None = None

    @property
    def is_finished(self) -> bool:
        return self.status in (STATUS_DONE, STATUS_ERROR)


class JobManager:
    def __init__(self, max_workers: int = MAX_WORKERS, max_jobs: int = MAX_STORED_JOBS,
                 ttl_seconds: float = JOB_TTL_SECONDS, clock: Callable[[], float] = time.monotonic):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="analysis")
        self._max_jobs = max_jobs
        self._ttl = ttl_seconds
        self._clock = clock

    # ------------------------------------------------------------------ public API
    def submit(self, raw: RawLog) -> dict[str, Any]:
        """Register a job for an already validated upload and start it. Returns the job's status."""
        with self._lock:
            self._purge_expired_locked()
            self._make_room_locked()
            if len(self._jobs) >= self._max_jobs:
                raise LogAnalysisError("server_busy", "The server is busy with other analyses. Wait a moment and try again.")
            job = Job(secrets.token_urlsafe(16), raw.filename, self._clock())
            # The upload was read, validated and decoded before the job was created, so stage 1 is genuinely complete.
            job.stages[0]["state"] = STAGE_DONE
            self._jobs[job.job_id] = job
            status = self._status_locked(job)
        self._executor.submit(self._run, job, raw)
        return status

    def status(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._lookup_locked(job_id)
            return self._status_locked(job) if job else None

    def report(self, job_id: str) -> Report | None:
        """The finished report, or None if the job is unknown, still running, or failed."""
        with self._lock:
            job = self._lookup_locked(job_id)
            return job.report if job and job.status == STATUS_DONE else None

    def delete(self, job_id: str) -> bool:
        if not JOB_ID_PATTERN.match(job_id or ""):
            return False
        with self._lock:
            return self._jobs.pop(job_id, None) is not None

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------ worker
    def _run(self, job: Job, raw: RawLog) -> None:
        self._set_status(job, STATUS_RUNNING)
        try:
            analysis = analyze_log(raw, on_stage=lambda stage, state: self._set_stage(job, stage, state))
            self._set_stage(job, "report", "running")
            report = build_report(analysis)
            self._set_stage(job, "report", "done")
        except LogAnalysisError as error:          # a problem with the file itself: safe to show as-is
            self._fail(job, error.code, error.message)
            return
        except Exception:                          # a bug: log the details here, show nothing internal to the user
            logger.exception("Analysis job %s failed unexpectedly", job.job_id)
            self._fail(job, "internal_error", "Something went wrong while analysing this file. Try again, or try a different file.")
            return
        with self._lock:
            job.report = report
            job.status = STATUS_DONE
            job.finished = self._clock()

    # ------------------------------------------------------------------ internals
    def _set_status(self, job: Job, status: str) -> None:
        with self._lock:
            job.status = status

    def _set_stage(self, job: Job, stage_id: str, state: str) -> None:
        with self._lock:
            for stage in job.stages:
                if stage["id"] == stage_id:
                    stage["state"] = state

    def _fail(self, job: Job, code: str, message: str) -> None:
        with self._lock:
            for stage in job.stages:
                if stage["state"] == STAGE_RUNNING:
                    stage["state"] = STAGE_FAILED
            job.error = {"code": code, "message": message}
            job.status = STATUS_ERROR
            job.finished = self._clock()

    def _lookup_locked(self, job_id: str) -> Job | None:
        if not JOB_ID_PATTERN.match(job_id or ""):
            return None
        self._purge_expired_locked()
        return self._jobs.get(job_id)

    def _purge_expired_locked(self) -> None:
        now = self._clock()
        for job_id in [j.job_id for j in self._jobs.values() if j.finished is not None and now - j.finished > self._ttl]:
            del self._jobs[job_id]

    def _make_room_locked(self) -> None:
        """Only called when a NEW job arrives: if the store is full, drop the oldest FINISHED job.
        Running jobs are never dropped."""
        if len(self._jobs) >= self._max_jobs:
            finished = sorted((j for j in self._jobs.values() if j.is_finished), key=lambda j: j.finished or 0)
            if finished:
                del self._jobs[finished[0].job_id]

    @staticmethod
    def _status_locked(job: Job) -> dict[str, Any]:
        return {"job_id": job.job_id, "filename": job.filename, "status": job.status,
                "stages": [dict(stage) for stage in job.stages], "error": job.error}

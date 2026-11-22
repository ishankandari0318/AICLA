"""HTTP routes. This file only wires requests to the pipeline modules;
it must never contain detection or parsing logic itself."""

from fastapi import APIRouter, File, UploadFile
from fastapi.responses import JSONResponse, Response

from app.api.schemas import DetectionPreview, FeaturesPreview, FindingsPreview, JobStatus, ParsePreview
from app.detection.anomaly_detector import detect
from app.detection.models import Thresholds
from app.errors import LogAnalysisError
from app.features.feature_engineering import extract_features
from app.ingestion.log_reader import ALLOWED_EXTENSIONS, MAX_FILE_SIZE_BYTES, RawLog, read_upload
from app.jobs import JobManager
from app.parsing.log_parser import ParseResult, parse_log
from app.pipeline import analyze_log
from app.reporting.markdown_report import render_markdown
from app.reporting.models import Report
from app.reporting.report_generator import build_report

router = APIRouter(prefix="/api")

# One job manager for the whole server (see app/jobs.py). Tests may replace it.
job_manager = JobManager()

# Error code -> HTTP status. Anything else is a 422 (the file itself is the problem).
STATUS_BY_CODE = {"file_too_large": 413, "unsupported_extension": 415, "server_busy": 503, "job_not_found": 404}


def _ingest_and_parse(file: UploadFile) -> tuple[RawLog, ParseResult]:
    """Modules 1 + 2, shared by every endpoint that takes an upload."""
    data = file.file.read(MAX_FILE_SIZE_BYTES + 1)  # +1 so we can tell "too large" from "exactly at the limit"
    raw = read_upload(file.filename, data)
    return raw, parse_log(raw)


def _error_response(error: LogAnalysisError) -> JSONResponse:
    return JSONResponse(
        status_code=STATUS_BY_CODE.get(error.code, 422),
        content={"error": {"code": error.code, "message": error.message}},
    )


@router.get("/health")
def health() -> dict:
    """Used by the frontend to confirm the backend is running."""
    return {"status": "online", "service": "ai-cybersecurity-log-analyzer", "version": "0.7.0"}


# These are plain `def` (not `async def`) on purpose: FastAPI runs them in a worker thread,
# so a large file being processed does not freeze the whole server.
@router.post("/parse", response_model=ParsePreview)
def parse_upload(file: UploadFile = File(...)):
    """Stage 2 view: ingest + parse an uploaded log and describe the result."""
    try:
        raw, result = _ingest_and_parse(file)
    except LogAnalysisError as error:
        return _error_response(error)
    return ParsePreview.from_parse(raw, result)


@router.post("/features", response_model=FeaturesPreview)
def features_upload(file: UploadFile = File(...)):
    """Stage 3 view: ingest, parse, then show the engineered features. Used to validate the
    numbers before detection is built on top of them."""
    try:
        raw, result = _ingest_and_parse(file)
    except LogAnalysisError as error:
        return _error_response(error)
    return FeaturesPreview.from_features(raw, result, extract_features(result.records))


@router.post("/detect", response_model=DetectionPreview)
def detect_upload(file: UploadFile = File(...)):
    """Stage 4 view: ingest, parse, build features, then run rule-based and ML detection.
    Findings are not yet classified or scored; that comes in the next stage."""
    try:
        raw, parsed = _ingest_and_parse(file)
    except LogAnalysisError as error:
        return _error_response(error)
    thresholds = Thresholds()
    result = detect(parsed.records, extract_features(parsed.records), thresholds)
    return DetectionPreview.from_detection(raw, parsed, result, thresholds)


@router.post("/findings", response_model=FindingsPreview)
def findings_upload(file: UploadFile = File(...)):
    """Stage 5 view: the full pipeline up to risk scoring. Returns categorized findings, worst first,
    each with a score breakdown. (Remediation advice and the report are added in Stage 6.)"""
    try:
        data = file.file.read(MAX_FILE_SIZE_BYTES + 1)
        raw = read_upload(file.filename, data)
        analysis = analyze_log(raw)
    except LogAnalysisError as error:
        return _error_response(error)
    return FindingsPreview.from_analysis(analysis)


def _analyze_upload(file: UploadFile):
    data = file.file.read(MAX_FILE_SIZE_BYTES + 1)
    return analyze_log(read_upload(file.filename, data))


@router.post("/report", response_model=Report)
def report_upload(file: UploadFile = File(...)):
    """Stage 6: the complete analysis report (status, overview, charts, findings with advice, remediation).
    This is the document the dashboard renders."""
    try:
        analysis = _analyze_upload(file)
    except LogAnalysisError as error:
        return _error_response(error)
    return build_report(analysis)


@router.post("/report/markdown")
def report_markdown(file: UploadFile = File(...)):
    """The same report as a downloadable Markdown document."""
    try:
        analysis = _analyze_upload(file)
    except LogAnalysisError as error:
        return _error_response(error)
    return Response(
        content=render_markdown(build_report(analysis)),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="security-report.md"'},   # fixed name: never taken from the upload
    )


# ---------------------------------------------------------------------------------------- Stage 7
# The endpoints the web interface uses: upload -> job -> poll progress -> fetch report.

@router.get("/config")
def config() -> dict:
    """Upload limits, so the frontend validates against the same numbers as the backend (which still
    re-checks everything: client-side validation is a convenience, never the security boundary)."""
    return {"allowed_extensions": list(ALLOWED_EXTENSIONS), "max_file_size_bytes": MAX_FILE_SIZE_BYTES}


@router.post("/analyze", response_model=JobStatus, status_code=202)
def analyze_upload(file: UploadFile = File(...)):
    """Validate the upload and start analysing it in the background. Returns at once with a job id;
    the browser then polls GET /api/jobs/{id} to show real progress."""
    try:
        data = file.file.read(MAX_FILE_SIZE_BYTES + 1)
        raw = read_upload(file.filename, data)
        return job_manager.submit(raw)
    except LogAnalysisError as error:
        return _error_response(error)


def _job_not_found() -> JSONResponse:
    return _error_response(LogAnalysisError("job_not_found", "This analysis no longer exists. Upload the file again to re-run it."))


@router.get("/jobs/{job_id}", response_model=JobStatus)
def job_status(job_id: str):
    status = job_manager.status(job_id)
    return status if status is not None else _job_not_found()


@router.get("/jobs/{job_id}/report", response_model=Report)
def job_report(job_id: str):
    """The finished report. 409 while the job is still running or if it failed."""
    report = job_manager.report(job_id)
    if report is not None:
        return report
    status = job_manager.status(job_id)
    if status is None:
        return _job_not_found()
    return JSONResponse(status_code=409, content={"error": {"code": "report_not_ready", "message": "The analysis has not finished successfully."}})


@router.get("/jobs/{job_id}/report.md")
def job_report_markdown(job_id: str):
    """The finished report as a downloadable Markdown document."""
    report = job_manager.report(job_id)
    if report is None:
        return _job_not_found()
    return Response(
        content=render_markdown(report),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="security-report.md"'},   # fixed name: never taken from the upload
    )


@router.delete("/jobs/{job_id}", status_code=204)
def delete_job(job_id: str):
    """Forget an analysis (the frontend calls this when the user starts a new upload)."""
    job_manager.delete(job_id)
    return Response(status_code=204)

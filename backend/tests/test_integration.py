"""Stage 8: end-to-end checks across every sample and a set of awkward files. No web server needed.
For each file the whole pipeline runs (ingest -> report -> Markdown) and invariants are checked:
the things that must be true no matter what the input is."""

import json
from pathlib import Path

import pytest

from app.errors import LogAnalysisError
from app.ingestion.log_reader import read_upload
from app.pipeline import analyze_log
from app.reporting.markdown_report import render_markdown
from app.reporting.report_generator import build_report

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"


def severity_for(score):
    return "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"


def run(name, data):
    raw = read_upload(name, data)
    report = build_report(analyze_log(raw))
    json.loads(report.model_dump_json())          # must be serialisable
    render_markdown(report)                       # must render
    return raw, report


def check_invariants(raw, report):
    assert report.overview.total_anomalies == len(report.findings) == sum(report.severity_distribution.values())
    assert (report.status.overall_status == "clean") == (not report.findings)
    assert report.overview.suspicious_events <= report.overview.total_logs_processed
    for f in report.findings:
        assert f.severity == severity_for(f.risk_score), "score and severity must agree"
        assert 0 <= f.risk_score <= 100
        assert f.recommended_solutions and f.immediate_mitigation
        assert f.occurrences >= 1 and f.evidence_total >= len(f.evidence)


# (file, expected overall status)
SAMPLE_EXPECTATIONS = [
    ("normal_ssh_auth.log", "clean"), ("normal_web_access.log", "clean"),
    ("bruteforce_ssh_auth.log", "critical"), ("suspicious_web_access.log", "suspicious"),
    ("sample_events.csv", "suspicious"), ("sample_events.json", "suspicious"), ("sample_events.jsonl", "suspicious"),
]


@pytest.mark.parametrize("name, expected", SAMPLE_EXPECTATIONS)
def test_samples_give_expected_status(name, expected):
    raw, report = run(name, (SAMPLES / name).read_bytes())
    check_invariants(raw, report)
    assert report.status.overall_status == expected


@pytest.mark.parametrize("name", ["bruteforce_ssh_auth.log", "suspicious_web_access.log", "normal_ssh_auth.log"])
def test_text_log_evidence_is_the_real_uploaded_line(name):
    raw, report = run(name, (SAMPLES / name).read_bytes())
    lines = raw.text.split("\n")
    for f in report.findings:
        for e in f.evidence:
            assert lines[e.line_no - 1].strip() == e.raw_line.strip()


def test_csv_evidence_is_the_original_row_at_the_right_line():
    raw, report = run("sample_events.csv", (SAMPLES / "sample_events.csv").read_bytes())
    lines = raw.text.split("\n")
    assert report.meta.line_label == "Line"
    for f in report.findings:
        for e in f.evidence:
            assert lines[e.line_no - 1].strip() == e.raw_line.strip()


def test_json_array_numbers_are_labelled_as_records():
    _, report = run("sample_events.json", (SAMPLES / "sample_events.json").read_bytes())
    assert report.meta.line_label == "Record"
    assert "record " in render_markdown(report)


def auth_lines(n, user="admin"):
    return "\n".join(f"Sep 22 10:31:{i % 60:02d} h sshd[1]: Failed password for {user} from 203.0.113.9 port 22 ssh2" for i in range(n)).encode()


@pytest.mark.parametrize("label, data", [
    ("crlf.log", auth_lines(60).replace(b"\n", b"\r\n")),
    ("utf16.log", b"\xff\xfe" + auth_lines(60).decode().encode("utf-16-le")),
    ("cp1252.log", auth_lines(60) + "\nSep 22 10:40:00 h sshd[1]: Failed password for jos\xe9 from 203.0.113.9 port 22 ssh2".encode("latin-1")),
    ("ipv6.log", b"Sep 22 10:31:21 h sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2\n" * 15),
    ("one_line.log", auth_lines(1)),
    ("no_timestamps.csv", b"user,src_ip,action\nadmin,1.2.3.4,failed login\nroot,1.2.3.4,failed login\n"),
    ("huge_line.log", b"Sep 22 10:31:21 h sshd[1]: Failed password for " + b"A" * 200000 + b" from 1.2.3.4 port 22 ssh2\n"),
])
def test_awkward_but_valid_files_never_crash(label, data):
    raw, report = run(label, data)
    check_invariants(raw, report)


def test_repeated_failures_in_awkward_encodings_are_still_detected():
    for label, data in [("crlf.log", auth_lines(60).replace(b"\n", b"\r\n")), ("utf16.log", b"\xff\xfe" + auth_lines(60).decode().encode("utf-16-le"))]:
        assert run(label, data)[1].findings, label


@pytest.mark.parametrize("label, data, code", [
    ("empty.log", b"", "empty_file"),
    ("blank.log", b"  \n\n ", "empty_file"),
    ("binary.log", bytes(range(256)) * 10, "binary_file"),
    ("malformed.log", (SAMPLES / "malformed_sample.log").read_bytes(), "unknown_format"),
    ("garbage.json", b"{not json", None),
    ("empty_list.json", b"[]", "no_records"),
    ("program.exe", b"MZ", "unsupported_extension"),
    ("noext", b"hello", "unsupported_extension"),
])
def test_bad_files_give_meaningful_errors(label, data, code):
    with pytest.raises(LogAnalysisError) as info:
        run(label, data)
    assert len(info.value.message) > 15
    if code:
        assert info.value.code == code


def test_hostile_text_is_carried_as_data_not_interpreted():
    payload = "<svg/onload=alert(1)>"
    data = auth_lines(40, user=payload)
    _, report = run("hostile.log", data)
    assert report.findings
    md = render_markdown(report)
    assert any(payload in (e.raw_line or "") for f in report.findings for e in f.evidence)   # kept verbatim: the frontend escapes it


def test_file_exactly_at_the_size_limit_is_accepted_and_one_byte_over_is_rejected():
    from app.ingestion.log_reader import MAX_FILE_SIZE_BYTES
    line = b"Sep 22 10:31:21 h sshd[1]: Accepted password for bob from 10.0.0.1 port 22 ssh2\n"
    data = (line * (MAX_FILE_SIZE_BYTES // len(line) + 1))[:MAX_FILE_SIZE_BYTES]
    assert read_upload("limit.log", data).size_bytes == MAX_FILE_SIZE_BYTES
    with pytest.raises(LogAnalysisError) as info:
        read_upload("limit.log", data + b"x")
    assert info.value.code == "file_too_large"


def test_two_analyses_in_one_process_do_not_share_state():
    _, first = run("a.log", (SAMPLES / "bruteforce_ssh_auth.log").read_bytes())
    _, second = run("b.log", (SAMPLES / "normal_ssh_auth.log").read_bytes())
    _, again = run("a.log", (SAMPLES / "bruteforce_ssh_auth.log").read_bytes())
    assert second.findings == [] and first.model_dump(exclude={"meta"}) == again.model_dump(exclude={"meta"})

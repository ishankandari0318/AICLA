import pytest

from app.errors import LogAnalysisError
from app.ingestion.format_detector import detect_format
from app.ingestion.log_reader import MAX_FILE_SIZE_BYTES, read_upload, sanitize_filename


def code_of(call):
    with pytest.raises(LogAnalysisError) as info:
        call()
    return info.value.code


def raw(text, name="x.log"):
    return read_upload(name, text.encode("utf-8"))


# ---------------------------------------------------------------- validation
def test_rejects_unsupported_extension():
    assert code_of(lambda: read_upload("malware.exe", b"hello")) == "unsupported_extension"
    assert code_of(lambda: read_upload("noextension", b"hello")) == "unsupported_extension"


def test_rejects_empty_and_blank_files():
    assert code_of(lambda: read_upload("a.log", b"")) == "empty_file"
    assert code_of(lambda: read_upload("a.log", b"  \n\n \t\n")) == "empty_file"


def test_rejects_oversized_file():
    assert code_of(lambda: read_upload("a.log", b"a" * (MAX_FILE_SIZE_BYTES + 1))) == "file_too_large"


def test_rejects_binary_file():
    assert code_of(lambda: read_upload("a.log", b"abc\x00\x01def")) == "binary_file"


def test_filename_is_sanitized_against_path_traversal():
    assert sanitize_filename("../../etc/passwd.log") == "passwd.log"
    assert sanitize_filename("C:\\Users\\me\\auth.log") == "auth.log"
    assert sanitize_filename("evil\x00name.log") == "evilname.log"
    assert sanitize_filename("") == "uploaded_file"
    assert read_upload("../../etc/passwd.log", b"x").filename == "passwd.log"


# ---------------------------------------------------------------- decoding
def test_decodes_utf8_with_bom():
    result = read_upload("a.log", b"\xef\xbb\xbfhello")
    assert result.text == "hello" and result.encoding == "utf-8"


def test_falls_back_to_cp1252_instead_of_crashing():
    result = read_upload("a.log", b"caf\xe9")
    assert result.text == "caf\u00e9" and result.encoding == "cp1252"


def test_decodes_utf16_with_bom():
    result = read_upload("a.log", "hello\nworld".encode("utf-16"))
    assert result.text == "hello\nworld" and result.encoding == "utf-16"


def test_normalizes_windows_line_endings():
    assert read_upload("a.log", b"one\r\ntwo\r\n").text == "one\ntwo\n"


# ---------------------------------------------------------------- format detection
SYSLOG = "Sep 22 10:31:21 server sshd[1234]: Failed password for admin from 192.168.1.50 port 22 ssh2\n" * 3
APACHE = '203.0.113.5 - - [22/Sep/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "curl/8.0"\n' * 3


def test_detects_each_format():
    assert detect_format(raw(SYSLOG)) == "syslog"
    assert detect_format(raw(APACHE)) == "apache_access"
    assert detect_format(raw("time,src_ip,user\n2026-09-22 10:00:00,1.2.3.4,bob\n", "a.csv")) == "csv"
    assert detect_format(raw('[{"time": "2026-09-22", "user": "bob"}]', "a.json")) == "json"
    assert detect_format(raw('{"user": "bob"}\n{"user": "eve"}\n', "a.jsonl")) == "jsonl"
    assert detect_format(raw("2026-09-22T10:31:21+05:30 host sshd[1]: Accepted password for bob from 1.2.3.4\n")) == "syslog"


def test_detection_uses_content_not_extension():
    assert detect_format(raw(SYSLOG, "notes.txt")) == "syslog"
    assert detect_format(raw(APACHE, "data.json")) == "apache_access"


def test_comment_lines_are_ignored_for_detection():
    assert detect_format(raw("# exported by tool\n" + SYSLOG)) == "syslog"


def test_unknown_format_gives_helpful_error():
    with pytest.raises(LogAnalysisError) as info:
        detect_format(raw("hello there\nthis is a diary entry\nnothing to see\n"))
    assert info.value.code == "unknown_format"
    assert "Supported formats" in info.value.message


def test_broken_json_array_is_reported_as_invalid_json():
    assert code_of(lambda: detect_format(raw('[{"a": 1}, {"b": ', "a.json"))) == "invalid_json"


def test_only_comments_is_reported():
    assert code_of(lambda: detect_format(raw("# nothing\n# here\n"))) == "no_records"

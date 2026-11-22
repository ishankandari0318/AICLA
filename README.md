# AI Cybersecurity Log Analyzer

Upload system or network logs, detect suspicious activity with rules and
machine learning (Isolation Forest), and get a SOC-style dashboard with
findings and recommended fixes.

**Status:** Stage 8 of 8: complete (ingestion, detection, risk, response, report, web interface, integration tests).

## Setup (Windows 11, PowerShell)

Create and activate a virtual environment once, from the project root:

```powershell
py -m venv venv
venv\Scripts\Activate.ps1
```

(If PowerShell blocks the activation script, run `Set-ExecutionPolicy -Scope Process Bypass` first.)

**All commands below must be run from the `backend` directory:**

```powershell
cd backend
py -m pip install -r requirements.txt
```

## Run

From the `backend` directory:

```powershell
py -m uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. Interactive API docs: http://127.0.0.1:8000/docs

## Test

From the `backend` directory:

```powershell
py -m pytest -v
```

## Stage 2: what works now

`POST /api/parse` accepts an uploaded log, detects its format, parses it into a
normalized table and returns a summary plus the first 20 normalized rows.
Try it from http://127.0.0.1:8000/docs (**POST /api/parse -> Try it out**) with any file in `data/samples/`.

### Supported formats (detected from content, not the file extension)

| Format | Example |
|---|---|
| Linux auth / syslog | `Sep 22 10:31:21 server sshd[1234]: Failed password for admin from 192.168.1.50 port 22 ssh2` |
| Syslog with ISO timestamps | `2026-09-22T10:31:21+05:30 server sshd[1234]: ...` |
| Apache / Nginx access log (common or combined) | `203.0.113.5 - - [22/Sep/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "curl/8.0"` |
| CSV with a header row | `Time,Src IP,User,Action` (field names are matched flexibly) |
| JSON (list of records, or `{"events": [...]}`) | nested fields such as `source.ip` are supported |
| JSON Lines | one JSON object per line |

Limits: `.csv .txt .log .json .jsonl`, up to 10 MB. Uploads are processed in memory and never written to disk.

### The normalized record

Every line becomes one row with these columns: `line_no, timestamp, host, service, event, username,
source_ip, destination_ip, source_port, destination_port, protocol, http_method, http_path,
status_code, auth_status, user_agent, message, raw_line`. Missing values stay empty.

Event names: `failed_login`, `successful_login`, `invalid_user`, `pam_auth_failure`,
`max_auth_attempts`, `connection_closed`, `disconnect`, `session_opened`, `session_closed`,
`sudo_command`, `no_identification`, `protocol_error`, `negotiation_failed`,
`http_success`, `http_redirect`, `http_client_error`, `http_server_error`, `other`.

### Things to know

- **Syslog has no year.** It is inferred (latest past date, handling New Year rollover).
- **Time zones.** Apache and ISO timestamps are converted to UTC. Classic syslog times are kept as written.
- **Counting failed logins:** count `failed_login` only. `pam_auth_failure` and `invalid_user` are
  extra lines describing the same attempt.
- **Untrusted content.** Control characters are stripped and long values truncated, but text is *not*
  HTML-escaped by the backend. The frontend must escape log content before displaying it.

## Stage 3: feature engineering

`POST /api/features` runs ingestion + parsing + feature engineering and shows the result (a validation
view; the real analysis endpoint comes later). Try it at http://127.0.0.1:8000/docs.

`features/feature_engineering.py` turns the normalized events into numbers, at three levels:

| Table | One row per | Used for |
|---|---|---|
| `window_features` | time window (default 60 s) for the whole log | Isolation Forest input, activity timeline |
| `ip_window_features` | (window, source IP) | Rules such as "failed logins per IP per minute" |
| `ip_summary` | source IP over the whole log | Top IPs, peaks, dashboard |

Plus `summary` (headline numbers) and `capabilities` (what this log can honestly support:
`has_auth_events`, `has_http`, `has_destination_ports`, ...). A web log has no logins, so login rules
must not run on it.

Features include: failed / successful logins and their ratio, unique IPs / usernames / destination
ports / URL paths, events per minute, HTTP 4xx and 5xx counts and rates, 401 count, busiest single IP
per window, and the time gap between consecutive events.

Design notes:
- **Tumbling windows.** A burst that crosses a minute boundary is split in two, so thresholds need margin.
- **Quiet windows are included** (with zeros) so "normal" includes idle time.
- **No NaN in the ML columns.** Ratios with no data are 0.0; a missing gap means "one full window apart".
- Very long logs automatically use a coarser window (max 20,000 windows).
- Logs without timestamps still get a summary and per-IP totals, but no time-based tables.

## Stage 4: detection engine

`POST /api/detect` runs ingestion, parsing, features and detection and returns every finding with its
evidence (a validation view; classification and risk scores are added in Stage 5).

Two kinds of detection, always labelled by `method`:

**Rule-based (`method: "rule"`)** - each rule has an explicit threshold (all in `detection/models.py`, class `Thresholds`)
and runs only if the log contains the information it needs. Skipped rules are reported with the reason.

| Rule | Looks for | Default threshold |
|---|---|---|
| `failed_login_burst` | failed logins from one IP in one window | >= 10 per 60 s |
| `repeated_failed_logins` | slow-and-low failures from one IP (if not already a burst) | >= 20 total |
| `many_usernames_from_ip` | one IP failing against many usernames | >= 5 usernames |
| `success_after_failures` | a successful login right after many failures from the same IP | >= 5 failures in 30 min |
| `ssh_probing` | connections that fail the SSH handshake | >= 5 events |
| `port_scan_like` | one IP touching many destination ports | >= 10 ports per window |
| `http_request_flood` | very many requests from one IP | >= 200 per 60 s |
| `http_probing` | mostly-failing (4xx) requests across many URLs | >= 30 errors, >= 60%, >= 5 URLs |
| `http_auth_failures` | repeated HTTP 401 responses | >= 20 |
| `http_server_error_spike` | a window where >= 30% of requests got 5xx | >= 20 requests in window |

**Machine learning (`method: "isolation_forest"`)** - an Isolation Forest trained on the per-window feature
vectors of the uploaded log (no labels needed). Safeguards:
1. It does not run with fewer than 20 active windows (reported as "insufficient data").
2. Only active windows are used, so quiet periods do not distort the baseline.
3. **Materiality gate:** an Isolation Forest always flags a few windows, even in normal data. A flagged
   window is reported only if a count feature is also far above typical (>= 8 robust units, using the median
   and MAD). This keeps normal logs clean.

ML findings are statistical outliers, never "confirmed attacks". They can catch what rules cannot (for
example a surge spread over many IPs). Each finding lists `related_detection_ids`: other findings that overlap
in time (and share the IP, when known), so a statistical anomaly that coincides with a rule finding is easy to spot.

Every finding carries `evidence`: real records from the file (line number + original text), the first 3 and
last 2 when there are more, plus `evidence_total`.

## Stage 5: classification and risk scoring

`POST /api/findings` runs the whole pipeline (`app/pipeline.py`) up to risk scoring and returns **findings**,
worst first (`F-001` is the highest risk), plus a `risk_summary` for the dashboard.

### Classification (`classification/attack_classifier.py`)

Each rule maps to one of the seven categories. The category comes from the evidence (which rule fired),
never from a guess. A finding also states *why* (`classification_basis`).

| Category | Produced by |
|---|---|
| Brute Force Attack | `failed_login_burst`, `repeated_failed_logins` |
| Credential Attack Indicators | `many_usernames_from_ip`, `http_auth_failures` |
| Suspicious Login Activity | `success_after_failures` |
| Port Scanning | `port_scan_like`, `ssh_probing` |
| DoS-like Activity | `http_request_flood` |
| Unusual HTTP Activity | `http_probing`, `http_server_error_spike` |
| Unknown Anomaly | a statistical (Isolation Forest) detection that no rule explains |

- Detections from the same IP and category are merged into one finding.
- A statistical detection that coincides with a rule finding is **not** a separate threat; it is recorded as
  corroboration (`supporting_ml_detection_ids`, and `"isolation_forest"` in `detection_methods`).
- `confidence` is `low` / `medium` / `high`, built from points (how far past the rule threshold, whether the
  statistical model agrees, whether the same IP shows other activity) and explained in `confidence_basis`.
  It is a label, not a probability.

### Risk score (`risk/risk_engine.py`)

Score = the sum of six factors whose maximums add up to exactly 100. Every finding lists each factor's points and reason.

| Factor | Max | Based on |
|---|---|---|
| Type of activity | 35 | the category (a likely compromise scores highest; reconnaissance lowest) |
| Number of occurrences | 15 | supporting log records, log scale |
| Intensity | 15 | how many times over the rule threshold, log scale (20x = maximum) |
| Attack pattern | 15 | same IP in several categories (+7); a success followed the failures (+8) |
| Detection confidence | 10 | high 10 / medium 5 / low 0 |
| Target importance | 10 | privileged accounts such as `root` or `admin` (+6); sensitive URLs such as `/admin` or `/login` (+6) |

Severity: 0-24 LOW, 25-49 MEDIUM, 50-74 HIGH, 75-100 CRITICAL.

**The Isolation Forest's anomaly score is never an input to the risk score** (it measures statistical
unusualness, not the probability of an attack). A finding that rests on statistics alone is additionally
capped at 49 (MEDIUM). Overall status: `clean` (no findings), `suspicious` (findings, none CRITICAL),
`critical` (at least one CRITICAL finding).

## Stage 6: response engine and report

`POST /api/report` runs the whole pipeline and returns **one complete JSON report**: the document the dashboard
renders. `POST /api/report/markdown` returns the same report as a downloadable Markdown file.
Try them at http://127.0.0.1:8000/docs.

### Response engine (`response/response_engine.py`)

Every finding becomes a `ThreatDetail` with: threat name, description, **why it is suspicious**, harmless
explanations to rule out, source and destination, affected service/host, accounts and URLs involved, occurrences,
severity and risk score (with the full breakdown), detection method, evidence, **possible impact**,
**recommended solutions**, **immediate mitigation steps** and optional reference commands.

- Advice is written per detection rule (SSH brute force and web login attacks need different advice) and filled in
  with the finding's real facts (IP, counts, accounts, URLs, times). No AI model is involved, so the same finding
  always gets the same advice.
- The wording is hedged on purpose ("indicators", "possibly compromised"). A test fails if any advice claims a
  confirmed attack or compromise.
- **It only recommends.** Nothing changes a firewall, blocks an address or edits a configuration.
  `reference_commands` are examples for a human to review. Only validated IP addresses are ever placed in them;
  usernames and URLs from the log appear in prose only (tested with injected "canary" values).

### Report (`reporting/report_generator.py`)

| Section | Contents |
|---|---|
| `meta` | file, format, size, UTC analysis time, records parsed / malformed, time range |
| `status` | `clean` / `suspicious` / `critical`, the label, a message and a note (the clean note states that this does not prove the system is secure) |
| `overview` | total logs, anomalies (= findings), **distinct** suspicious events, critical alerts, high-risk findings, unique source IPs |
| `severity_distribution`, `category_distribution` | counts |
| `findings` | the `ThreatDetail` list, worst first |
| `remediation_summary` | the first immediate actions of each finding, in priority order |
| `log_summary` | most frequent events, most active IPs, authentication stats, HTTP stats, network stats |
| `activity_summary` | short factual sentences (used on the clean-logs screen) |
| `charts` | severity distribution, event types, activity over time, suspicious timeline, top suspicious IPs |
| `analysis_details` | which rules ran or were skipped (and why), machine-learning status, notes |

Rules the report follows:
- **Nothing is invented.** A metric the log cannot provide is `null` (for example `unique_source_ips` for a log with no
  IP addresses, or `authentication` for a web log), so the UI can hide it instead of showing a fake zero.
- **Suspicious events are counted once.** Findings can share log lines (the same failed logins appear in a brute-force
  and a username-guessing finding), so `suspicious_events` is the number of distinct log records, not a sum.
- **Charts never exceed 240 points.** Longer logs are bucketed (`bucket_seconds` says how), and totals are preserved.
- Markdown export: text from the log is placed in code spans/blocks with backticks removed, so a hostile log line
  cannot inject formatting or links; the download filename is fixed, never taken from the upload.

Performance: a 10 MB file (about 59,000 log lines) is analyzed in roughly 3 seconds.

## Sample data

`data/samples/` contains clearly labelled **synthetic** logs (see its README). Regenerate with
`python data/samples/generate_samples.py`.

## Project layout

```
backend/app/
  ingestion/   log_reader.py (validate + decode), format_detector.py (which format?)
  parsing/     log_parser.py (dispatcher), syslog_parser.py, access_parser.py,
               structured_parser.py (csv/json/jsonl), auth_events.py, patterns.py, schema.py
  features/    feature_engineering.py
  detection/   anomaly_detector.py (entry point), rules.py, ml_detector.py, models.py, common.py
  classification/  attack_classifier.py, models.py (the Finding)
  risk/        risk_engine.py
  response/    response_engine.py (advice per finding), models.py (ThreatDetail)
  reporting/   report_generator.py, markdown_report.py, models.py (Report)
  pipeline.py  parse -> features -> detect -> classify -> score
  api/         routes.py, schemas.py
  errors.py    one error type with a code + user-friendly message
```


## Stage 7: the web interface

Open http://127.0.0.1:8000 after starting the server. Screens: **upload** -> **processing** (real stage progress) ->
**dashboard** (findings) or **clean logs screen** (no findings) -> **threat details** side panel -> upload another file.

### How the pieces talk to each other

```
browser                                   backend
POST /api/analyze (file)      ------>     validate upload, create a job, start it in a worker thread
                              <------     {job_id, stages[]}
GET  /api/jobs/{id} (polled)  ------>     status of each of the 7 stages: pending / running / done / failed
GET  /api/jobs/{id}/report    ------>     the full report JSON (this is what every screen renders)
GET  /api/jobs/{id}/report.md ------>     downloadable Markdown report
DELETE /api/jobs/{id}                     forget the results (called when you start a new upload)
GET  /api/config                          allowed extensions + size limit (so the UI never hard-codes them)
```

New files: `backend/app/jobs.py` (job manager), `frontend/index.html`, `css/style.css`, `js/app.js`,
`backend/tests/test_jobs.py`, `backend/tests/test_api_analyze.py`. Changed: `pipeline.py` (reports each stage as it starts and
finishes), `api/routes.py`, `api/schemas.py`, `main.py` (security headers).

### Design decisions
- **Real progress:** the pipeline calls a callback when a stage starts and ends; the browser shows exactly that. A failed
  stage is marked failed and later stages show "NOT RUN".
- **Jobs live in memory only**, have unguessable ids, expire after 30 minutes, and at most 20 are kept.
- **Untrusted logs:** the frontend only inserts text with `textContent`/text nodes (never `innerHTML`), and the server sends a
  Content-Security-Policy that blocks inline scripts.
- **Nothing is mixed between uploads:** "Analyze another file" destroys the old charts, clears the page and deletes the old job.
- **Charts:** Chart.js is loaded from `frontend/assets/vendor/` or a pinned CDN (see the README there).

Run the tests from `backend`: `py -m pytest -v`.


## Stage 8: integration and testing

Run everything from `backend`: `py -m pytest -v`. Test files and what they cover:

| File | Covers |
|---|---|
| `test_log_reader.py`, `test_parsers.py` | upload validation, encodings, every parser |
| `test_features.py`, `test_detection.py` | feature numbers, rules, Isolation Forest |
| `test_classification_risk.py`, `test_response_report.py` | categories, scores, advice, report, Markdown |
| `test_jobs.py` | background jobs: real stage progress, isolation, expiry, failures |
| `test_integration.py` | every sample end to end + awkward files (CRLF, UTF-16, cp1252, IPv6, no timestamps, 200 KB line, exactly-10 MB, binary, empty, malformed) with invariants: score matches severity, counts agree, evidence equals the real uploaded line |
| `test_api_analyze.py`, `test_api_parse.py`, `test_health.py` | the HTTP layer (needs `fastapi`, installed by `requirements.txt`) |

Expected results for the sample files: `normal_*` -> clean screen; `bruteforce_ssh_auth.log` -> CRITICAL;
`suspicious_web_access.log`, `sample_events.*` -> SUSPICIOUS; `malformed_sample.log` -> a clear "unrecognized format" error.

Integration fixes made in this stage: CSV evidence now shows the original CSV line (not a re-serialised copy), and for a JSON
array the evidence column and Markdown report say "Record" (a position in the array) instead of "Line".

### Manual checklist (about 5 minutes)
1. Open the app: only the upload screen shows. 2. Try a `.exe`, an empty file and a 11 MB file: each gives a clear message.
3. Upload `normal_ssh_auth.log`: "Your Logs Look Normal". 4. Upload `bruteforce_ssh_auth.log`: watch the 7 stages, then the
dashboard; click a threat; press Esc. 5. Click "Analyze another file": nothing from the previous run remains.
6. Upload `malformed_sample.log`: the failed stage is marked and an error is shown. 7. Download the Markdown report.

### Known limitations
- Detection uses fixed thresholds (`detection/models.py`, class `Thresholds`), tuned on the synthetic samples, not on real traffic.
- Isolation Forest needs at least 20 active time windows; shorter logs get rule-based detection only.
- Findings are indicators, not confirmed attacks. The tool recommends actions and never runs them.
- Results are kept in server memory for 30 minutes; restarting the server discards them.
- Optional LLM explanations (Module 8) were not added; the core report is fully rule-based.

# MailCheck — Email validation web app

Flask web application built around the supplied Python email validation logic.

## Features
- Sign up, login, logout; password hashes are stored, not plaintext passwords.
- Upload CSV/XLSX with an `email` header; non-empty rows are counted, then explicitly start validation.
- SQLite-backed background queue with restart recovery for queued/running jobs; parallel email checks with configurable worker limits.
- DNS response caching and a disposable-domain list cached in memory for six hours.
- Per-account job history, saved results in SQLite, and CSV/XLSX downloads later.
- CSRF protection, upload size/type checks, secure session cookie options, spreadsheet-formula-safe exports.

## Run locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

Set a strong secret before starting. PowerShell:

```powershell
$env:SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
python app.py
```

macOS/Linux:

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

Open http://127.0.0.1:5000. The SQLite database is created in `instance/app.db`.

If you want to use an SMTP envelope sender, set an address you control before starting the app (PowerShell example):

```powershell
$env:SMTP_MAIL_FROM = "validator@your-owned-domain.example"
$env:SMTP_TIMEOUT = "12"
$env:EMAIL_WORKERS = "3"
python app.py
```

Do not put an address you do not control here. If `SMTP_MAIL_FROM` is blank, the engine uses the standards-based null reverse-path (`<>`).

## Performance settings

Optional environment variables (starting values; benchmark your own connection before increasing them):

- `EMAIL_WORKERS=3`: parallel email checks within the active job.
- `MAX_CONCURRENT_SMTP=2`: process-wide limit for simultaneous SMTP probes; lower concurrency helps avoid provider throttling.
- `DNS_TIMEOUT=6` and `SMTP_TIMEOUT=12`: per-operation timeouts in seconds.
- `SMTP_RETRIES=2`: attempts per MX host for transient failures.
- `SMTP_RETRY_DELAY=1.5`: backoff delay in seconds between retries.
- `MAX_MX_TO_TRY=3`: maximum MX hosts tested in preference order.
- `SMTP_MAIL_FROM=`: optional envelope sender address that you control. Leave blank to use the RFC null reverse-path (`<>`).
- `DISPOSABLE_CACHE_TTL=21600`: disposable list memory-cache lifetime in seconds (6 hours).
- `QUEUE_POLL_SECONDS=2`: how often the SQLite queue checks for waiting jobs.

The queue is persistent in SQLite and recovers unfinished work after a normal restart. This is intended for one local app process/single machine; it is not a distributed queue. For multiple web workers or multiple machines, use a dedicated queue such as RQ/Celery with Redis and a production database.

## Docker

```bash
docker build -t mailcheck .
docker run --rm -p 5000:5000 \
  -e SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')" \
  -e COOKIE_SECURE=false \
  -v mailcheck-data:/app/instance mailcheck
```

For a public HTTPS deployment, set `COOKIE_SECURE=true`, use a durable volume for `/app/instance`, and configure a strong `SECRET_KEY` through your host's secret manager. Do not use the sample development secret.

## Important production notes

1. **This is designed for a single local app process, not a distributed multi-worker service.** The SQLite-backed queue recovers unfinished jobs after a restart, but queue processing runs in a daemon thread in the web process. For a high-volume or multi-instance deployment, use Celery/RQ + Redis and PostgreSQL.
2. SQLite is fine for a small single-instance pilot with persistent storage. Use PostgreSQL for multiple instances or significant concurrent use.
3. SMTP recipient probes are enabled by default for local use. Many cloud platforms block outbound port 25; set `ENABLE_SMTP_CHECK=false` on such hosts. SMTP results cannot guarantee mailbox existence.
4. SMTP responses cannot prove a mailbox exists. Results use `Likely valid` or `Unknown` where appropriate; do not treat these checks as guaranteed delivery or permission to send marketing email.
5. The database stores uploaded email addresses and validation results. Add a privacy notice, retention/deletion policy, backups, HTTPS, monitoring, and abuse/rate controls before offering this to the public.
6. The disposable-domain list is refreshed every six hours when its public source is reachable; a saved local copy is used if the download fails. DNS/network access is needed for network checks.

## Input format

CSV or XLSX with a header named exactly `email` (case-insensitive). Example:

```csv
email,name
hello@example.com,Hello
team@example.org,Team
```


## SMTP validation notes (important)

- `Likely Valid` means the MX server accepted the target `RCPT TO`; if a random-recipient control was rejected as a non-existent mailbox, that adds confidence. If the control is inconclusive, the result stays `Likely Valid` but the sub-status explicitly says catch-all was not confirmed. This is not proof of delivery.
- `Catch All` means both the target and a random test recipient were accepted. The individual mailbox remains unconfirmed.
- `Unknown` is intentional for blocked port 25, provider privacy protections, 4xx greylisting/rate limits, and inconclusive responses. Do not convert these to `Invalid`.
- The probe uses EHLO/HELO, STARTTLS when advertised, a configured sender address you control (if `SMTP_MAIL_FROM` is set) or RFC null reverse-path (`MAIL FROM:<>`), and a random-recipient comparison. It never sends `DATA` or an email message.
- DNS and SMTP timeouts have been lengthened. Temporary connection/4xx failures are retried with a delay, and alternate MX hosts are tried in preference order (up to `MAX_MX_TO_TRY`).
- Random-recipient catch-all control is cached per domain/MX host for six hours to avoid repeatedly probing the same domain for every address; the cache expires automatically.
- Gmail, Microsoft, Yahoo and many hosted providers intentionally hide recipient existence. No free SMTP-only algorithm can reliably identify every mailbox. Only a confirmation link/reply or authoritative provider-side account data can prove control/existence.
- To reduce false negatives, keep `ENABLE_SMTP_CHECK=true`, allow outbound TCP port 25, and keep conservative concurrency (`EMAIL_WORKERS=2` to `3`, `MAX_CONCURRENT_SMTP=1` to `2`). Do not raise concurrency to force more accepted responses; it can cause throttling and worse results.

## Website result columns (custom ZeroBounce-style layout)

The website preview and CSV/XLSX export use the same six columns:

- `Email`
- `Status`
- `My Sub Status`
- `My MX Record`
- `My SMTP Provider`
- `SMTP Response`

`SMTP Response` includes the SMTP numeric response (for example, 250, 550, or 451) and the server's response text when the server provides it. `My SMTP Provider` is inferred from MX hostnames and is best-effort (Google, Microsoft, Yahoo, Proofpoint, etc.). `My Sub Status` is an independent, conservative reason label such as `role_based`, `catch_all`, `temporary_smtp_failure`, or `smtp_rejected_unconfirmed`.

This project does not reproduce ZeroBounce's proprietary infrastructure, reputation datasets, mailbox intelligence, or private scoring. It retains the existing DNS/SMTP checks and adds a ZeroBounce-style presentation/classification layer using public DNS and live SMTP responses. A generic SMTP 550 is NOT automatically classified as Invalid. After a target `RCPT TO` 550, the engine probes a random recipient in the same session as a control:

- `Invalid` (`mailbox_not_found`) only when the target is rejected with enhanced code `5.1.1` or explicit mailbox/user-not-found wording, while the random recipient is accepted (250/251). This is strong evidence, not an absolute guarantee.
- `Unknown` (`smtp_550_unconfirmed`) when the 550 is generic, policy/security/spam/sender-related, the random recipient is also rejected, or the control probe is inconclusive.
- `Catch All` only when both the target and a random recipient are accepted. A 550 alone never implies catch-all.
- 4xx, timeout, greylisting, 551/553, and other inconclusive responses remain `Unknown` unless separate evidence supports a classification.

A 550 returned during connection, `EHLO`, or `MAIL FROM` is never treated as mailbox-level evidence. This conservative rule is intended to reduce false Invalid results; some providers deliberately conceal recipient existence, so SMTP-only checks cannot guarantee mailbox existence.

Run the local logic tests with `python -m unittest discover -s tests` (12 offline tests cover output columns, provider mapping, RCPT decisions, 550 handling, catch-all cache and temporary retry behavior).

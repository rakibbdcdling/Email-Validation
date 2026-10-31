
import os
import re
import socket
import smtplib
import ssl
import urllib.request
import threading
import time
import dns.resolver
import dns.exception
from openpyxl import load_workbook, Workbook

INPUT_FILE = "emails.xlsx"
OUTPUT_FILE = "emails_checked.xlsx"
DISPOSABLE_FILE = "disposable_domains.txt"

# Longer, conservative network windows: slow MX servers should not be marked Unknown too early.
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "6"))
SMTP_TIMEOUT = float(os.getenv("SMTP_TIMEOUT", "12"))
SMTP_RETRIES = max(1, int(os.getenv("SMTP_RETRIES", "2")))
SMTP_RETRY_DELAY = max(0.0, float(os.getenv("SMTP_RETRY_DELAY", "1.5")))
MAX_MX_TO_TRY = max(1, int(os.getenv("MAX_MX_TO_TRY", "3")))
MAX_CONCURRENT_SMTP = max(1, int(os.getenv("MAX_CONCURRENT_SMTP", "2")))
SMTP_MAIL_FROM = os.getenv("SMTP_MAIL_FROM", "").strip()  # Optional address you control; blank uses RFC null reverse-path <>.
DISPOSABLE_CACHE_TTL = max(60, int(os.getenv("DISPOSABLE_CACHE_TTL", "21600")))
ENABLE_SMTP_CHECK = os.getenv("ENABLE_SMTP_CHECK", "true").lower() == "true"

DISPOSABLE_URL = (
    "https://disposable.github.io/"
    "disposable-email-domains/domains.txt"
)

HEADERS = [
    "Email",
    "Status",
    "My Sub Status",
    "My MX Record",
    "My SMTP Provider",
    "SMTP Response",
]

ROLE_NAMES = {
    "admin", "administrator", "support", "info", "sales",
    "contact", "help", "webmaster", "postmaster", "office",
    "billing", "abuse", "security", "hr", "jobs",
    "noreply", "no-reply", "mailer-daemon",
}

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com",
    "hotmail.com", "live.com", "yahoo.com", "ymail.com",
    "icloud.com", "me.com", "aol.com", "proton.me",
    "protonmail.com", "gmx.com", "mail.com", "zoho.com",
}

resolver = dns.resolver.Resolver()
resolver.timeout = DNS_TIMEOUT
resolver.lifetime = DNS_TIMEOUT * 2
resolver.cache = dns.resolver.LRUCache(max_size=10000)

# Shared across all email workers in this process.
SMTP_LIMITER = threading.BoundedSemaphore(MAX_CONCURRENT_SMTP)
_disposable_lock = threading.Lock()
_disposable_cache = None
_disposable_cache_time = 0.0
_smtp_policy_lock = threading.Lock()
_smtp_policy_cache = {}  # (domain, mx_host) -> ("random_accepted"|"random_rejected"|"unknown", expiry)
SMTP_POLICY_CACHE_TTL = max(300, int(os.getenv("SMTP_POLICY_CACHE_TTL", "21600")))


def load_disposable_domains():
    """Cache the disposable list in memory; refresh periodically and use disk offline."""
    global _disposable_cache, _disposable_cache_time
    with _disposable_lock:
        now = time.monotonic()
        if _disposable_cache is not None and now - _disposable_cache_time < DISPOSABLE_CACHE_TTL:
            return _disposable_cache

        domains = set()
        try:
            request = urllib.request.Request(
                DISPOSABLE_URL,
                headers={"User-Agent": "FreeEmailChecker/1.0"},
            )
            with urllib.request.urlopen(request, timeout=15) as response:
                content = response.read().decode("utf-8")
            domains = {
                line.strip().lower().rstrip(".")
                for line in content.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            }
            if domains:
                with open(DISPOSABLE_FILE, "w", encoding="utf-8") as f:
                    f.write("\n".join(sorted(domains)))
                print(f"Disposable list updated: {len(domains)} domains")
        except Exception as exc:
            print(f"Could not update disposable list: {exc}")

        if not domains and os.path.exists(DISPOSABLE_FILE):
            try:
                with open(DISPOSABLE_FILE, encoding="utf-8") as f:
                    domains = {
                        line.strip().lower().rstrip(".")
                        for line in f
                        if line.strip() and not line.lstrip().startswith("#")
                    }
            except OSError as exc:
                print(f"Could not read saved disposable list: {exc}")

        if not domains:
            print("WARNING: No disposable list available.")

        _disposable_cache = domains
        _disposable_cache_time = now
        return _disposable_cache


def valid_syntax(email):
    if not isinstance(email, str):
        return False

    email = email.strip()

    if len(email) > 254 or email.count("@") != 1:
        return False

    local, domain = email.rsplit("@", 1)

    if not local or len(local) > 64 or not domain:
        return False

    if (
        local.startswith(".")
        or local.endswith(".")
        or ".." in local
    ):
        return False

    if not re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local
    ):
        return False

    try:
        domain = domain.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return False

    if len(domain) > 253 or "." not in domain:
        return False

    for label in domain.split("."):
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[A-Za-z0-9-]+", label)
        ):
            return False

    return True


def check_dns(domain):
    """Resolve MX in preference order; correctly support RFC 7505 Null MX and implicit MX."""
    try:
        answers = resolver.resolve(domain, "MX")
        mx_pairs = sorted(
            ((int(r.preference), str(r.exchange).rstrip(".").lower()) for r in answers),
            key=lambda item: item[0],
        )
        # A single Null MX (0 .) explicitly says this domain accepts no mail.
        if mx_pairs and all(not host for _, host in mx_pairs):
            return "No", "Yes", [], False
        hosts = list(dict.fromkeys(host for _, host in mx_pairs if host))
        if hosts:
            return "No", "No", hosts, True
    except dns.resolver.NXDOMAIN:
        return "Yes", "Yes", [], False
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException:
        return "Unknown", "Unknown", [], None

    # RFC implicit-MX fallback: A/AAAA may be the mail destination when MX is absent.
    saw_temporary = False
    for record_type in ("A", "AAAA"):
        try:
            resolver.resolve(domain, record_type)
            return "No", "Yes", [domain], True
        except dns.resolver.NXDOMAIN:
            return "Yes", "Yes", [], False
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException:
            saw_temporary = True
    if saw_temporary:
        return "Unknown", "Unknown", [], None
    return "No", "Yes", [], False


def check_mail_host_dns(hosts):
    """A host is usable if either A or AAAA resolves; transient DNS errors stay Unknown."""
    if not hosts:
        return "Unknown"
    saw_temporary = False
    for host in hosts:
        host_resolved = False
        host_temporary = False
        for record_type in ("A", "AAAA"):
            try:
                resolver.resolve(host, record_type)
                host_resolved = True
                break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except dns.exception.DNSException:
                host_temporary = True
        if host_resolved:
            return "No"
        saw_temporary = saw_temporary or host_temporary
    return "Unknown" if saw_temporary else "Yes"


def _smtp_message(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()
    return str(value or "").strip()


def _is_definitive_mailbox_550(message):
    """Only recognize strong mailbox-nonexistent evidence, not generic 550 policy blocks."""
    text = _smtp_message(message).lower()
    # 5.1.1 is the standard enhanced status for a bad destination mailbox address.
    if re.search(r"\b5\.1\.1\b", text):
        return True
    # Provider-specific text is accepted only when it explicitly says the recipient/user
    # or mailbox does not exist. Generic 'rejected', 'blocked', 'unavailable' is not enough.
    strong_phrases = (
        "user unknown", "unknown user", "no such user", "no such mailbox",
        "mailbox does not exist", "mailbox not found", "recipient does not exist",
        "recipient not found", "address does not exist", "account does not exist",
        "user does not exist", "invalid recipient address",
    )
    return any(phrase in text for phrase in strong_phrases)


def _is_temporary_smtp(code, message=""):
    text = _smtp_message(message).lower()
    return 400 <= int(code or 0) < 500 or any(
        token in text for token in ("try again", "temporarily", "greylist", "rate limit")
    )


def _smtp_mail_from(server):
    # Use only a sender explicitly configured by the operator. Otherwise use RFC null path.
    return server.mail(SMTP_MAIL_FROM) if SMTP_MAIL_FROM else server.mail("")


def _get_cached_random_policy(domain, host):
    key = (domain.lower(), host.lower())
    now = time.monotonic()
    with _smtp_policy_lock:
        item = _smtp_policy_cache.get(key)
        if item and item[1] > now:
            return item[0]
        if item:
            _smtp_policy_cache.pop(key, None)
    return None


def _set_cached_random_policy(domain, host, policy):
    if policy not in {"random_accepted", "random_rejected", "unknown"}:
        return
    key = (domain.lower(), host.lower())
    # Positive/negative controls are cached longer; inconclusive results are short-lived.
    ttl = SMTP_POLICY_CACHE_TTL if policy != "unknown" else min(SMTP_POLICY_CACHE_TTL, 600)
    with _smtp_policy_lock:
        _smtp_policy_cache[key] = (policy, time.monotonic() + ttl)


def _random_recipient_probe(server, domain):
    """One control recipient, on the same MX, using a fresh SMTP transaction."""
    try:
        server.rset()
        mail_code, mail_msg = _smtp_mail_from(server)
        if mail_code != 250:
            return mail_code, mail_msg
        random_email = f"probe-{os.urandom(12).hex()}@{domain}"
        return server.rcpt(random_email)
    except (OSError, smtplib.SMTPException, socket.timeout) as exc:
        return 0, str(exc)


def _smtp_recipient_probe_limited(hosts, email):
    """Careful RCPT-only probe. Never issues DATA and never equates generic 550 with invalid."""
    if not ENABLE_SMTP_CHECK or not hosts:
        return "Not checked", "", "", ""

    domain = email.rsplit("@", 1)[1].lower()
    last = ("Unavailable / blocked", "", "", "No SMTP response")
    for host in list(hosts)[:MAX_MX_TO_TRY]:
        for attempt in range(SMTP_RETRIES):
            server = None
            try:
                server = smtplib.SMTP(timeout=SMTP_TIMEOUT)
                server.set_debuglevel(0)
                connect_code, banner = server.connect(host, 25)
                if connect_code != 220:
                    last = (f"SMTP greeting rejected ({connect_code})", str(connect_code), host, _smtp_message(banner)[:300])
                    if _is_temporary_smtp(connect_code, banner) and attempt + 1 < SMTP_RETRIES:
                        time.sleep(SMTP_RETRY_DELAY * (attempt + 1))
                        continue
                    break

                ehlo_code, ehlo_msg = server.ehlo()
                if ehlo_code >= 400:
                    helo_code, helo_msg = server.helo()
                    if helo_code >= 400:
                        last = (f"EHLO/HELO rejected ({helo_code})", str(helo_code), host, _smtp_message(helo_msg)[:300])
                        break

                # STARTTLS when advertised. If TLS negotiation fails, retry this host on a
                # fresh connection; do not silently downgrade on the same connection.
                if server.has_extn("starttls"):
                    try:
                        server.starttls(context=ssl.create_default_context())
                        ehlo_code, ehlo_msg = server.ehlo()
                        if ehlo_code >= 400:
                            last = (f"EHLO after STARTTLS rejected ({ehlo_code})", str(ehlo_code), host, _smtp_message(ehlo_msg)[:300])
                            break
                    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
                        last = ("STARTTLS negotiation failed", "", host, str(exc)[:300])
                        if attempt + 1 < SMTP_RETRIES:
                            time.sleep(SMTP_RETRY_DELAY * (attempt + 1))
                            continue
                        break

                mail_code, mail_msg = _smtp_mail_from(server)
                if mail_code != 250:
                    last = (f"MAIL FROM rejected ({mail_code})", str(mail_code), host, _smtp_message(mail_msg)[:300])
                    # MAIL FROM failures are sender/policy-related, not recipient-invalid.
                    if _is_temporary_smtp(mail_code, mail_msg) and attempt + 1 < SMTP_RETRIES:
                        time.sleep(SMTP_RETRY_DELAY * (attempt + 1))
                        continue
                    break

                target_code, target_msg = server.rcpt(email)
                target_text = _smtp_message(target_msg)
                cached_policy = _get_cached_random_policy(domain, host)

                if target_code in (250, 251):
                    if cached_policy is None:
                        random_code, random_msg = _random_recipient_probe(server, domain)
                        if random_code in (250, 251):
                            cached_policy = "random_accepted"
                        elif random_code == 550 and _is_definitive_mailbox_550(random_msg):
                            cached_policy = "random_rejected"
                        else:
                            cached_policy = "unknown"
                        _set_cached_random_policy(domain, host, cached_policy)
                        random_detail = f"Random RCPT: {random_code} {_smtp_message(random_msg)}"
                    else:
                        random_detail = f"Random RCPT policy cached: {cached_policy}"

                    detail = f"Target RCPT: {target_code} {target_text}; {random_detail}"[:500]
                    if cached_policy == "random_accepted":
                        return ("Likely catch-all; mailbox unconfirmed", str(target_code), host, detail)
                    if cached_policy == "random_rejected":
                        return ("Target accepted; random recipient rejected", str(target_code), host, detail)
                    return ("Target accepted; catch-all control inconclusive", str(target_code), host, detail)

                if target_code == 550:
                    if cached_policy is None:
                        random_code, random_msg = _random_recipient_probe(server, domain)
                        if random_code in (250, 251):
                            cached_policy = "random_accepted"
                        elif random_code == 550 and _is_definitive_mailbox_550(random_msg):
                            cached_policy = "random_rejected"
                        else:
                            cached_policy = "unknown"
                        _set_cached_random_policy(domain, host, cached_policy)
                        random_detail = f"Random RCPT: {random_code} {_smtp_message(random_msg)}"
                    else:
                        random_detail = f"Random RCPT policy cached: {cached_policy}"
                    detail = f"Target RCPT: 550 {target_text}; {random_detail}"[:500]
                    if cached_policy == "random_accepted" and _is_definitive_mailbox_550(target_msg):
                        return ("Definitive mailbox-not-found (550)", "550", host, detail)
                    last = ("Target 550; mailbox existence unconfirmed", "550", host, detail)
                    break

                if 400 <= target_code < 500:
                    last = (f"Temporary SMTP rejection ({target_code})", str(target_code), host, target_text[:300])
                    if attempt + 1 < SMTP_RETRIES:
                        time.sleep(SMTP_RETRY_DELAY * (attempt + 1))
                        continue
                    break

                if target_code == 252:
                    last = ("Server cannot verify recipient (252)", "252", host, target_text[:300])
                    break

                last = (f"Recipient rejected; not definitive ({target_code})", str(target_code), host, target_text[:300])
                break

            except (OSError, socket.timeout, smtplib.SMTPException, ssl.SSLError) as exc:
                last = ("Unavailable / blocked", "", host, str(exc)[:300])
                if attempt + 1 < SMTP_RETRIES:
                    time.sleep(SMTP_RETRY_DELAY * (attempt + 1))
                    continue
                break
            finally:
                if server is not None:
                    try:
                        server.quit()
                    except Exception:
                        try:
                            server.close()
                        except Exception:
                            pass

    return last


def smtp_recipient_probe(hosts, email):
    """Run SMTP probes under a process-wide concurrency limit."""
    if not ENABLE_SMTP_CHECK or not hosts:
        return ("Not checked", "", "", "")
    with SMTP_LIMITER:
        return _smtp_recipient_probe_limited(hosts, email)


def identify_smtp_provider(hosts, domain):
    """Best-effort provider label inferred from MX hostnames; not an API lookup."""
    text = " ".join(hosts or []).lower()
    domain = (domain or "").lower()
    rules = [
        (("google.com", "googlemail.com", "aspmx.l.google.com", "smtp.google.com"), "google"),
        (("mail.protection.outlook.com", "olc.protection.outlook.com", "outlook.com"), "microsoft"),
        (("yahoodns.net", "yahoo.com", "yahoodns"), "yahoo"),
        (("protection.pamx", "ppe-hosted.com"), "proofpoint"),
        (("mx.cloudflare.net",), "cloudflare"),
        (("mailgun.org",), "mailgun"),
        (("ionos.com", "1and1.com"), "ionos"),
        (("titan.email",), "titan"),
        (("hostinger.com",), "hostinger"),
        (("emailsrvr.com",), "rackspace"),
        (("comcast.net", "mxge.comcast.net"), "comcast"),
        (("siteground", "mailspamprotection.com"), "siteground"),
    ]
    for needles, label in rules:
        if any(needle in text or needle in domain for needle in needles):
            return label
    return "Other / Unknown" if hosts else "Unknown"


def build_sub_status(local, smtp_result, smtp_code, smtp_detail):
    """Build a conservative sub-status; generic SMTP 550 is not proof of a missing mailbox."""
    local_name = local.lower().split("+", 1)[0]
    if smtp_result == "Definitive mailbox-not-found (550)":
        return "mailbox_not_found"
    if str(smtp_code or "") == "550" and smtp_result != "Definitive mailbox-not-found (550)":
        return "smtp_550_unconfirmed"
    if smtp_result.lower().startswith("likely catch-all"):
        return "catch_all"
    if smtp_result == "Target accepted; random recipient rejected":
        return "recipient_accepted"
    if smtp_result == "Target accepted; catch-all control inconclusive":
        return "recipient_accepted_catchall_unconfirmed"
    if local_name in ROLE_NAMES:
        return "role_based"
    if smtp_result == "Target accepted; mailbox unconfirmed":
        return ""
    if smtp_code and str(smtp_code).startswith("5"):
        return "smtp_rejected_unconfirmed"
    if smtp_code and str(smtp_code).startswith("4"):
        return "temporary_smtp_failure"
    if smtp_result == "Not checked":
        return "smtp_not_checked"
    if smtp_result == "Unavailable / blocked":
        return "smtp_unreachable_or_blocked"
    return "inconclusive"

def check_email(email, disposable_domains):
    email = str(email).strip()
    result = {header: "" for header in HEADERS}
    result["Email"] = email
    result["Status"] = "Unknown"
    result["My Sub Status"] = "inconclusive"
    result["My MX Record"] = ""
    result["My SMTP Provider"] = "Unknown"
    result["SMTP Response"] = "Not checked"

    if not valid_syntax(email):
        result["Status"] = "Invalid"
        result["My Sub Status"] = "invalid_syntax"
        result["SMTP Response"] = "Not checked: invalid email syntax"
        return result

    local, domain = email.rsplit("@", 1)
    domain = domain.rstrip(".").lower()
    local_name = local.lower().split("+", 1)[0]

    dns_error, mx_error, hosts, routing = check_dns(domain)

    result["My MX Record"] = ", ".join(hosts)
    result["My SMTP Provider"] = identify_smtp_provider(hosts, domain)

    if routing is False:
        result["Status"] = "Invalid"
        result["My Sub Status"] = "no_mail_route"
        result["SMTP Response"] = "Not checked: domain has no usable mail route"
        return result

    if routing is None:
        result["My Sub Status"] = "dns_temporary_or_inconclusive"
        result["SMTP Response"] = "Not checked: DNS lookup inconclusive"
        return result

    mail_host_dns = check_mail_host_dns(hosts)
    if mail_host_dns == "Yes":
        result["My Sub Status"] = "mx_host_unresolved"
        result["SMTP Response"] = "Not checked: MX host has no resolved address"
        return result
    if mail_host_dns == "Unknown":
        result["My Sub Status"] = "mx_host_dns_inconclusive"
        result["SMTP Response"] = "Not checked: MX host DNS inconclusive"
        return result

    smtp_result, smtp_code, smtp_server, smtp_detail = smtp_recipient_probe(hosts, email)
    code_text = str(smtp_code or "").strip()
    detail_text = str(smtp_detail or "").strip()
    result["SMTP Response"] = (f"{code_text} - {detail_text}" if code_text else detail_text or smtp_result)
    result["My SMTP Provider"] = identify_smtp_provider([smtp_server] if smtp_server else hosts, domain)
    result["My Sub Status"] = build_sub_status(local, smtp_result, smtp_code, smtp_detail)

    # Only a target-specific 550 with strong mailbox-not-found evidence AND a
    # random-recipient control accepted by the same server is classified Invalid.
    # Generic/policy 550 responses remain Unknown to reduce false invalids.
    if smtp_result == "Definitive mailbox-not-found (550)" and code_text == "550":
        result["Status"] = "Invalid"
    elif smtp_result in (
        "Target accepted; random recipient rejected",
        "Target accepted; catch-all control inconclusive",
    ):
        result["Status"] = "Likely Valid"
    elif smtp_result.lower().startswith("likely catch-all"):
        result["Status"] = "Catch All"
    else:
        result["Status"] = "Unknown"

    return result



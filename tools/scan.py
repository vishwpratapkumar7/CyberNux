#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# FILE: scan.py
# Web Vulnerability - terminal website vulnerability scanner. v2.2
#
# v2.2 TARGETED FIXES (from real scan-output analysis):
#  A. Findings are no longer generated on 4xx/5xx error pages
#     (page_finding_eligible). Links are still extracted from them.
#  B. HTML entities are unescaped in hrefs - "&amp;" URLs are gone.
#  C. New aggregated "broken_link" Observation for crawl-discovered
#     link targets that return error statuses.
#  D. CSRF markup check factored into testable pure functions.
#  E. url_key canonicalizes repeated identical query pairs.
#  F. Report explains the growing [n/total] progress denominator.
#  + 18 new offline unit tests incl. mock-response header/form tests.
#
# Classification model (unchanged): every finding is
#   issue | potential | hardening | observation
# and "Confirmed" refers to the OBSERVATION, never to exploitability.
# Read-only GET scanning. No credential guessing, no exploit payloads,
# no data extraction, no authentication attempts. Authorized targets only.
# Menu: [1] Scan Website  [2] Exit. Self-test: --selftest

import html as _htmllib
import os
import re
import shutil
import socket
import ssl
import sys
import textwrap
import threading
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

try:
    import requests
except ImportError:
    sys.stderr.write("\n[!] Missing dependency: requests\n"
                     "    Install:  pip install requests\n\n")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants (developer-controlled; not user-facing settings)
# ---------------------------------------------------------------------------
APP_NAME = "Web Vulnerability"
MAX_WORKERS = 40                 # concurrency cap (bounded pool)
MIN_REQUEST_INTERVAL = 0.03      # per-host pacing (~33 req/s)
MAX_RETRIES_PER_URL = 1          # bounded retry for transport errors only
MAX_RETRIES_TOTAL = 25           # global retry budget per scan
CONNECT_TIMEOUT = 8
READ_TIMEOUT = 15
MAX_CONTENT_BYTES = 3_000_000
MAX_PAGES = 250
MAX_DEPTH = 4
MAX_DISCOVERED = 700
MAX_SITEMAPS = 4
MAX_PARAM_TESTS = 35
PORT_TIMEOUT = 1.2
USER_AGENT = ("Web-Vulnerability-Scanner/1.0 "
              "(non-destructive; authorized security assessment)")

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}
RISK_WORD = {"Critical": "VERY HIGH", "High": "HIGH", "Medium": "MEDIUM",
             "Low": "LOW", "Informational": "INFO"}
CATEGORIES = ("issue", "potential", "hardening", "observation")
MENU_OPTIONS = [("1", "Scan Website"), ("2", "Exit")]

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}
# Reachability on these ports is worth an observation (commonly attacked
# when public). Still never claimed to be a vulnerable service.
NOTABLE_PORTS = {21, 23, 3306, 5432, 6379, 27017}

SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico", ".svg", ".css",
    ".js", ".mjs", ".map", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".mpeg", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".m4a", ".m4v", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt",
    ".pptx", ".zip", ".rar", ".7z", ".gz", ".tar", ".tgz", ".bz2", ".xml",
    ".json", ".txt", ".csv", ".rss", ".atom", ".apk", ".exe", ".dmg",
    ".iso", ".psd", ".ai", ".swf",
}
EXCLUDED_SEGMENTS = {"logout", "signout", "logoff", "sign-off", "log-out"}

SQL_ERR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql_[a-z_]+\(",
    r"mysql_fetch_[a-z_]+\(",
    r"unclosed quotation mark after the character string",
    r"incorrect syntax near",
    r"sqlite3?\.(operationalerror|databaseerror)",
    r"SQLSTATE\[[A-Z0-9]{5}\]",
    r"\bORA-\d{5}\b",
    r"microsoft oledb provider for sql server",
    r"microsoft sql server, error",
    r"postgresql query failed",
    r"pg_query\(",
    r"syntax error at or near",
    r"could not prepare statement",
]
STACK_PATTERNS = [
    r"traceback \(most recent call last\)",
    r"java\.lang\.(nullpointerexception|stackoverflowerror|illegalstateexception)",
    r"system\.nullreferenceexception",
    r"at [a-z0-9_$.]+\(.*\.java:\d+\)",
    r"(fatal|parse) error: .+ in .+ on line \d+",
    r"<b>deprecated</b>:",
    r"exception details:",
    r"server error in '",
    r"debug mode is enabled",
]
MIXED_RE = re.compile(
    r"(?is)<(script|iframe|embed|object|link|img|video|audio|source|track)\b"
    r"[^>]*?(?:src|href|data)\s*=\s*[\"'](http://[^\"']+)[\"']")
A_HREF_RE = re.compile(r"(?is)<a\b[^>]*?href\s*=\s*[\"']([^\"'\s]+)[\"']")
CSRF_TOKEN_RE = re.compile(
    r"(?i)name=[\"'](csrf|_token|token|authenticity_token|anticsrf|"
    r"__requestverificationtoken)[^\"']*[\"']")

SENSITIVE_PROBES = [
    dict(path="/.env", title="Secret Settings File (.env) Is Public",
         sev="Critical",
         sigs=(b"APP_KEY=", b"DB_PASSWORD=", b"DB_HOST=", b"APP_URL="),
         html=False),
    dict(path="/.env.local", title="Secret Settings (.env.local) Is Public",
         sev="Critical",
         sigs=(b"APP_KEY=", b"DB_PASSWORD=", b"DB_HOST=", b"APP_URL="),
         html=False),
    dict(path="/.git/HEAD", title="Git Code History (.git) Is Public",
         sev="High", sigs=(b"ref: refs/",), html=False),
    dict(path="/.git/config", title="Git Config (.git/config) Is Public",
         sev="High", sigs=(b"repositoryformatversion",), html=False),
    dict(path="/.htaccess", title="Server Rules File (.htaccess) Is Public",
         sev="Medium", sigs=(b"RewriteEngine", b"RewriteRule"), html=False),
    dict(path="/web.config", title="Server Config (web.config) Is Public",
         sev="Medium", sigs=(b"<system.web", b"<connectionStrings"),
         html=True),
    dict(path="/wp-config.php", title="WordPress Password File Is Public",
         sev="Critical", sigs=(b"DB_PASSWORD", b"DB_NAME"), html=False),
    dict(path="/phpinfo.php", title="PHP Info Page Is Public",
         sev="Medium", sigs=(b"phpinfo", b"PHP Version"), html=True),
    dict(path="/server-status", title="Server Status Page Is Public",
         sev="Medium", sigs=(b"Apache Server Status", b"Server Version:"),
         html=True),
    dict(path="/backup.sql", title="Database Backup (backup.sql) Is Public",
         sev="Critical", sigs=(b"INSERT INTO", b"CREATE TABLE"), html=False),
    dict(path="/dump.sql", title="Database Backup (dump.sql) Is Public",
         sev="Critical", sigs=(b"INSERT INTO", b"CREATE TABLE"), html=False),
    dict(path="/backup.zip", title="Backup Zip File Is Public",
         sev="High", sigs=(b"PK" + bytes([3, 4]),), html=False),
]

ADMIN_PROBES = [
    dict(path="/admin/", markers=(b"password", b"login", b"signin")),
    dict(path="/wp-admin/", markers=(b"wp-login", b"user-login")),
    dict(path="/administrator/", markers=(b"password", b"joomla")),
    dict(path="/phpmyadmin/", markers=(b"phpmyadmin", b"pma_username")),
]

BANNER_FONT = {
    "W": ["#   #", "#   #", "# # #", "# # #", " # # "],
    "E": ["####", "#   ", "### ", "#   ", "####"],
    "B": ["### ", "#  #", "### ", "#  #", "### "],
    "V": ["#   #", "#   #", "#   #", " # # ", "  #  "],
    "U": ["#   #", "#   #", "#   #", "#   #", " ### "],
    "L": ["#    ", "#    ", "#    ", "#    ", "#### "],
    "N": ["#   #", "##  #", "# # #", "#  ##", "#   #"],
    "R": ["### ", "#  #", "### ", "# # ", "#  #"],
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    "I": ["#####", "  #  ", "  #  ", "  #  ", "#####"],
    "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
    "Y": ["#   #", " # # ", "  #  ", "  #  ", "  #  "],
}

# ---------------------------------------------------------------------------
# Terminal styling
# ---------------------------------------------------------------------------
def _ansi_enabled():
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 4)
                return True
        except Exception:
            os.system("")
        return True
    return True


class Style:
    def __init__(self, enabled):
        self.enabled = enabled

    def wrap(self, code, s):
        if self.enabled:
            return "\033[" + code + "m" + str(s) + "\033[0m"
        return str(s)

    def bold(self, s): return self.wrap("1", s)
    def dim(self, s): return self.wrap("2", s)
    def cyan(self, s): return self.wrap("96", s)
    def green(self, s): return self.wrap("92", s)
    def yellow(self, s): return self.wrap("93", s)
    def red(self, s): return self.wrap("91", s)


STY = Style(_ansi_enabled())
_PRINT_LOCK = threading.Lock()


def uprint(msg=""):
    with _PRINT_LOCK:
        try:
            print(msg)
        except UnicodeEncodeError:
            try:
                print(str(msg).encode("ascii", "replace").decode("ascii"))
            except Exception:
                pass


def sev_color(severity):
    return {"Critical": STY.red, "High": STY.red, "Medium": STY.yellow,
            "Low": STY.green, "Informational": STY.cyan}.get(severity, str)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _clip(s, n):
    s = str(s).replace("\x00", "")
    return s if len(s) <= n else s[: n - 3] + "..."


REDACT_PATTERNS = [
    (re.compile(
        r"(?i)\b([A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|token|"
        r"api[_-]?key|apikey|access[_-]?key|auth|credential|"
        r"private[_-]?key|client[_-]?secret|session[_-]?id|sessionid|"
        r"bearer))\b['\"]?\s*([=:\s]+)\s*([^\s;,'\"]{4,120})"),
     r"\1\2<REDACTED>"),
    (re.compile(r"(?i)(set-cookie:\s*[^=;\s]+)="), r"\1=<REDACTED>"),
    (re.compile(r"\bAKIA[A-Z0-9]{16}\b"), "<REDACTED-KEY>"),
    (re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?"
        r"-----END [A-Z ]*PRIVATE KEY-----"),
     "<REDACTED-PRIVATE-KEY>"),
    (re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
     "<REDACTED-JWT>"),
    (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "<REDACTED-HEX>"),
    (re.compile(r"\b[A-Za-z0-9+/_-]{40,}\b"), "<REDACTED-TOKEN>"),
]


def sanitize_evidence(text):
    t = str(text or "")
    for pat, repl in REDACT_PATTERNS:
        t = pat.sub(repl, t)
    return _clip(t, 400)


def _subst(text, **kw):
    out = str(text or "")
    for k, v in kw.items():
        if v is not None:
            out = out.replace("{{" + k.upper() + "}}", str(v))
    return out


def _looks_html(text):
    head = (text or "")[:2000].lower()
    return "<html" in head or "<body" in head or "<!doctype html" in head


def _decode_body(body, headers):
    if not body:
        return ""
    m = re.search(r"charset=[\"']?([\w\-]+)",
                  headers.get("content-type", ""), re.I)
    candidates = ([m.group(1)] if m else []) + \
                 ["utf-8", "windows-1252", "latin-1"]
    for enc in candidates:
        try:
            return body.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return body.decode("utf-8", "replace")


def _dns_or_conn(e):
    s = str(e).lower()
    if ("getaddrinfo" in s or "name or service not known" in s
            or "nodename nor servname provided" in s
            or "temporary failure in name resolution" in s):
        return "DNS resolution failed"
    return "connection failed"


def _tag_attr(src, name):
    m = re.search(
        r"(?is)\b" + re.escape(name) +
        r"\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", src)
    if not m:
        return ""
    return m.group(1) or m.group(2) or m.group(3) or ""


def _fmt_duration(sec):
    if sec >= 90:
        return str(int(sec // 60)) + "m " + str(int(sec % 60)) + "s"
    return str(round(sec, 1)) + "s"


def _wrap(text, indent="     ", width=None):
    if width is None:
        width = min(shutil.get_terminal_size((100, 30)).columns, 100)
    usable = max(width - len(indent), 40)
    out = []
    for line in str(text or "").split("\n"):
        if not line.strip():
            out.append("")
            continue
        out.extend(textwrap.wrap(line, width=usable) or [""])
    return "\n".join(indent + ln if ln else indent.rstrip() + ""
                     for ln in out)


def _windows_system_proxy():
    if os.name != "nt":
        return None
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
        try:
            enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
        except Exception:
            enable = 0
        try:
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
        except Exception:
            server = ""
        winreg.CloseKey(key)
        if not enable:
            return None
        server = str(server or "").strip()
        if not server:
            return None
        if "=" not in server:
            return server if "://" in server else "http://" + server
        for part in server.split(";"):
            k, _, v = part.partition("=")
            v = v.strip()
            if not v:
                continue
            if k.strip().lower() in ("https", "http"):
                return v if "://" in v else "http://" + v
        return None
    except Exception:
        return None


def _env_proxy_set():
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
              "ALL_PROXY", "all_proxy"):
        if os.environ.get(k):
            return True
    return False


# ---------------------------------------------------------------------------
# URL validation, normalization, deduplication
# ---------------------------------------------------------------------------
def normalize_url(raw):
    raw = (raw or "").strip().rstrip(".,;:!")
    if not raw:
        return None, "No URL entered."
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", raw):
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", raw):
            return None, "Only http and https URLs are supported."
        raw = "https://" + raw
    try:
        p = urlsplit(raw)
    except ValueError as e:
        return None, "Invalid URL (" + _clip(str(e), 60) + ")."
    if p.scheme.lower() not in ("http", "https"):
        return None, "Only http and https URLs are supported."
    if not p.netloc:
        return None, "URL has no host (example: https://example.com)."
    if p.username or p.password:
        return None, "URLs with embedded credentials are not supported."
    host = (p.hostname or "").lower()
    if not host:
        return None, "URL has no host."
    try:
        port = p.port
    except ValueError:
        return None, "Invalid port number."
    if host != "localhost" and not host.endswith(".localhost"):
        if not re.match(
                r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?"
                r"(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$", host):
            return None, ("'" + _clip(host, 60) +
                          "' does not look like a valid domain name.")
    default_port = (p.scheme.lower() == "https" and port == 443) or \
                   (p.scheme.lower() == "http" and port == 80)
    netloc = host if (port is None or default_port) else host + ":" + str(port)
    return urlunsplit((p.scheme.lower(), netloc, p.path or "/",
                       p.query, "")), None


# Tracking parameters are dropped for DEDUPLICATION only; the actual
# requests always keep the full original query string.
TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term",
                   "utm_content", "gclid", "fbclid", "msclkid"}


def url_key(url):
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return url
    host = (p.hostname or "").lower()
    host = host[4:] if host.startswith("www.") else host
    default = (p.scheme == "https" and port == 443) or \
              (p.scheme == "http" and port == 80)
    netloc = host if (port is None or default) else host + ":" + str(port)
    q = [(k.lower(), v) for k, v in parse_qsl(p.query, keep_blank_values=True)
         if k.lower() not in TRACKING_PARAMS]
    # v2.2 FIX (E): repeated identical pairs collapse for dedup only.
    q = sorted(set(q))
    return (p.scheme + "://" + netloc + (p.path or "/") +
            (("?" + urlencode(q)) if q else ""))


def _clean_url(u):
    try:
        p = urlsplit(u)
        return urlunsplit((p.scheme.lower(), p.netloc.lower(),
                           p.path or "/", p.query, ""))
    except ValueError:
        return u


def _strip_www(h):
    return h[4:] if h.startswith("www.") else h


def host_in_scope(host, scope_hosts):
    host = (host or "").lower()
    if not host:
        return False
    return any(_strip_www(host) == _strip_www(s) for s in scope_hosts)


def is_template_placeholder(u):
    # ${fileUrl} / {{url}} / percent-encoded forms are JS template
    # placeholders: crawler artifacts, never findings.
    u = u or ""
    return ("${" in u or "%24%7B" in u or "{{" in u or "%7B%7B" in u)


def extract_links(text, base_url):
    hrefs = A_HREF_RE.findall(text or "")
    seen, out = set(), []
    for h in hrefs:
        h = (h or "").strip()
        if not h or h.startswith("#"):
            continue
        # v2.2 FIX (B): HTML-escaped hrefs must be unescaped before use,
        # otherwise the crawler requests literal "&amp;" URLs.
        h = _htmllib.unescape(h)
        if is_template_placeholder(h):
            continue
        if h.lower().startswith(("mailto:", "tel:", "javascript:",
                                 "data:", "ftp:")):
            continue
        try:
            absu = urljoin(base_url, h)
            p = urlsplit(absu)
        except ValueError:
            continue
        if p.scheme not in ("http", "https") or not p.netloc or len(absu) > 1800:
            continue
        k = url_key(absu)
        if k in seen:
            continue
        seen.add(k)
        out.append(_clean_url(absu))
    return out


# ---------------------------------------------------------------------------
# Pure detection logic (unit-testable without any network)
# ---------------------------------------------------------------------------
def classify_headers(headers, https_page):
    # Each missing header is its own finding; HSTS is only expected on
    # HTTPS pages; frame-ancestors inside CSP suppresses the XFO finding
    # (same root cause, no duplicate).
    h = {str(k).lower(): v for k, v in (headers or {}).items()}
    missing = []
    if https_page and "strict-transport-security" not in h:
        missing.append("hsts_missing")
    csp = h.get("content-security-policy", "")
    if not csp:
        missing.append("csp_missing")
    if "x-frame-options" not in h and "frame-ancestors" not in csp.lower():
        missing.append("xfo_missing")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        missing.append("xcto_missing")
    if "referrer-policy" not in h:
        missing.append("referrer_missing")
    if "permissions-policy" not in h:
        missing.append("perms_missing")
    return missing


def classify_banners(headers):
    h = {str(k).lower(): v for k, v in (headers or {}).items()}
    out = []
    srv = h.get("server", "")
    if srv and re.search(r"\d", srv):
        out.append(("server_banner", "Server", srv))
    for hdr in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                "x-generator", "x-drupal-cache"):
        v = h.get(hdr)
        if v:
            out.append(("tech_banner", hdr, v))
    return out


def probe_hit(status, body, sigs, allow_html):
    # Direct 200 + signature match + (for non-HTML files) body must not
    # look like an HTML error/home page. Redirects never count.
    if status != 200 or not body:
        return False
    if not any(s in body[:200000] for s in sigs):
        return False
    if not allow_html and _looks_html(body[:2000].decode("utf-8", "replace")):
        return False
    return True


def admin_hit(status, body, markers):
    if status != 200 or not body:
        return False
    low = body[:200000].lower()
    return any(m in low for m in markers)


def port_is_notable(port):
    return port in NOTABLE_PORTS


def page_finding_eligible(status):
    # v2.2 FIX (A): error responses (404/410/5xx) are custom error pages
    # whose headers are not representative of the site - findings must
    # not be generated from them. 2xx and final 3xx are eligible.
    return 200 <= status < 400


def form_has_csrf_token(form_markup):
    # v2.2 FIX (D): markup-only heuristic. Absence of a visible token
    # proves nothing about server-side protection.
    return bool(CSRF_TOKEN_RE.search(form_markup or ""))


def csrf_finding_needed(method, form_markup):
    return method == "POST" and not form_has_csrf_token(form_markup)


def counters_from_records(records):
    # All page counters derive from ONE record list, so
    # discovered == scanned + skipped + failed + pending always holds.
    c = {"discovered": 0, "scanned": 0, "skipped": 0, "failed": 0,
         "pending": 0}
    for r in records:
        if r.kind != "page":
            continue
        c["discovered"] += 1
        if r.state in ("scanned", "skipped", "failed"):
            c[r.state] += 1
        else:
            c["pending"] += 1
    return c


def counters_consistent(c):
    return c["discovered"] == (c["scanned"] + c["skipped"] +
                               c["failed"] + c["pending"])


def apply_context(findings, login_form_seen):
    # Context-aware severity: raise hardening severity only when observed
    # site context justifies it.
    ids = set(f.check_id for f in findings)
    for f in findings:
        if f.check_id == "hsts_missing" and login_form_seen:
            f.severity = "Medium"
            f.note = ("A login form was observed on this site, so the "
                      "downgrade window matters more here.")
        if f.check_id == "csp_missing" and "xss_indicator" in ids:
            f.severity = "Medium"
            f.note = ("A reflection indicator was also found on this "
                      "site, so a policy would add real protection.")
    return findings


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class ResponseData:
    requested_url: str
    final_url: str = ""
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    set_cookies: List[str] = field(default_factory=list)
    body: bytes = b""
    text: str = ""
    content_type: str = ""
    elapsed: float = 0.0
    error: Optional[str] = None


@dataclass
class PageRecord:
    url: str
    key: str
    depth: int
    kind: str = "page"          # page | probe | admin
    state: str = "pending"      # pending | scanned | skipped | failed
    reason: str = ""
    status: int = 0
    elapsed: float = 0.0
    probe: Optional[dict] = None


@dataclass
class Finding:
    fid: str
    check_id: str
    cat: str                     # issue | potential | hardening | observation
    title: str
    severity: str
    verification: str            # Confirmed | Potential (of the OBSERVATION)
    confidence: str = "Medium"
    url: str = ""
    method: str = "GET"
    param: str = ""
    header: str = ""
    evidence: str = ""
    what: str = ""
    impact: str = ""
    fix: str = ""
    tech: str = ""
    lim: str = ""
    note: str = ""
    affected_urls: List[str] = field(default_factory=list)
    occurrences: int = 1


@dataclass
class ScanStats:
    requests: int = 0
    errors: int = 0
    retries: int = 0
    processed: int = 0
    duplicates: int = 0
    filtered: int = 0
    param_probes: int = 0


@dataclass
class ScanResult:
    url: str
    domain: str
    ip: str = ""
    reverse_dns: str = ""
    duration: float = 0.0
    records: List[PageRecord] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    findings: List[Finding] = field(default_factory=list)
    tls_version: str = ""
    open_ports: List[Tuple[int, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Catalogue. verif = whether the OBSERVATION itself was directly seen.
# cat decides report grouping: a confirmed observation is never presented
# as a confirmed vulnerability unless it is a real "issue".
# ---------------------------------------------------------------------------
CATALOG = {
    "no_https": dict(
        cat="issue", sev="High", conf="High", verif="Confirmed",
        title="Website Uses No Lock (Plain HTTP)",
        what="All traffic, including passwords and cookies, travels "
             "unencrypted and can be read or changed by anyone on the "
             "network path.",
        impact="Session hijacking, credential theft and content injection "
               "by anyone able to observe the traffic.",
        fix="Install a free certificate, serve HTTPS, redirect all HTTP "
            "requests to HTTPS, then add HSTS.",
        tech="Plain http requests completed successfully during the scan.",
        lim="Whether the same host also serves HTTPS was not tested."),
    "tls_invalid": dict(
        cat="issue", sev="High", conf="High", verif="Confirmed",
        title="Security Certificate Failed Validation",
        what="The website's certificate is broken, expired or issued for "
             "another name, so browsers will refuse or warn about it.",
        impact="Clients refuse the connection, and on networks that "
               "tolerate bad certificates an attacker can impersonate the "
               "site and capture credentials.",
        fix="Install a valid certificate from a trusted authority for this "
            "exact hostname, serve the full chain, automate renewal.",
        tech="A TLS handshake with certificate verification enabled "
             "failed; the error is in the evidence.",
        lim="The root cause (expired, self-signed, wrong name) was not "
            "diagnosed."),
    "tls_expiring": dict(
        cat="issue", sev="Medium", conf="High", verif="Confirmed",
        title="Security Certificate Expires Soon",
        what="The certificate runs out in less than 30 days. If nobody "
             "renews it, browsers will block the site until it is fixed.",
        impact="An expired certificate causes an effective outage: every "
               "browser shows a full-page warning.",
        fix="Renew now and enable automatic renewal with alerts at 30, 14 "
            "and 7 days before expiry.",
        tech="The notAfter date read from the live handshake is under 30 "
             "days away.",
        lim="Only the end date was checked."),
    "weak_tls": dict(
        cat="issue", sev="Medium", conf="High", verif="Confirmed",
        title="Old TLS Version In Use",
        what="The server still negotiates TLS 1.0 or 1.1, retired "
             "protocols that modern browsers refuse.",
        impact="Some visitors cannot connect at all, and downgrade attacks "
               "become more practical while legacy versions stay enabled.",
        fix="Disable TLS 1.0/1.1, allow only TLS 1.2 and 1.3, then verify "
            "with an external SSL scanner.",
        tech="The handshake negotiated the protocol shown in evidence.",
        lim="Cipher-suite strength was not audited."),
    "form_http_password": dict(
        cat="issue", sev="High", conf="High", verif="Confirmed",
        title="Password Form Without The Lock (HTTP)",
        what="A login form was found on a page or action served over "
             "plain HTTP, so passwords travel unencrypted.",
        impact="Anyone spying on the network can read the password letter "
               "by letter; login credentials are reused across sites.",
        fix="Serve the form and its action over HTTPS only, redirect HTTP "
            "permanently, and enable HSTS.",
        tech="Form markup containing a password input was observed on a "
             "plain-HTTP page.",
        lim="No credentials were submitted or captured."),
    "sql_error_passive": dict(
        cat="issue", sev="Medium", conf="High", verif="Confirmed",
        title="Database Error Text Shown To Visitors",
        what="The page displays a raw database error message, revealing "
             "the engine and often table and column names.",
        impact="Free reconnaissance for attackers planning SQL injection; "
               "also proves error output is not suppressed in production.",
        fix="Disable error display in production; log details server-side "
            "and show users only a generic message with a reference ID.",
        tech="The response body matched a database-engine error pattern.",
        lim="Which query failed and whether user input reaches it was not "
            "investigated."),
    "stack_trace": dict(
        cat="issue", sev="Medium", conf="High", verif="Confirmed",
        title="Internal Error Report Shown To Visitors",
        what="The page shows a stack trace or debug output - file paths, "
             "code names and framework versions.",
        impact="Attackers can map the application and target known "
               "weaknesses; visible traces often mean debug mode is on.",
        fix="Turn debug off in production, return generic error pages, "
            "log traces server-side with a correlation ID.",
        tech="The response body matched stack-trace or debug markers.",
        lim="The error was observed as delivered; it was not triggered "
            "deliberately."),
    "dir_listing": dict(
        cat="issue", sev="Medium", conf="High", verif="Confirmed",
        title="Folder Content List Shown",
        what="The server lists every file in a folder as clickable links, "
             "like an open catalogue.",
        impact="Forgotten backups and private files become directly "
               "downloadable and get indexed by search engines.",
        fix="Disable autoindexing (Options -Indexes in Apache, autoindex "
            "off in nginx) and add a neutral index page.",
        tech="The response markup is a server-generated directory index.",
        lim="Only one listed directory was observed; the tree was not "
            "crawled."),
    "mixed_content": dict(
        cat="issue", sev="Medium", conf="High", verif="Confirmed",
        title="Locked Page Loads Unlocked Parts",
        what="An HTTPS page references scripts, frames or images over "
             "plain http, so parts bypass the lock.",
        impact="Active mixed content is blocked by browsers (breaks "
               "features); passive content can be observed or replaced by "
               "an on-path attacker.",
        fix="Rewrite every reference to explicit https and add the CSP "
            "upgrade-insecure-requests directive.",
        tech="Static markup referenced http:// subresources on an HTTPS "
             "page.",
        lim="JavaScript-injected resources were not assessed."),
    "exposed_file": dict(
        cat="issue", sev="High", conf="Medium", verif="Confirmed",
        title="Sensitive File Publicly Served",
        what="A file that should be private (settings, backup, source "
             "history) is served to anyone who knows its address.",
        impact="Credentials, keys or whole databases inside such files "
               "must be treated as compromised and rotated immediately.",
        fix="Delete it from the server and all backups, rotate every "
            "secret it contained, and block dot-files at the edge.",
        tech="A GET returned a direct 200 whose body matched this file "
             "type's signature.",
        lim="The full contents were deliberately not read or validated."),
    "sqli_indicator": dict(
        cat="potential", sev="High", conf="Medium", verif="Potential",
        title="Possible SQL Injection (Indicator Only)",
        what="Adding one harmless quote to a parameter made the server "
             "return a database error - a strong sign, not proof, of SQL "
             "injection.",
        impact="If real: authentication bypass, reading, changing or "
               "deleting the whole database.",
        fix="Use prepared statements with placeholders for every query, "
            "validate input types, use a least-privilege DB account.",
        tech="One quote appended to {{PARAM}} produced a DB error string "
             "in the response.",
        lim="No payload was executed and no data extracted. Manual "
            "authorized verification required."),
    "xss_indicator": dict(
        cat="potential", sev="High", conf="Medium", verif="Potential",
        title="Possible Reflected XSS (Indicator Only)",
        what="Typed text in the {{PARAM}} parameter comes back on the "
             "page unchanged, which is the precondition for script "
             "injection.",
        impact="If real: an attacker link can run JavaScript in victims' "
               "browsers - cookie theft and phishing under your name.",
        fix="Encode output by context, keep template auto-escaping on, "
            "insert untrusted values as text, add a restrictive CSP.",
        tech="A benign marker appended to {{PARAM}} was reflected "
             "unencoded into the HTML.",
        lim="No script was executed; exploitability depends on context "
            "and filtering."),
    "cookie_secure": dict(
        cat="potential", sev="Medium", conf="High", verif="Confirmed",
        title="Cookie Can Be Sent Unlocked (No Secure Flag)",
        what="The browser may send this cookie over plain HTTP too, not "
             "just over the locked connection.",
        impact="If any http URL on this host is ever requested, the "
               "cookie crosses the network in cleartext and can be "
               "captured and replayed.",
        fix="Add the Secure flag to every cookie (framework option, e.g. "
            "SESSION_COOKIE_SECURE / secure=True).",
        tech="An observed Set-Cookie header omitted the Secure attribute.",
        lim="Exploitation needs an unencrypted request to actually occur; "
            "values are redacted from evidence."),
    "cookie_httponly": dict(
        cat="potential", sev="Medium", conf="High", verif="Confirmed",
        title="Cookie Readable By Scripts (No HttpOnly Flag)",
        what="JavaScript running in the page can read this cookie.",
        impact="If an attacker ever injects script, the cookie is handed "
               "over immediately - HttpOnly is the cheap containment "
               "layer for exactly that case.",
        fix="Add the HttpOnly flag to session cookies; enable the "
            "framework default and document any exceptions.",
        tech="An observed Set-Cookie header omitted the HttpOnly "
             "attribute.",
        lim="Impact requires a script-injection flaw to exist first."),
    "cookie_samesite": dict(
        cat="hardening", sev="Low", conf="Medium", verif="Confirmed",
        title="Cookie Missing SameSite Declaration",
        what="The cookie does not declare SameSite, so older browsers may "
             "attach it to cross-site requests.",
        impact="Reduces protection against cross-site request forgery on "
               "older clients; modern browsers default to Lax.",
        fix="Declare SameSite=Lax or Strict explicitly and pair it with "
            "server-side CSRF tokens.",
        tech="An observed Set-Cookie header omitted the SameSite "
             "attribute.",
        lim="Defaults vary by browser; endpoints were not tested "
            "cross-site."),
    "hsts_missing": dict(
        cat="hardening", sev="Low", conf="Medium", verif="Confirmed",
        title="Always-Use-HTTPS Rule Missing (HSTS)",
        what="The site does not tell browsers to remember HTTPS-only, so "
             "the first request of a visit can still be downgraded.",
        impact="An on-path attacker can convert an HTTPS bookmark into a "
               "plain HTTP request during that downgrade window.",
        fix="Add Strict-Transport-Security with a long max-age once HTTPS "
            "works on every path; ramp up from 300 seconds.",
        tech="The HTTPS response contained no Strict-Transport-Security "
             "header.",
        lim="Redirects may already force HTTPS; the attack needs an "
            "active man-in-the-middle. A Report-Only CSP or "
            "meta-delivered policy was not separately parsed."),
    "csp_missing": dict(
        cat="hardening", sev="Low", conf="Medium", verif="Confirmed",
        title="No Security Guard List (CSP Missing)",
        what="The page has no Content-Security-Policy limiting which "
             "scripts and endpoints may run.",
        impact="If an injection bug is ever introduced, nothing stops the "
               "injected code from running with full permissions.",
        fix="Deploy a restrictive CSP, start in Report-Only mode, add only "
            "needed origins, then enforce.",
        tech="The response contained no Content-Security-Policy header.",
        lim="A meta-element policy was not parsed; absence does not prove "
            "injectability."),
    "xfo_missing": dict(
        cat="hardening", sev="Low", conf="Medium", verif="Confirmed",
        title="Invisible-Frame Trick Not Blocked",
        what="Nothing tells browsers to refuse framing, so another site "
             "can embed this page invisibly.",
        impact="Clickjacking: tricking a logged-in visitor into clicking "
               "invisible buttons (needs state-changing UI to matter).",
        fix="Send X-Frame-Options: DENY and CSP frame-ancestors 'none'.",
        tech="Neither X-Frame-Options nor CSP frame-ancestors present.",
        lim="Purely informational pages carry little risk."),
    "xcto_missing": dict(
        cat="hardening", sev="Low", conf="Medium", verif="Confirmed",
        title="Browser File-Type Guessing Allowed",
        what="Without nosniff, browsers may guess the content type of "
             "responses instead of trusting the label.",
        impact="A mislabelled uploaded file could be executed as script "
               "on some clients.",
        fix="Add X-Content-Type-Options: nosniff on every response and "
            "serve uploads with correct types.",
        tech="The response lacked X-Content-Type-Options: nosniff.",
        lim="Needs user-controlled files to matter; static pages are "
            "essentially unaffected."),
    "referrer_missing": dict(
        cat="hardening", sev="Low", conf="Medium", verif="Confirmed",
        title="Page Address Can Leak To Other Sites",
        what="Without a Referrer-Policy, browsers may hand the full "
             "previous URL (including query string) to other sites.",
        impact="Tokens, search terms or identifiers in URLs leak to third "
               "parties when users click outbound links.",
        fix="Add Referrer-Policy: strict-origin-when-cross-origin; use "
            "no-referrer on URLs containing secrets.",
        tech="The response lacked a Referrer-Policy header.",
        lim="Real leakage needs sensitive parameters to exist; browsers "
            "are moving to stricter defaults anyway."),
    "perms_missing": dict(
        cat="hardening", sev="Informational", conf="Low",
        verif="Confirmed",
        title="Unused Browser Powers Not Switched Off",
        what="No Permissions-Policy disables camera, microphone or "
             "location features the site does not use.",
        impact="If bad code is ever injected, it could quietly request "
               "those features.",
        fix="Add a Permissions-Policy disabling unused features, e.g. "
            "camera=(), microphone=(), geolocation=().",
        tech="The response lacked a Permissions-Policy header.",
        lim="Impact depends on which features the site or embeds request; "
            "many sites legitimately skip this header."),
    "server_banner": dict(
        cat="hardening", sev="Informational", conf="High",
        verif="Confirmed",
        title="Server Name And Version Shown",
        what="The server announces its software and version - like "
             "printing your lock's brand on the gate.",
        impact="Attackers can look up known break-in tricks for that "
               "exact version without probing the live service.",
        fix="Hide the version (server_tokens off in nginx, "
            "ServerSignature Off in Apache); keep software patched.",
        tech="A Server header with version digits was observed.",
        lim="The version was not checked against specific CVEs; not a "
            "vulnerability by itself."),
    "tech_banner": dict(
        cat="hardening", sev="Informational", conf="High",
        verif="Confirmed",
        title="Programming Tool Version Shown",
        what="A header such as X-Powered-By reveals the language or "
             "framework and its version.",
        impact="Hands attackers a precise CVE target list before they "
               "touch the site.",
        fix="Remove the header at the app or proxy (expose_php = Off "
            "etc.); track advisories regardless.",
        tech="A technology-disclosure header was observed.",
        lim="Not a vulnerability by itself; stacks remain fingerprintable "
            "other ways, and no concrete risk was established here."),
    "form_csrf": dict(
        cat="potential", sev="Low", conf="Low", verif="Potential",
        title="Form May Be Submittable By Other Sites",
        what="No token-like hidden input was found in a POST form's "
             "markup.",
        impact="If server-side protection is also missing, another site "
               "can submit this form with the victim's cookies attached.",
        fix="Enable the framework's CSRF middleware and verify tokens "
            "server-side on every state-changing POST.",
        tech="A POST form without a token-like hidden input was observed.",
        lim="Markup-only heuristic: server-side CSRF protection CANNOT be "
            "verified from static HTML - frameworks commonly protect "
            "forms via cookie/header tokens invisible in markup. Manual "
            "review required."),
    "open_port": dict(
        cat="observation", sev="Informational", conf="High",
        verif="Confirmed",
        title="Port {{PARAM}} Reachable From The Internet",
        what="The server answered a TCP connection on this port from the "
             "outside. This is a reachability fact only.",
        impact="An open port is NOT a verified vulnerability and no "
               "service details were read. Publicly reachable database or "
               "legacy ports are, however, frequently targeted by "
               "password guessing - whether that applies here was NOT "
               "tested.",
        fix="If the service is only needed internally, bind it to "
            "localhost or block it in the firewall; otherwise verify "
            "strong authentication and lockout rules yourself.",
        tech="A TCP connect to the port succeeded.",
        lim="Authentication, service version and firewalling behind the "
            "port were not tested; no credentials were attempted."),
    "admin_panel": dict(
        cat="observation", sev="Informational", conf="High",
        verif="Confirmed",
        title="Admin Login Page Publicly Reachable ({{PATH}})",
        what="An administrative login page answers directly (no redirect) "
             "to anyone on the internet.",
        impact="A public login page is NOT a vulnerability by itself - "
               "most sites have one. It only becomes a problem if access "
               "control behind it is weak; that was not and cannot be "
               "safely tested here. Expect automated password-guessing "
               "traffic like any public login.",
        fix="Good practice, not a bug fix: restrict by IP or VPN if "
            "feasible, add rate-limiting and lockout, enable two-factor "
            "login, keep the admin component patched.",
        tech="The path returned a direct 200 whose markup contains login "
             "markers such as a password field.",
        lim="No login or bypass was attempted; authentication strength is "
            "unknown."),
    "robots_reveal": dict(
        cat="observation", sev="Informational", conf="High",
        verif="Confirmed",
        title="robots.txt Lists Hidden Paths",
        what="The public robots.txt names paths kept away from search "
             "engines - a signpost anyone can read.",
        impact="None by itself; it advertises where interesting areas "
               "might be, but listing a path protects nothing and "
               "exposing the list breaks nothing.",
        fix="Never rely on robots.txt for protection; remove entries that "
            "name sensitive locations and give those real access control.",
        tech="Disallow entries were read from robots.txt.",
        lim="Listed paths were not individually probed beyond normal "
            "crawling."),
    "broken_link": dict(
        cat="observation", sev="Informational", conf="High",
        verif="Confirmed",
        title="Broken Internal Link (HTTP {{PARAM}})",
        what="A link on the site points to a page of the same site that "
             "returns an error status.",
        impact="No direct security impact; indicates stale content and "
               "poor hygiene, and error pages sometimes leak stack traces "
               "(which this scanner checks separately when they are "
               "served).",
        fix="Fix or remove the link; add automated link checking to the "
            "build or CMS workflow.",
        tech="A crawl-discovered link target returned the error status "
             "shown; the source page contained the href.",
        lim="Only hard error statuses are detected; soft 404s (HTTP 200 "
            "with an error page) are not recognized."),
}


def _verify_catalog():
    problems = []
    for key, c in CATALOG.items():
        for fld in ("cat", "sev", "conf", "verif", "title", "what",
                    "impact", "fix", "tech", "lim"):
            if not c.get(fld):
                problems.append(key + "." + fld)
        if c.get("cat") not in CATEGORIES:
            problems.append(key + ".cat")
        if c.get("sev") not in SEV_ORDER:
            problems.append(key + ".sev")
        if c.get("verif") not in ("Confirmed", "Potential"):
            problems.append(key + ".verif")
        if len(c.get("what", "")) < 40:
            problems.append(key + ".short")
    if problems:
        uprint(STY.red("[!] INTEGRITY WARNING: incomplete catalogue: "
                       + ", ".join(problems)))
        uprint(STY.red("    The file copy looks incomplete - re-copy the "
                       "whole file."))
    return not problems


# ---------------------------------------------------------------------------
# Rate limiter (per-host pacing)
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, min_interval):
        self._min = min_interval
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self._min
            delay = start - now
        if delay > 0:
            time.sleep(delay)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
class Scanner:
    def __init__(self, raw_url):
        url, err = normalize_url(raw_url)
        if err or not url:
            raise ValueError(err or "invalid URL")
        self.url = url
        p = urlsplit(url)
        self.host = (p.hostname or "").lower()
        self.port = p.port or (443 if p.scheme == "https" else 80)
        self.scheme = p.scheme
        self.scope = {self.host}
        if self.host.startswith("www."):
            self.scope.add(self.host[4:])
        else:
            self.scope.add("www." + self.host)
        self.ip = ""
        self.reverse_dns = ""
        self.login_form_seen = False

        self.lock = threading.Lock()
        self._rate = RateLimiter(MIN_REQUEST_INTERVAL)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT,
                                     "Accept": "*/*"})
        try:
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=MAX_WORKERS, pool_maxsize=MAX_WORKERS)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
        except Exception:
            pass

        self.proxy_info = ""
        if not _env_proxy_set():
            chosen = _windows_system_proxy()
            if chosen:
                self.session.proxies = {"http": chosen, "https": chosen}
                self.proxy_info = ("[i] Using Windows system proxy: "
                                   + chosen)

        self.queue = deque()
        self.seen = set()
        self.scanned_keys = set()
        self.records = []
        self.findings = []
        self._finding_map = {}
        self.stats = ScanStats()
        self.stop = False
        self._any_http = False
        self.sitemap_count = 0
        self.page_count = 0
        self.tls_version = ""
        self.open_ports = []
        self._http_ok = False
        self._t0 = 0.0
        self._ipv4_active = False
        self._orig_getaddrinfo = None

    def _enable_ipv4_mode(self):
        if self._ipv4_active:
            return
        orig = socket.getaddrinfo

        def _ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
            try:
                return orig(host, port, socket.AF_INET, type, proto, flags)
            except socket.gaierror:
                return orig(host, port, family, type, proto, flags)

        socket.getaddrinfo = _ipv4_only
        self._orig_getaddrinfo = orig
        self._ipv4_active = True

    def _restore_dns(self):
        if self._ipv4_active and self._orig_getaddrinfo is not None:
            socket.getaddrinfo = self._orig_getaddrinfo
            self._ipv4_active = False
            self._orig_getaddrinfo = None

    def _fetch_once(self, url, method, allow_redirects):
        rd = ResponseData(requested_url=url, final_url=url)
        self._rate.wait()
        with self.lock:
            self.stats.requests += 1
        try:
            r = self.session.request(
                method, url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                stream=True, allow_redirects=allow_redirects)
            try:
                rd.set_cookies = list(
                    r.raw.headers.get_all("Set-Cookie") or [])
            except Exception:
                sc = r.headers.get("set-cookie", "")
                rd.set_cookies = [sc] if sc else []
            try:
                chunks, size, truncated = [], 0, False
                for chunk in r.iter_content(65536):
                    if chunk:
                        chunks.append(chunk)
                        size += len(chunk)
                        if size >= MAX_CONTENT_BYTES:
                            truncated = True
                            break
                body = b"".join(chunks)[:MAX_CONTENT_BYTES]
            finally:
                r.close()
            rd.status = r.status_code
            rd.headers = {k.lower(): v for k, v in r.headers.items()}
            rd.body = body
            rd.text = _decode_body(body, rd.headers)
            rd.content_type = rd.headers.get("content-type", "")
            rd.elapsed = r.elapsed.total_seconds()
            rd.final_url = r.url or url
            if truncated:
                rd.text = _clip(rd.text, 500000)
            if rd.requested_url.lower().startswith("http://"):
                self._http_ok = True
            return rd
        except requests.exceptions.Timeout:
            rd.error = "request timed out"
        except requests.exceptions.SSLError as e:
            rd.error = "TLS error: " + _clip(
                str(e).split(":")[-1].strip() or "SSL failure", 60)
        except requests.exceptions.ConnectionError as e:
            rd.error = _dns_or_conn(e)
        except requests.exceptions.TooManyRedirects:
            rd.error = "redirect loop"
        except requests.exceptions.RequestException as e:
            rd.error = _clip("request failed: " + str(e), 80)
        if rd.error:
            with self.lock:
                self.stats.errors += 1
        return rd

    def fetch(self, url, method="GET", allow_redirects=True):
        # Bounded retry: one extra attempt for transient transport errors,
        # under a global budget. HTTP 4xx/5xx are NOT retried.
        rd = self._fetch_once(url, method, allow_redirects)
        if rd.error in ("request timed out", "connection failed"):
            can_retry = False
            with self.lock:
                if self.stats.retries < MAX_RETRIES_TOTAL:
                    self.stats.retries += 1
                    can_retry = True
            if can_retry:
                rd = self._fetch_once(url, method, allow_redirects)
        return rd

    def add_finding(self, check_id, url, evidence="", param="",
                    header="", method="GET", title=None, sev=None):
        c = CATALOG[check_id]
        key = (check_id, param, header)
        with self.lock:
            f = self._finding_map.get(key)
            if f is not None:
                f.occurrences += 1
                if url and url not in f.affected_urls \
                        and len(f.affected_urls) < 10:
                    f.affected_urls.append(url)
                return f
            f = Finding(
                fid="F" + str(len(self.findings) + 1).zfill(3),
                check_id=check_id, cat=c["cat"],
                title=title or c["title"],
                severity=sev or c["sev"],
                verification=c["verif"], confidence=c["conf"],
                url=url, method=method, param=param, header=header,
                evidence=sanitize_evidence(evidence),
                what=c["what"], impact=c["impact"], fix=c["fix"],
                tech=_subst(c["tech"], param=param, path=param),
                lim=_subst(c["lim"], param=param, path=param))
            self.findings.append(f)
            self._finding_map[key] = f
        uprint(sev_color(f.severity)(
            "[" + f.cat[:4].upper() + "] " + _clip(url, 80) + " - " +
            f.title + " [" + f.severity + "]"))
        return f

    def enqueue(self, url, depth, kind="page", probe=None):
        # Returns "queued" | "dup" | "filtered" so counters stay exact.
        url = _clean_url(url)
        if is_template_placeholder(url):
            with self.lock:
                self.stats.filtered += 1
            return "filtered"
        key = url_key(url)
        with self.lock:
            if key in self.seen:
                self.stats.duplicates += 1
                return "dup"
            if len(self.seen) >= MAX_DISCOVERED:
                self.stats.filtered += 1
                return "filtered"
            if kind == "page":
                p = urlsplit(url)
                if not host_in_scope(p.hostname or "", self.scope):
                    self.stats.filtered += 1
                    return "filtered"
                path = (p.path or "/").lower()
                if os.path.splitext(path)[1] in SKIP_EXTENSIONS:
                    self.stats.filtered += 1
                    return "filtered"
                if any(seg in EXCLUDED_SEGMENTS for seg in path.split("/")):
                    self.stats.filtered += 1
                    return "filtered"
                if depth > MAX_DEPTH or self.page_count >= MAX_PAGES:
                    self.stats.filtered += 1
                    return "filtered"
                self.page_count += 1
            pr = PageRecord(url=url, key=key, depth=depth, kind=kind,
                            probe=probe)
            self.seen.add(key)
            self.queue.append(pr)
            self.records.append(pr)
            return "queued"

    # -- DNS -------------------------------------------------------------
    def check_dns(self):
        uprint("")
        uprint(STY.bold(STY.cyan("--- DNS & IP ---")))
        try:
            self.ip = socket.gethostbyname(self.host)
            uprint("  Host : " + self.host)
            uprint("  IP   : " + self.ip)
            try:
                rev = socket.gethostbyaddr(self.ip)
                self.reverse_dns = rev[0]
                uprint("  Name : " + rev[0])
            except Exception:
                pass
        except Exception as e:
            uprint(STY.red("  DNS failed: " + _clip(str(e), 80)))

    # -- Threaded port reachability ----------------------------------------
    def check_ports(self):
        uprint("")
        uprint(STY.bold(STY.cyan("--- Port Reachability ---")))
        if not self.ip:
            try:
                self.ip = socket.gethostbyname(self.host)
            except Exception:
                uprint(STY.yellow("  Skipped: no IP resolved."))
                return

        def _probe(prt):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(PORT_TIMEOUT)
                ok = s.connect_ex((self.ip, prt)) == 0
                s.close()
                return prt if ok else None
            except Exception:
                return None

        open_found = []
        with ThreadPoolExecutor(max_workers=13) as ex:
            for res in ex.map(_probe, sorted(COMMON_PORTS)):
                if res is not None:
                    open_found.append((res, COMMON_PORTS[res]))
        self.open_ports = open_found
        if not open_found:
            uprint("  No common ports answered.")
            return
        for prt, svc in open_found:
            uprint("  Port " + str(prt) + " (" + svc + ") answered")
        for prt, svc in open_found:
            if port_is_notable(prt):
                self.add_finding(
                    "open_port", self.url,
                    evidence=("TCP connect to port " + str(prt) +
                              " (" + svc + ") succeeded from outside. "
                              "Reachability only - no service details "
                              "were read and no login was attempted."),
                    param=str(prt) + " " + svc, method="TCP",
                    title="Port " + str(prt) + " (" + svc +
                          ") Reachable From The Internet")

    # -- SSL / TLS ----------------------------------------------------------
    def check_ssl(self):
        uprint("")
        uprint(STY.bold(STY.cyan("--- SSL / Certificate ---")))
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.host, 443),
                                          timeout=10) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.host) as ts:
                    self.tls_version = ts.version() or ""
                    cert = ts.getpeercert() or {}
            if self.tls_version in ("TLSv1", "TLSv1.1"):
                self.add_finding(
                    "weak_tls", self.url,
                    evidence="Negotiated: " + self.tls_version,
                    title="Old TLS Version (" + self.tls_version + ")")
            else:
                uprint("  TLS version : " + self.tls_version)
            expiry_str = cert.get("notAfter", "")
            if expiry_str:
                try:
                    expiry = datetime.strptime(
                        expiry_str, "%b %d %H:%M:%S %Y %Z")
                    now_utc = datetime.now(timezone.utc).replace(
                        tzinfo=None)
                    days = (expiry - now_utc).days
                    uprint("  Certificate : expires " + expiry_str +
                           " (" + str(days) + " days)")
                    if days < 0:
                        self.add_finding(
                            "tls_invalid", self.url,
                            evidence=("Expired " + str(abs(days)) +
                                      " days ago (" + expiry_str + ")."),
                            title="Certificate EXPIRED")
                    elif days < 30:
                        self.add_finding(
                            "tls_expiring", self.url,
                            evidence=("Expires in " + str(days) +
                                      " days (" + expiry_str + ")."),
                            title="Certificate Expires In " +
                                  str(days) + " Days")
                except ValueError:
                    pass
            subj = dict(x[0] for x in cert.get("subject", []))
            iss = dict(x[0] for x in cert.get("issuer", []))
            if subj.get("commonName"):
                uprint("  Issued to   : " + subj["commonName"])
            if iss.get("organizationName") or iss.get("commonName"):
                uprint("  Issuer      : " +
                       (iss.get("organizationName") or
                        iss.get("commonName")))
        except ssl.SSLCertVerificationError as e:
            self.add_finding("tls_invalid", self.url, evidence=str(e),
                             title="Certificate Failed Validation")
        except Exception as e:
            msg = _clip(str(e), 80)
            if "timed out" in msg.lower() or "refused" in msg.lower():
                uprint(STY.yellow("  Port 443 not reachable - no HTTPS."))
            else:
                uprint(STY.yellow("  SSL check skipped: " + msg))

    # -- Connectivity: 3 escalating attempts --------------------------------
    def _connectivity_check(self):
        global CONNECT_TIMEOUT, READ_TIMEOUT
        uprint(STY.dim("[i] Connectivity check: " + self.url))
        rd = self.fetch(self.url)
        if rd.error is None:
            self._any_http = True
            uprint(STY.green("[i] Target reachable - HTTP " +
                             str(rd.status)))
            return True
        last_error = rd.error
        uprint(STY.yellow("[i] Attempt 1 failed (" + rd.error +
                          ") - retrying with 25s timeout..."))
        old_ct, old_rt = CONNECT_TIMEOUT, READ_TIMEOUT
        CONNECT_TIMEOUT, READ_TIMEOUT = 25, 40
        try:
            rd = self.fetch(self.url)
            if rd.error is None:
                self._any_http = True
                uprint(STY.green("[i] Reachable on retry - HTTP " +
                                 str(rd.status)))
                uprint(STY.cyan("[i] Slow server - long timeouts kept."))
                return True
            last_error = rd.error
            uprint(STY.yellow("[i] Attempt 2 failed (" + rd.error +
                              ") - trying IPv4-only mode..."))
            self._enable_ipv4_mode()
            rd = self.fetch(self.url)
            if rd.error is None:
                self._any_http = True
                uprint(STY.green("[i] Reachable in IPv4-only mode - HTTP " +
                                 str(rd.status)))
                uprint(STY.cyan("[i] IPv6 looks broken; using IPv4."))
                return True
            last_error = rd.error
        finally:
            if last_error is not None:
                CONNECT_TIMEOUT, READ_TIMEOUT = old_ct, old_rt
                self._restore_dns()
        uprint()
        uprint(STY.red("=" * 70))
        uprint(STY.red(" TARGET UNREACHABLE - scan stopped"))
        uprint(STY.red("=" * 70))
        uprint(" Final error : " + last_error)
        uprint(" Even a 25-second timeout and IPv4 mode failed, so the")
        uprint(" site is most likely down or blocking you.")
        uprint(" 1. Open the URL in a browser; if that also fails, the")
        uprint("    site itself is down - try again later.")
        uprint(" 2. If the browser works, allow python.exe in Windows")
        uprint("    Security > Firewall and check your antivirus.")
        uprint(STY.red("=" * 70))
        return False

    def run(self):
        self._t0 = time.monotonic()
        if not self._connectivity_check():
            self._restore_dns()
            return None
        self.check_dns()
        self.check_ports()
        self.check_ssl()
        self._seed()
        if self.stop:
            self._restore_dns()
            return None
        ex = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        try:
            self._crawl(ex)
        except KeyboardInterrupt:
            self.stop = True
            return None
        finally:
            try:
                ex.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                ex.shutdown(wait=False)
            self._restore_dns()
            for pr in self.queue:
                if pr.state == "pending":
                    pr.state = "skipped"
                    pr.reason = "scan aborted before this URL was reached"
        if not self.stop and self.scheme == "http" and self._http_ok:
            self.add_finding(
                "no_https", self.url,
                evidence=("Plain-HTTP requests completed successfully "
                          "during the scan."),
                title="Website Uses No Lock (Plain HTTP)")
        apply_context(self.findings, self.login_form_seen)
        return ScanResult(url=self.url, domain=self.host, ip=self.ip,
                          reverse_dns=self.reverse_dns,
                          duration=time.monotonic() - self._t0,
                          records=list(self.records), stats=self.stats,
                          findings=list(self.findings),
                          tls_version=self.tls_version,
                          open_ports=list(self.open_ports))

    def _seed(self):
        self.enqueue(self.url, 0)
        robots_url = urljoin(self.url, "/robots.txt")
        rd = self.fetch(robots_url)
        if rd.error:
            uprint(STY.cyan("[i] robots.txt - " + rd.error))
        elif rd.status == 200 and not _looks_html(rd.text):
            text = rd.text[:100000]
            disallow = re.findall(r"(?im)^disallow:\s*(\S+)", text)
            sms = re.findall(r"(?im)^sitemap:\s*(\S+)", text)
            uprint(STY.cyan("[i] robots.txt 200 (" +
                            str(round(rd.elapsed, 2)) + "s) - " +
                            str(len(disallow)) + " disallow, " +
                            str(len(sms)) + " sitemap entries"))
            if disallow:
                self.add_finding(
                    "robots_reveal", robots_url,
                    evidence="Disallow entries: " +
                             ", ".join(disallow[:12]),
                    title="robots.txt Lists Hidden Paths")
            for sm in sms[:MAX_SITEMAPS]:
                self._load_sitemap(sm.strip())
        else:
            uprint(STY.cyan("[i] robots.txt " + str(rd.status)))
        for spec in SENSITIVE_PROBES:
            self.enqueue(urljoin(self.url, spec["path"]), 0,
                         kind="probe", probe=spec)
        for spec in ADMIN_PROBES:
            self.enqueue(urljoin(self.url, spec["path"]), 0,
                         kind="admin", probe=spec)

    def _load_sitemap(self, sm_url):
        if self.sitemap_count >= MAX_SITEMAPS or self.stop:
            return
        self.sitemap_count += 1
        rd = self.fetch(sm_url)
        if rd.error or rd.status != 200:
            return
        uprint(STY.cyan("[i] sitemap parsed: " + _clip(sm_url, 70)))
        locs = re.findall(r"(?is)<loc>\s*([^<\s]+)\s*</loc>",
                          rd.text[:2000000])
        added = 0
        for loc in locs:
            loc = _htmllib.unescape(loc.strip())
            low = loc.lower()
            if low.endswith(".xml") and "sitemap" in low:
                self._load_sitemap(loc)
                continue
            if self.enqueue(loc, 0) == "queued":
                added += 1
            if added >= 250 or self.stop:
                break

    def _crawl(self, ex):
        while not self.stop:
            with self.lock:
                batch = []
                while self.queue and len(batch) < 128:
                    batch.append(self.queue.popleft())
            if not batch:
                break
            futures = [ex.submit(self._process_page, pr) for pr in batch]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception:
                    pass
            with self.lock:
                processed = self.stats.processed
            if processed >= 8 and not self._any_http and not self.stop:
                uprint(STY.red("[!] Target stopped responding - aborting."))
                self.stop = True
                break

    def _process_page(self, pr):
        if self.stop:
            pr.state = "skipped"
            pr.reason = "scan aborted"
            return
        try:
            self._process_page_inner(pr)
        except Exception as e:
            pr.state = "failed"
            pr.reason = "internal error: " + _clip(str(e), 80)

    def _process_page_inner(self, pr):
        # Probes/admin checks never follow redirects: a 301 to the
        # homepage must not count as an exposed file or admin panel.
        follow = pr.kind == "page"
        rd = self.fetch(pr.url, allow_redirects=follow)
        with self.lock:
            self.stats.processed += 1
            n = self.stats.processed
            total = len(self.seen)
        if rd.error is None:
            self._any_http = True
        if rd.error:
            pr.state = "failed"
            pr.reason = rd.error
            uprint("[" + str(n) + "/" + str(total) + "] " +
                   STY.red("[x] " + _clip(pr.url, 90) + " - " + rd.error))
            return
        pr.status = rd.status
        pr.elapsed = rd.elapsed
        if pr.kind == "probe":
            self._handle_probe(pr, rd, n, total)
            return
        if pr.kind == "admin":
            self._handle_admin(pr, rd, n, total)
            return
        fk = url_key(rd.final_url or pr.url)
        with self.lock:
            dup = fk in self.scanned_keys and fk != pr.key
            self.scanned_keys.add(fk)
        if dup:
            pr.state = "skipped"
            pr.reason = "duplicate content (redirect target already scanned)"
            uprint("[" + str(n) + "/" + str(total) + "] " +
                   STY.yellow("[~] " + _clip(pr.url, 90) + " - " +
                              pr.reason))
            return
        if rd.status in (401, 403):
            pr.state = "skipped"
            pr.reason = "HTTP " + str(rd.status) + " (needs login)"
            uprint("[" + str(n) + "/" + str(total) + "] " +
                   STY.yellow("[~] " + _clip(pr.url, 90) + " - " +
                              pr.reason))
            return

        # v2.2 FIX (A): error pages are counted as scanned, links are
        # still extracted, but NO findings are generated from them, and
        # v2.2 FIX (C): crawl-discovered error targets become one
        # aggregated broken_link observation.
        if not page_finding_eligible(rd.status):
            pr.state = "scanned"
            pr.reason = ("HTTP " + str(rd.status) +
                         " (error page - checks skipped)")
            if pr.depth > 0:
                self.add_finding(
                    "broken_link", pr.url,
                    evidence=("Link target returned HTTP " +
                              str(rd.status) + "; the href was found in "
                              "a crawled page of the same site."),
                    param=str(rd.status), method="GET",
                    title="Broken Internal Link (HTTP " +
                          str(rd.status) + ")")
            uprint("[" + str(n) + "/" + str(total) + "] " +
                   STY.yellow("[!] " + _clip(pr.url, 90) + " " +
                              str(rd.status) + " (" +
                              str(round(rd.elapsed, 2)) +
                              "s) error page - checks skipped"))
            text = rd.text
            if pr.depth < MAX_DEPTH and not self.stop and text \
                    and ("html" in rd.content_type.lower()
                         or _looks_html(text)):
                for link in extract_links(text, rd.final_url or pr.url):
                    if self.stop:
                        break
                    self.enqueue(link, pr.depth + 1)
            return

        pr.state = "scanned"
        uprint("[" + str(n) + "/" + str(total) + "] " +
               STY.green("[+] " + _clip(pr.url, 90)) + " " +
               str(rd.status) + " (" + str(round(rd.elapsed, 2)) + "s)")
        text = rd.text
        if text and ("html" in rd.content_type.lower() or _looks_html(text)):
            self._check_html_page(pr, rd, text)
            if pr.depth < MAX_DEPTH and not self.stop:
                for link in extract_links(text, rd.final_url or pr.url):
                    if self.stop:
                        break
                    self.enqueue(link, pr.depth + 1)

    def _handle_probe(self, pr, rd, n, total):
        spec = pr.probe or {}
        sigs = spec.get("sigs", ())
        allow_html = spec.get("html", False)
        hit = probe_hit(rd.status, rd.body, sigs, allow_html)
        uprint("[" + str(n) + "/" + str(total) + "] " + STY.cyan(
            "[i] " + _clip(pr.url, 90) + " " + str(rd.status)))
        if hit:
            excerpt = _decode_body(rd.body[:400], rd.headers)
            ev = sanitize_evidence(excerpt) or \
                 "(direct 200, signature matched)"
            self.add_finding("exposed_file", pr.url, evidence=ev,
                             param=spec.get("path", ""),
                             title=spec.get("title"),
                             sev=spec.get("sev"))
        pr.state = "scanned"

    def _handle_admin(self, pr, rd, n, total):
        spec = pr.probe or {}
        markers = spec.get("markers", ())
        hit = admin_hit(rd.status, rd.body, markers)
        uprint("[" + str(n) + "/" + str(total) + "] " + STY.cyan(
            "[i] " + _clip(pr.url, 90) + " " + str(rd.status)))
        if hit:
            self.add_finding(
                "admin_panel", pr.url,
                evidence=("Direct 200 (no redirect); markup contains "
                          "login markers. Reachability only - no login "
                          "was attempted."),
                param=spec.get("path", ""),
                title="Admin Login Page Publicly Reachable (" +
                      spec.get("path", "") + ")")
        pr.state = "scanned"

    def _check_html_page(self, pr, rd, text):
        h = rd.headers
        page_url = pr.url
        final = rd.final_url or pr.url
        https_page = final.lower().startswith("https://")

        for check_id in classify_headers(h, https_page):
            self.add_finding(check_id, page_url,
                             evidence="Header absent from the response.")
        for check_id, hdr, val in classify_banners(h):
            self.add_finding(check_id, page_url, header=hdr,
                             evidence=hdr + ": " + val)

        for c in rd.set_cookies:
            self._check_cookie(pr, c)

        scan = text[:200000]
        for pat in SQL_ERR_PATTERNS:
            m = re.search(pat, scan, re.I)
            if m:
                ev = _clip(scan[max(0, m.start() - 60):m.end() + 120]
                           .replace("\n", " "), 250)
                self.add_finding(
                    "sql_error_passive", page_url, evidence=ev,
                    title="Database Error Text Shown To Visitors")
                break
        for pat in STACK_PATTERNS:
            m = re.search(pat, scan, re.I)
            if m:
                ev = _clip(scan[max(0, m.start() - 60):m.end() + 120]
                           .replace("\n", " "), 250)
                self.add_finding(
                    "stack_trace", page_url, evidence=ev,
                    title="Internal Error Report Shown To Visitors")
                break
        if re.search(r"(?i)<title[^>]*>\s*(?:Index of\s*/|"
                     r"Directory listing for)", text[:50000]):
            self.add_finding(
                "dir_listing", page_url,
                evidence="Directory index page in markup.",
                title="Folder Content List Shown")
        if https_page:
            found = [m.group(1) for m in MIXED_RE.finditer(text[:400000])][:3]
            if found:
                ev = "Mixed references:\n" + "\n".join(found)
                self.add_finding(
                    "mixed_content", page_url, evidence=ev,
                    title="Locked Page Loads Unlocked Parts")

        self._check_forms(pr, rd, text)
        self._probe_params(pr, rd)

    def _check_cookie(self, pr, cookie):
        parts = cookie.split(";")
        name = parts[0].split("=", 1)[0].strip()
        if not name:
            return
        attrs = {p.strip().lower().split("=", 1)[0]
                 for p in parts[1:] if p.strip()}
        ev = "Set-Cookie: " + cookie
        if "secure" not in attrs:
            self.add_finding("cookie_secure", pr.url, param=name,
                             header="Set-Cookie", evidence=ev,
                             title="Cookie '" + name +
                                   "' Can Be Sent Unlocked")
        if "httponly" not in attrs:
            self.add_finding("cookie_httponly", pr.url, param=name,
                             header="Set-Cookie", evidence=ev,
                             title="Cookie '" + name +
                                   "' Readable By Scripts")
        if "samesite" not in attrs:
            self.add_finding("cookie_samesite", pr.url, param=name,
                             header="Set-Cookie", evidence=ev,
                             title="Cookie '" + name +
                                   "' Missing SameSite")

    def _check_forms(self, pr, rd, text):
        final = rd.final_url or pr.url
        page_https = final.lower().startswith("https://")
        entries = re.findall(r"(?is)<form\b[^>]*>.*?(?:</form>|$)", text)
        for raw in entries:
            action = _tag_attr(raw, "action")
            method = (_tag_attr(raw, "method") or "get").upper()
            has_pw = re.search(r"(?i)type\s*=\s*[\"']?password",
                               raw) is not None
            if has_pw:
                self.login_form_seen = True
            action_abs = urljoin(final, action) if action else final
            if has_pw and (not page_https
                           or action_abs.lower().startswith("http://")):
                self.add_finding(
                    "form_http_password", pr.url, method=method,
                    evidence=("Form at " + final + " has a password "
                              "field; page or action is plain HTTP."),
                    title="Password Form Without The Lock (HTTP)")
            # v2.2 FIX (D): testable helper; markup-only, stays Potential.
            if csrf_finding_needed(method, raw):
                fields = len(re.findall(
                    r"(?i)<(?:input|select|textarea)\b", raw))
                self.add_finding(
                    "form_csrf", pr.url, method="POST",
                    evidence=("POST form, " + str(fields) +
                              " fields, no token-like hidden input "
                              "in markup."),
                    title="Form May Be Submittable By Other Sites")

    def _probe_params(self, pr, rd):
        p = urlsplit(pr.url)
        if not p.query or not rd.text or self.stop:
            return
        if "html" not in rd.content_type.lower() \
                and not _looks_html(rd.text):
            return
        pairs = parse_qsl(p.query, keep_blank_values=True)
        if not pairs:
            return
        with self.lock:
            if self.stats.param_probes >= MAX_PARAM_TESTS:
                return
            self.stats.param_probes += 1
        k0, v0 = pairs[0]
        marker = "wv" + uuid.uuid4().hex[:8] + "'\"<"
        pairs[0] = (k0, (v0 + marker) if v0 else marker)
        test_url = urlunsplit((p.scheme, p.netloc, p.path,
                               urlencode(pairs), ""))
        rd2 = self.fetch(test_url)
        if rd2.error or not rd2.text:
            return
        if marker in rd2.text:
            self.add_finding(
                "xss_indicator", pr.url, param=k0, method="GET",
                evidence=("Probe value " + repr(marker) +
                          " on parameter '" + k0 +
                          "' was reflected unencoded."),
                title="Possible Reflected XSS (Indicator Only)")
            return
        for pat in SQL_ERR_PATTERNS:
            m = re.search(pat, rd2.text[:200000], re.I)
            if m:
                ev = _clip(rd2.text[max(0, m.start() - 60):m.end() + 120]
                           .replace("\n", " "), 250)
                self.add_finding(
                    "sqli_indicator", pr.url, param=k0, method="GET",
                    evidence=("After one quote on '" + k0 + "': " + ev),
                    title="Possible SQL Injection (Indicator Only)")
                return


# ---------------------------------------------------------------------------
# Terminal report: four separated groups
# ---------------------------------------------------------------------------
GROUPS = [
    ("issue",
     "SECURITY ISSUES - REAL EVIDENCE SEEN",
     "Each item below was directly observed in responses during the scan."),
    ("potential",
     "POTENTIAL ISSUES - NEED MANUAL VERIFICATION",
     "Strong signs, but NOT confirmed. Verify manually before acting."),
    ("hardening",
     "HARDENING RECOMMENDATIONS - LOW RISK",
     "Missing best-practice controls. Not vulnerabilities by themselves."),
    ("observation",
     "OBSERVATIONS - NOT VULNERABILITIES",
     "Facts about the server. Reachability is not a security problem by "
     "itself; nothing here was exploited or tested intrusively."),
]


def _print_finding(f):
    uprint(sev_color(f.severity)("-" * 70))
    uprint(sev_color(f.severity)(
        " " + f.fid + "  RISK: " + RISK_WORD.get(f.severity, "?") +
        "  |  " + f.title))
    uprint("   Status     : " + f.verification +
           " (confidence: " + f.confidence + ")")
    uprint("   URL        : " + _clip(f.url, 110))
    if f.param:
        uprint("   Where      : " + f.param)
    if f.header:
        uprint("   Header     : " + f.header)
    if f.occurrences > 1:
        extra = ", ".join(f.affected_urls[:5])
        uprint("   Seen on    : " + str(f.occurrences) + " pages" +
               (" (e.g. " + extra + ")" if extra else ""))
    uprint("")
    uprint(STY.bold("   WHAT IT IS :"))
    uprint(_wrap(_subst(f.what, param=f.param, path=f.param)))
    if f.evidence:
        uprint(STY.bold("   EVIDENCE   :"))
        uprint(_wrap(f.evidence))
    uprint(STY.bold("   IMPACT     :"))
    uprint(_wrap(_subst(f.impact, param=f.param, path=f.param)))
    uprint(STY.bold("   HOW TO FIX :"))
    uprint(_wrap(_subst(f.fix, param=f.param, path=f.param)))
    uprint(STY.dim("   DETECTION  : " + f.tech))
    lim = f.lim + (("  " + f.note) if f.note else "")
    uprint(STY.dim("   LIMITS     : " + lim))


def print_terminal_report(r):
    line = "=" * 70
    uprint()
    uprint(STY.bold(STY.cyan(line)))
    uprint(STY.bold(STY.cyan("WEB VULNERABILITY - SCAN REPORT".center(70))))
    uprint(STY.bold(STY.cyan(line)))
    uprint(" Target   : " + r.url)
    uprint(" Domain   : " + r.domain)
    if r.ip:
        uprint(" IP       : " + r.ip +
               ("   " + r.reverse_dns if r.reverse_dns else ""))
    uprint(" Lock/SSL : " +
           (r.tls_version if r.tls_version else "none / not reachable"))
    if r.open_ports:
        uprint(" Ports    : " +
               ", ".join(str(p) + " " + s for p, s in r.open_ports) +
               " (reachability only)")

    c = counters_from_records(r.records)
    probes = sum(1 for x in r.records if x.kind != "page")
    uprint(" Pages    : " + str(c["discovered"]) + " discovered | " +
           str(c["scanned"]) + " scanned | " + str(c["skipped"]) +
           " skipped | " + str(c["failed"]) + " failed | " +
           str(c["pending"]) + " not reached")
    uprint(" Avoided  : " + str(r.stats.duplicates) +
           " duplicate URLs, " + str(r.stats.filtered) +
           " filtered (out of scope / placeholders / limits), " +
           str(probes) + " internal probes")
    ok = counters_consistent(c)
    uprint(" Counter check: discovered == scanned+skipped+failed+pending -> "
           + ("OK" if ok else STY.red("MISMATCH - please report this bug")))
    uprint(" Requests : " + str(r.stats.requests) +
           " (" + str(r.stats.errors) + " errors, " +
           str(r.stats.retries) + " retries) in " +
           _fmt_duration(r.duration))

    by_cat = {g: 0 for g in CATEGORIES}
    sev = {s: 0 for s in SEV_ORDER}
    for f in r.findings:
        by_cat[f.cat] += 1
        sev[f.severity] += 1
    uprint(" Results  : " + str(len(r.findings)) + " findings -> " +
           "issues " + str(by_cat["issue"]) +
           ", potential " + str(by_cat["potential"]) +
           ", hardening " + str(by_cat["hardening"]) +
           ", observations " + str(by_cat["observation"]))
    uprint(" Severity : Critical " + str(sev["Critical"]) +
           ", High " + str(sev["High"]) +
           ", Medium " + str(sev["Medium"]) +
           ", Low " + str(sev["Low"]) +
           ", Info " + str(sev["Informational"]))
    uprint(line)

    if not r.findings:
        uprint(" No findings were produced by these checks.")
        uprint(" This does NOT prove the website is fully safe.")
    for cat, heading, blurb in GROUPS:
        fl = [f for f in r.findings if f.cat == cat]
        if not fl:
            continue
        uprint("")
        uprint(STY.bold(STY.cyan(" " + heading)))
        uprint(STY.dim("   " + blurb))
        uprint("")
        for f in sorted(fl, key=lambda x: SEV_RANK[x.severity]):
            _print_finding(f)
        uprint("-" * 70)

    uprint("")
    uprint(STY.dim(" Method: read-only GET requests only. No password"))
    uprint(STY.dim(" guessing, no exploit payloads, no data extraction,"))
    uprint(STY.dim(" no authentication attempts. Rate-limited to ~" +
                   str(int(1 / MIN_REQUEST_INTERVAL)) +
                   " req/s, " + str(MAX_WORKERS) + " workers max."))
    uprint(STY.dim(" Error pages (4xx/5xx) are counted but excluded from"))
    uprint(STY.dim(" header/content findings; their links are followed."))
    uprint(STY.dim(" The [n/total] progress total grows as new URLs are"))
    uprint(STY.dim(" discovered during the crawl; per-line n is unique."))
    uprint(STY.dim(" Not covered: login-protected pages, JS-rendered"))
    uprint(STY.dim(" content, service versions behind open ports."))
    uprint(STY.dim(" Scan only websites you own or are authorized to test."))
    uprint(line)


# ---------------------------------------------------------------------------
# Terminal interface (CLI and banner preserved)
# ---------------------------------------------------------------------------
def _banner_lines(text):
    rows = [""] * 5
    for ch in text:
        glyph = BANNER_FONT.get(ch.upper())
        if glyph is None:
            glyph = ["     "] * 5
        for i in range(5):
            rows[i] += glyph[i] + " "
    return [row.rstrip() for row in rows]


def print_banner():
    l1 = _banner_lines("WEB")
    l2 = _banner_lines("VULNERABILITY")
    width = shutil.get_terminal_size((100, 30)).columns
    uprint()
    if width >= 80:
        for ln in l1 + [""] + l2:
            uprint(STY.cyan(ln))
    else:
        bar = "=" * min(max(width - 2, 20), 60)
        uprint(STY.cyan(bar))
        uprint(STY.bold(STY.cyan("WEB VULNERABILITY".center(len(bar)))))
        uprint(STY.cyan(bar))
    uprint(STY.dim("  read-only scanning, honest severity, clear findings"))
    uprint(STY.dim("  authorized targets only"))
    uprint()


def cmd_scan():
    uprint()
    try:
        raw = input("Enter Target Website URL: ").strip()
    except EOFError:
        return
    if not raw:
        uprint(STY.red("[!] No URL entered."))
        return
    try:
        sc = Scanner(raw)
    except ValueError as e:
        uprint(STY.red("[!] Invalid URL: " + str(e)))
        return
    uprint()
    uprint(STY.bold("Target : ") + STY.cyan(sc.url))
    uprint(STY.bold("Domain : ") + STY.cyan(sc.host))
    if sc.proxy_info:
        uprint(STY.cyan(sc.proxy_info))
    uprint()
    try:
        result = sc.run()
    except KeyboardInterrupt:
        result = None
    if result is None:
        uprint(STY.yellow("\n[!] Scan stopped."))
        return
    print_terminal_report(result)
    try:
        input("\nPress Enter to return to the main menu...")
    except EOFError:
        pass


def main_menu():
    print_banner()
    _verify_catalog()
    while True:
        uprint(STY.bold("Main Menu"))
        uprint(STY.dim("---------"))
        for k, label in MENU_OPTIONS:
            uprint("[" + k + "] " + label)
        uprint()
        try:
            choice = input("Select an option: ").strip()
        except EOFError:
            uprint()
            break
        if choice == "1":
            cmd_scan()
        elif choice == "2":
            uprint(STY.green("[i] Exiting. Goodbye."))
            break
        else:
            uprint(STY.red("[!] Enter 1 or 2."))


# ---------------------------------------------------------------------------
# Offline unit tests (no network; mock responses). Run: --selftest
# ---------------------------------------------------------------------------
def _mk_finding(check_id, sev):
    c = CATALOG[check_id]
    return Finding(fid="T", check_id=check_id, cat=c["cat"],
                   title=c["title"], severity=sev,
                   verification=c["verif"])


FULL_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
}


def _mock_rd(status=200, headers=None, text="", final="https://example.com/p"):
    return ResponseData(requested_url=final, final_url=final,
                        status=status,
                        headers=dict(headers or {}),
                        set_cookies=[], body=text.encode("utf-8"),
                        text=text, content_type="text/html",
                        elapsed=0.01, error=None)


def selftest():
    results = []

    def t(name, cond):
        results.append((name, bool(cond)))

    # --- URL normalization ---------------------------------------------
    u, e = normalize_url("example.com")
    t("t01 normalize adds https + slash",
      e is None and u == "https://example.com/")
    u, e = normalize_url("HTTP://Example.COM:80/a?b=1")
    t("t02 normalize lowercases host, drops default port",
      e is None and u == "http://example.com/a?b=1")
    t("t03 normalize rejects non-http scheme",
      normalize_url("ftp://example.com")[1] is not None)

    # --- Canonical dedup -------------------------------------------------
    t("t04 url_key dedups www + tracking + param order",
      url_key("https://example.com/a?b=1&c=2") ==
      url_key("https://www.EXAMPLE.com/a?c=2&b=1&utm_source=x"))
    t("t05 url_key preserves meaningful param VALUES",
      url_key("https://example.com/a?id=1") !=
      url_key("https://example.com/a?id=2"))
    t("t06 url_key preserves meaningful param NAMES",
      url_key("https://example.com/a?x=1") !=
      url_key("https://example.com/a?y=1"))

    # --- Placeholders ------------------------------------------------------
    t("t07 placeholder detector catches ${...} and {{...}}",
      is_template_placeholder("${fileUrl}") and
      is_template_placeholder("${mailtoUrl}") and
      is_template_placeholder("%24%7BgmailUrl%7D") and
      is_template_placeholder("{{url}}") and
      not is_template_placeholder("/normal/path"))
    page = ("<a href='${fileUrl}'>a</a>"
            "<a href='mailto:${mailtoUrl}'>b</a>"
            "<a href='/about'>c</a>")
    t("t08 extract_links skips placeholders, keeps real links",
      extract_links(page, "https://ex.com/") == ["https://ex.com/about"])

    # --- v2.2 FIX (B): HTML entity unescaping ---------------------------
    raw = "<a href='/a?x=1&amp;slug=about'>t</a>"
    got = extract_links(raw, "https://ex.com/")
    t("t09 href &amp; is unescaped to &",
      got == ["https://ex.com/a?x=1&slug=about"])
    t("t10 no literal '&amp;' survives extraction",
      all("&amp;" not in g for g in got))
    t("t11 unescaped and escaped hrefs dedup to one URL",
      len(extract_links("<a href='/a?x=1&amp;y=2'>1</a>"
                        "<a href='/a?x=1&y=2'>2</a>",
                        "https://ex.com/")) == 1)

    # --- v2.2 FIX (E): duplicate query pairs -----------------------------
    t("t12 url_key collapses repeated identical params",
      url_key("https://e.com/a?b=1&b=1") == url_key("https://e.com/a?b=1"))

    # --- Header classification --------------------------------------------
    miss = classify_headers({}, True)
    t("t13 all six headers missing on https page",
      miss == ["hsts_missing", "csp_missing", "xfo_missing",
               "xcto_missing", "referrer_missing", "perms_missing"])
    t("t14 no findings when all headers present",
      classify_headers(FULL_HEADERS, True) == [])
    csp_only = {"Content-Security-Policy":
                "default-src 'self'; frame-ancestors 'none'"}
    t("t15 CSP frame-ancestors suppresses xfo (no dup root cause)",
      "xfo_missing" not in classify_headers(csp_only, False))
    t("t16 HSTS not demanded on plain HTTP page",
      "hsts_missing" not in classify_headers({}, False))
    t("t17 header names and values are case-insensitive",
      classify_headers({"X-CONTENT-TYPE-OPTIONS": "NOSNIFF"}, False)
      .count("xcto_missing") == 0)

    # --- Probe / admin / redirect false-positive guards ------------------
    env_sigs = (b"DB_PASSWORD=", b"DB_HOST=")
    t("t18 probe_hit true on real signature",
      probe_hit(200, b"DB_PASSWORD=x\nDB_HOST=y", env_sigs, False))
    t("t19 probe_hit rejects homepage HTML vs .env",
      not probe_hit(200, b"<html><body>home</body></html>",
                    env_sigs, False))
    t("t20 probe_hit rejects non-200 (incl. redirect 302)",
      not probe_hit(404, b"DB_PASSWORD=x", env_sigs, False) and
      not probe_hit(302, b"DB_PASSWORD=x", env_sigs, False))
    t("t21 probe_hit rejects signature mismatch",
      not probe_hit(200, b"nothing relevant here", env_sigs, False))
    t("t22 admin_hit true on real login markup",
      admin_hit(200, b"<input type='password' name='pw'>",
                (b"password",)))
    t("t23 admin_hit false on plain homepage",
      not admin_hit(200, b"<html><body>welcome</body></html>",
                    (b"password",)))
    t("t24 admin_hit false on redirect status",
      not admin_hit(302, b"<input type='password'>", (b"password",)))

    # --- v2.2 FIX (A): error-page eligibility -----------------------------
    t("t25 page_finding_eligible: 200/206/302 yes, 404/410/500/0 no",
      page_finding_eligible(200) and page_finding_eligible(206) and
      page_finding_eligible(302) and not page_finding_eligible(404) and
      not page_finding_eligible(410) and not page_finding_eligible(500) and
      not page_finding_eligible(0))

    # --- v2.2 FIX (D): CSRF markup heuristic ------------------------------
    with_tok = ("<form method='POST'><input type='hidden' "
                "name='csrf_token' value='x'><input name='a'></form>")
    no_tok = ("<form method='POST'><input name='a'>"
              "<input name='b'></form>")
    get_no_tok = "<form method='GET'><input name='a'></form>"
    t("t26 form_has_csrf_token true for hidden token field",
      form_has_csrf_token(with_tok))
    t("t27 form_has_csrf_token false for plain form",
      not form_has_csrf_token(no_tok))
    t("t28 csrf_finding_needed: only POST forms without tokens",
      not csrf_finding_needed("GET", no_tok) and
      not csrf_finding_needed("GET", get_no_tok) and
      csrf_finding_needed("POST", no_tok) and
      not csrf_finding_needed("POST", with_tok))

    # --- Ports / classification policy ------------------------------------
    t("t29 open_port is observation + Informational, no vuln claim",
      CATALOG["open_port"]["cat"] == "observation" and
      CATALOG["open_port"]["sev"] == "Informational" and
      "NOT a verified vulnerability" in CATALOG["open_port"]["impact"])
    t("t30 admin_panel is observation; broken_link is observation",
      CATALOG["admin_panel"]["cat"] == "observation" and
      CATALOG["broken_link"]["cat"] == "observation")

    # --- Catalogue integrity + severity policy ----------------------------
    ok_cat = True
    for key, c in CATALOG.items():
        if c["cat"] not in CATEGORIES or c["sev"] not in SEV_ORDER:
            ok_cat = False
        if c["verif"] not in ("Confirmed", "Potential"):
            ok_cat = False
        for fld in ("title", "what", "impact", "fix", "tech", "lim"):
            if not c.get(fld):
                ok_cat = False
    t("t31 catalogue complete and valid", ok_cat and _verify_catalog())
    t("t32 header misses are hardening (never confirmed vulns)",
      CATALOG["hsts_missing"]["cat"] == "hardening" and
      CATALOG["csp_missing"]["cat"] == "hardening" and
      CATALOG["xcto_missing"]["cat"] == "hardening" and
      CATALOG["referrer_missing"]["cat"] == "hardening" and
      CATALOG["perms_missing"]["cat"] == "hardening" and
      CATALOG["tech_banner"]["sev"] == "Informational")
    t("t33 indicators stay Potential, never Confirmed",
      CATALOG["sqli_indicator"]["verif"] == "Potential" and
      CATALOG["xss_indicator"]["verif"] == "Potential" and
      CATALOG["form_csrf"]["verif"] == "Potential")

    # --- Counter integrity --------------------------------------------------
    recs = [PageRecord("a", "a", 0, state="scanned"),
            PageRecord("b", "b", 0, state="scanned"),
            PageRecord("c", "c", 0, state="skipped"),
            PageRecord("d", "d", 0, state="failed"),
            PageRecord("e", "e", 0, state="pending"),
            PageRecord("p", "p", 0, kind="probe", state="scanned")]
    c = counters_from_records(recs)
    t("t34 counters reconcile (probes excluded, pending counted)",
      c["discovered"] == 5 and c["scanned"] == 2 and c["skipped"] == 1 and
      c["failed"] == 1 and c["pending"] == 1 and counters_consistent(c))
    bad = dict(c)
    bad["scanned"] += 1
    t("t35 counter mismatch is detected", not counters_consistent(bad))
    # v2.2: error pages are 'scanned' with a reason - still reconcile.
    recs2 = [PageRecord("a", "a", 0, state="scanned",
                        reason="HTTP 404 (error page - checks skipped)"),
             PageRecord("b", "b", 1, state="scanned"),
             PageRecord("p1", "p1", 0, kind="probe", state="scanned"),
             PageRecord("p2", "p2", 0, kind="admin", state="scanned")]
    c2 = counters_from_records(recs2)
    t("t36 error-page records keep counters consistent",
      c2["discovered"] == 2 and c2["scanned"] == 2 and
      counters_consistent(c2))

    # --- Context-aware severity ---------------------------------------------
    fs = [_mk_finding("hsts_missing", "Low")]
    apply_context(fs, True)
    t("t37 HSTS bumps to Medium when a login form was seen",
      fs[0].severity == "Medium" and fs[0].note != "")
    fs2 = [_mk_finding("hsts_missing", "Low")]
    apply_context(fs2, False)
    t("t38 HSTS stays Low without login context",
      fs2[0].severity == "Low")
    fs3 = [_mk_finding("csp_missing", "Low"),
           _mk_finding("xss_indicator", "High")]
    apply_context(fs3, False)
    t("t39 CSP bumps to Medium when an XSS indicator exists",
      fs3[0].severity == "Medium")

    # --- Redaction ------------------------------------------------------------
    s = sanitize_evidence("password=SuperSecret123 DB_PASSWORD=hunter2")
    t("t40 evidence redaction hides secrets",
      "SuperSecret123" not in s and "hunter2" not in s
      and "REDACTED" in s)

    # --- Mock-response pipeline tests (no network) -------------------------
    # A Scanner instance is safe offline: __init__ only builds a session
    # and may read the Windows proxy registry key.
    sc = Scanner("https://example.com/")
    pr = PageRecord(url="https://example.com/p", key="k", depth=1)

    sc1 = Scanner("https://example.com/")
    sc1._check_html_page(pr, _mock_rd(headers=FULL_HEADERS,
                                      text="<html><body>hi</body></html>",
                                      final="https://example.com/p"),
                         "<html><body>hi</body></html>")
    t("t41 mock page with all headers: zero findings",
      len(sc1.findings) == 0)

    sc2 = Scanner("https://example.com/")
    sc2._check_html_page(pr, _mock_rd(headers={},
                                      text="<html><body>hi</body></html>",
                                      final="https://example.com/p"),
                         "<html><body>hi</body></html>")
    ids2 = set(f.check_id for f in sc2.findings)
    t("t42 mock page missing headers: exactly the 6 hardening findings",
      ids2 == {"hsts_missing", "csp_missing", "xfo_missing",
               "xcto_missing", "referrer_missing", "perms_missing"} and
      all(f.cat == "hardening" for f in sc2.findings))

    sc3 = Scanner("https://example.com/")
    form_tok = ("<html><body><form method='POST' action='/x'>"
                "<input name='a'><input type='hidden' "
                "name='authenticity_token' value='v'></form>"
                "</body></html>")
    sc3._check_html_page(pr, _mock_rd(headers=FULL_HEADERS, text=form_tok,
                                      final="https://example.com/p"),
                         form_tok)
    t("t43 mock POST form WITH token: no CSRF finding",
      all(f.check_id != "form_csrf" for f in sc3.findings))

    sc4 = Scanner("https://example.com/")
    form_no = ("<html><body><form method='POST' action='/x'>"
               "<input name='a'><input name='b'></form>"
               "</body></html>")
    sc4._check_html_page(pr, _mock_rd(headers=FULL_HEADERS, text=form_no,
                                      final="https://example.com/p"),
                         form_no)
    t("t44 mock POST form WITHOUT token: one Potential CSRF finding",
      sum(1 for f in sc4.findings if f.check_id == "form_csrf") == 1 and
      all(f.cat == "potential" and f.verification == "Potential"
          for f in sc4.findings if f.check_id == "form_csrf"))

    t("t45 redirect final response is eligible, error page is not "
      "(report guard)",
      page_finding_eligible(_mock_rd(status=302).status) and
      not page_finding_eligible(_mock_rd(status=404).status))

    # Mixed-record report-counter reconciliation (mock of a real run).
    recs3 = ([PageRecord("u" + str(i), "u" + str(i), 0,
                         state="scanned") for i in range(215)] +
             [PageRecord("s1", "s1", 1, state="skipped"),
              PageRecord("s2", "s2", 1, state="skipped")] +
             [PageRecord("q" + str(i), "q" + str(i), 0, kind="probe",
                         state="scanned") for i in range(16)])
    c3 = counters_from_records(recs3)
    t("t46 log-shaped record set reconciles (217 = 215+2+0+0)",
      c3["discovered"] == 217 and c3["scanned"] == 215 and
      c3["skipped"] == 2 and c3["pending"] == 0 and
      counters_consistent(c3))

    t("t47 finding IDs unique and severities valid (mock set)",
      (lambda fl: len({f.fid for f in fl}) == len(fl) and
       all(f.severity in SEV_ORDER and f.cat in CATEGORIES
           for f in fl))(sc4.findings))

    t("t48 placeholders never enter enqueue path",
      (lambda sc: [sc.enqueue(u, 1) for u in
                   ("${fileUrl}", "https://example.com/ok")] and
       sc.stats.filtered == 1 and len(sc.records) == 1)(
          Scanner("https://example.com/")))

    uprint(STY.bold("Web Vulnerability - unit tests (v2.2)"))
    uprint("-" * 60)
    passed = 0
    for name, ok in results:
        passed += 1 if ok else 0
        uprint(("  [PASS] " if ok else "  [FAIL] ") + name)
    uprint("-" * 60)
    uprint("  " + str(passed) + "/" + str(len(results)) +
           " tests passed.")
    if passed == len(results):
        uprint("  Offline logic verified incl. mock responses. Network")
        uprint("  behaviour (crawl, TLS, ports) needs an authorized scan.")
    return 0 if passed == len(results) else 1


def main():
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if "--selftest" in sys.argv[1:]:
        return selftest()
    try:
        main_menu()
    except KeyboardInterrupt:
        uprint()
        uprint(STY.yellow("[!] Interrupted - exiting cleanly."))
    return 0


if __name__ == "__main__":
    sys.exit(main())

# ==== END OF FILE ====
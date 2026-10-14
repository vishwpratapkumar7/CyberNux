#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phishing Link & Zphisher Detector
=================================

A defensive, static-analysis module for identifying suspicious URLs,
credential-harvesting pages, and structural indicators associated with
phishing toolkits such as Zphisher and its shellphish-family relatives.

Safety rules enforced throughout this module:
  * Nothing is ever executed: URLs are never fetched, HTML is never
    rendered, JavaScript is never run, credentials are never submitted,
    and no web browser is ever opened.
  * Findings are evidence-based and weighted. The 0-100 risk score is a
    triage heuristic -- NOT a verified probability of compromise.
  * Zphisher attribution is pattern-based. Reports use hedged wording
    ("Possible Zphisher-related indicators detected") and never claim
    definitive toolkit identity, because Zphisher shares most patterns
    with its shellphish/blackeye-family forks.
  * Offline detection works with zero configuration and zero third-party
    dependencies (Python 3.11+ standard library only). Threat-intel
    lookups (Mode 4) are strictly optional, read the API key from the
    environment, ask for consent, and never display or log the key.

Modes
  1. URL analysis     - lexical/structural inspection (no network).
  2. Local HTML       - static scan of user-provided files/directories.
  3. Server logs      - static scan of user-provided access logs.
  4. Threat intel     - optional Google Safe Browsing lookup (needs key).

Usage
  python detector.py                 # interactive terminal menu
  python detector.py --selftest      # run the embedded unit tests
  python detector.py --url <url>     # one-shot URL analysis
  python detector.py --file <path>   # one-shot HTML analysis
  
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import json
import os
import re
import sys
import unittest
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional

MODULE_VERSION = "1.0.0"

MAX_HTML_BYTES = 10 * 1024 * 1024
MAX_LOG_BYTES = 50 * 1024 * 1024
MAX_LOG_LINES = 200_000
MAX_DIR_FILES = 500
NETWORK_TIMEOUT = 10.0

GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GSB_ENV_VAR = "GOOGLE_SAFE_BROWSING_API_KEY"

# ============================================================================
# Signature data (locally stored -- nothing is downloaded at runtime)
# ============================================================================

BRANDS: dict[str, str] = {
    "paypal": "paypal.com", "google": "google.com", "gmail": "google.com",
    "facebook": "facebook.com", "instagram": "instagram.com",
    "whatsapp": "whatsapp.com", "netflix": "netflix.com",
    "amazon": "amazon.com", "apple": "apple.com", "icloud": "icloud.com",
    "microsoft": "microsoft.com", "office": "office.com",
    "outlook": "outlook.com", "linkedin": "linkedin.com",
    "twitter": "twitter.com", "spotify": "spotify.com",
    "steam": "steampowered.com", "roblox": "roblox.com",
    "yahoo": "yahoo.com", "adobe": "adobe.com", "github": "github.com",
    "dropbox": "dropbox.com", "binance": "binance.com",
    "coinbase": "coinbase.com",
}
OFFICIAL_SUFFIXES: set[str] = set(BRANDS.values()) | {
    "fb.com", "facebook.net", "office365.com", "live.com", "x.com",
    "steamcommunity.com",
}

SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "ow.ly", "buff.ly", "rebrand.ly", "tiny.cc", "bit.do",
    "s.id", "lnkd.in", "v.gd", "trib.al", "bl.ink",
}

# Zphisher-family kits expose their local credential listener through
# reverse tunnels; documented kit behaviour includes ngrok/serveo/cloudflared.
TUNNEL_SUFFIXES: tuple[str, ...] = (
    "ngrok.io", "ngrok-free.app", "serveo.net", "trycloudflare.com",
    "localhost.run", "localtunnel.me", "loca.lt", "portmap.io",
    "tunnelmole.com",
)

RISKY_TLDS: set[str] = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "click", "icu",
    "cfd", "sbs", "cam", "quest", "work", "link", "live", "online", "site",
    "shop", "monster",
}

REDIRECT_PARAMS: set[str] = {
    "url", "redirect", "redirect_url", "redirect_uri", "next", "goto", "go",
    "return", "return_url", "returnto", "continue", "dest", "destination",
    "target", "link", "out", "forward", "r", "u",
}

CRED_KEYWORDS: tuple[str, ...] = (
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "secure", "account", "update", "confirm", "password", "billing",
    "wallet", "recovery", "unlock", "authenticate", "webscr", "credential",
    "session", "suspended",
)

# Bare PHP handler names used by Zphisher-family templates to receive and
# store/forward credentials. Also used by legitimate apps -> medium weight.
KIT_HANDLERS: set[str] = {
    "login.php", "post.php", "write.php", "results.php", "result.php",
    "handler.php", "up.php", "ip.php", "logs.php", "log.php", "send.php",
    "process.php", "auth.php",
}

KIT_ARTIFACT_NAMES: tuple[str, ...] = (
    "usernames.txt", "passwords.txt", "savedpassword", "saved-pass",
    "result.txt", "results.txt", "logs.txt", "victims.txt", "creds.txt",
)

CRED_INPUT_NAMES: set[str] = {
    "password", "passwd", "pass", "pwd", "login_password", "user_password",
    "password_confirm", "confirm_password",
}

SUSPICIOUS_TOKENS: tuple[str, ...] = (
    "login", "signin", "secure", "verify", "account", "update", "confirm",
    "support", "auth", "bill", "wallet", "recover", "unlock", "warning",
    "limited", "help",
)

_CHAR_SUBS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a",
                            "5": "s", "$": "s", "@": "a"})

LOG_LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"]*))?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?\s*$'
)

# ============================================================================
# Terminal colours
# ============================================================================

_COLOR_ENABLED = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def set_color(enabled: bool) -> None:
    global _COLOR_ENABLED
    _COLOR_ENABLED = enabled


def _enable_windows_ansi() -> None:
    if os.name == "nt":
        os.system("")  # activates ANSI VT processing on Windows 10+ consoles


def paint(text: object, code: str) -> str:
    s = str(text)
    if not _COLOR_ENABLED or os.environ.get("NO_COLOR"):
        return s
    return f"\033[{code}m{s}\033[0m"


def _c(s): return paint(s, "90")      # dim
def _red(s): return paint(s, "91")
def _green(s): return paint(s, "92")
def _yellow(s): return paint(s, "93")
def _blue(s): return paint(s, "94")
def _cyan(s): return paint(s, "96")
def _bold(s): return paint(s, "1")


# ============================================================================
# Core model
# ============================================================================

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str            # "high" | "medium" | "low" | "info"
    weight: int              # heuristic triage points, not probabilities
    evidence: str = ""
    attribution: str = "generic"   # "generic" | "zphisher" | "inconclusive"
    count: int = 1


@dataclass
class Report:
    target: str
    mode: str
    methods: list[str]
    findings: list[Finding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        for existing in self.findings:
            if existing.rule_id == finding.rule_id:
                existing.count += 1
                if finding.weight > existing.weight:
                    existing.weight = finding.weight
                    existing.severity = finding.severity
                    existing.evidence = finding.evidence
                    existing.attribution = finding.attribution
                elif finding.evidence and finding.evidence not in existing.evidence:
                    existing.evidence = truncate(
                        f"{existing.evidence} | {finding.evidence}", 240)
                return
        self.findings.append(finding)

    def score(self) -> int:
        """Capped sum of weights. Heuristic triage value only."""
        return min(100, sum(f.weight for f in self.findings))

    def confidence(self) -> str:
        strong = [f for f in self.findings if f.weight >= 15]
        highs = [f for f in self.findings if f.severity == "high"]
        if self.score() >= 60 and len(strong) >= 3 and highs:
            return "High"
        if self.score() >= 25 or len(strong) >= 2:
            return "Medium"
        return "Low"

    def verdict(self) -> tuple[str, str]:
        s = self.score()
        if s >= 70:
            return ("HIGH RISK",
                    "Strong, mutually-reinforcing phishing indicators. "
                    "Do not interact with this target.")
        if s >= 40:
            return ("ELEVATED RISK",
                    "Multiple phishing indicators. Treat as untrusted until "
                    "independently verified.")
        if s >= 20:
            return ("SUSPICIOUS",
                    "Some phishing indicators present. Additional "
                    "verification recommended.")
        return ("LOW RISK (HEURISTIC)",
                "No strong phishing indicators found. This is NOT a "
                "guarantee of safety.")

    def zphisher_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.attribution == "zphisher"]

    def zphisher_verdict(self) -> str:
        n = len(self.zphisher_findings())
        if n >= 2:
            return ("POSSIBLE ZPHISHER-RELATED INDICATORS DETECTED — "
                    "pattern-based, not definitive attribution (Zphisher "
                    "shares patterns with shellphish-family forks).")
        if n == 1:
            return ("Limited Zphisher-related indicator(s) detected — "
                    "inconclusive on its own.")
        return ("No Zphisher-specific indicators observed (the target may "
                "still be phishing from another toolkit).")

    def recommended_actions(self) -> list[str]:
        acts: list[str] = []
        s = self.score()
        if s >= 70:
            acts += [
                "Do not open this link or enter credentials on the associated page.",
                "Block the domain/URL at your DNS, proxy, or mail gateway and report it "
                "(e.g., via Google Safe Browsing or the impersonated brand's abuse form).",
                "If any credentials were entered there, change them immediately and "
                "enable multi-factor authentication.",
            ]
        elif s >= 40:
            acts += [
                "Treat the target as untrusted: do not authenticate to it.",
                "Verify through a professional, isolated URL-analysis service before "
                "deciding on a block.",
                "Report to your security team or abuse contact if received via "
                "email/message.",
            ]
        elif s >= 20:
            acts += [
                "Expand any shortener/redirect chain and re-run the analysis on the "
                "final destination.",
                "Check domain age/registration (WHOIS) and TLS certificate details "
                "before trusting it.",
                "If you must inspect it, use an isolated environment only.",
            ]
        else:
            acts += [
                "No action strictly required; remain cautious — heuristics can miss "
                "novel phishing.",
                "Report anything that feels wrong to your security contact even if "
                "this tool scored it low.",
            ]
        if any(f.attribution == "zphisher" for f in self.findings):
            acts += [
                "Zphisher-family indicators present: if you operate the affected "
                "host, take it offline and preserve evidence before cleanup.",
                "Search the web root for kit artifacts (bare PHP handlers, credential "
                "text files, tunnel client processes) and review access logs for "
                "credential POSTs.",
            ]
        return acts


def truncate(s: object, n: int) -> str:
    text = " ".join(str(s).split())
    return text if len(text) <= n else text[: n - 1] + "…"


# ============================================================================
# Shared helpers
# ============================================================================

def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_tunnel(host: str) -> bool:
    h = (host or "").lower()
    return any(h == t or h.endswith("." + t) for t in TUNNEL_SUFFIXES)


def _host_is_official(host: str) -> Optional[str]:
    h = (host or "").lower().rstrip(".")
    for suf in OFFICIAL_SUFFIXES:
        if h == suf or h.endswith("." + suf):
            return suf
    return None


def _is_risky_tld(host: str) -> bool:
    labels = (host or "").lower().rstrip(".").split(".")
    return len(labels) > 1 and labels[-1] in RISKY_TLDS


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > cap:
        return cap + 1
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        ca = a[i - 1]
        for j in range(1, lb + 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1,
                         prev[j - 1] + (ca != b[j - 1]))
        prev = cur
    return prev[lb]


def _try_b64_decode(encoded: str) -> Optional[str]:
    """Decode base64 for INSPECTION ONLY. Never executed. Returns None for
    anything that is not cleanly decodable printable text (kills FPs from
    random alphanumeric strings)."""
    s = encoded.strip()
    pad = "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s + pad, validate=True)
        if not raw:
            return None
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not text or not all(31 < ord(ch) < 127 or ch in "\r\n\t" for ch in text):
        return None
    return text


def _b64_contains(encoded: str, needles: tuple[str, ...]) -> bool:
    decoded = _try_b64_decode(encoded)
    if not decoded:
        return False
    low = decoded.lower()
    return any(n in low for n in needles)


# ============================================================================
# Mode 1 — URL analysis (purely lexical; the URL is never fetched)
# ============================================================================

def analyze_url(raw: str) -> Report:
    if not raw or not raw.strip():
        raise ValueError("No URL supplied.")
    url = raw.strip()
    if re.search(r"\s", url):
        raise ValueError("URL contains whitespace; supply a single complete URL.")

    rep = Report(
        target=url,
        mode="Mode 1 — URL analysis",
        methods=[
            "Lexical/structural URL parsing (network access: none)",
            "Hostname, IP, punycode and subdomain heuristics",
            "Brand-impersonation and typosquat matching",
            "Redirect-parameter and encoding analysis",
            "Shortener, tunnel-domain and TLD reputation lists",
        ],
        limitations=[
            "The URL is never fetched, resolved, or opened; content-based "
            "phishing cannot be seen from the outside.",
            "A clean score is not proof of safety — novel phishing "
            "infrastructure can look harmless.",
            "Brand and TLD checks use built-in lists and can miss less "
            "common brands.",
            "Shortened or heavily encoded URLs hide their true destination "
            "from static analysis.",
        ],
    )

    lowered = url.lower()
    scheme_match = re.match(r"^([a-z][a-z0-9+.\-]*):", lowered)
    if scheme_match and scheme_match.group(1) in ("javascript", "data",
                                                  "vbscript", "file"):
        rep.add(Finding(
            "URL_DANGEROUS_SCHEME",
            f"Non-web/executable URL scheme '{scheme_match.group(1)}:'",
            "high", 40,
            "URLs with this scheme are used to smuggle code or local files "
            "and should never be trusted in links."))
        return rep

    if "://" not in url and not scheme_match:
        url = "http://" + url
        rep.limitations.insert(
            0, "No scheme was supplied; the URL was analyzed as 'http://'. "
               "If the real site uses HTTPS, HTTP-related findings may not "
               "apply.")
        lowered = url.lower()

    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise ValueError(f"Could not parse URL: {exc}") from None

    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("Could not extract a hostname from the supplied URL.")
    scheme = parts.scheme or ""

    try:
        port = parts.port
    except ValueError:
        port = None
        rep.add(Finding("URL_MALFORMED_PORT", "Malformed port in URL",
                        "low", 5, "The port component of the URL is invalid."))

    ip_obj = None
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        pass

    labels = host.split(".")
    path_l = urllib.parse.unquote(parts.path or "").lower()
    query_l = urllib.parse.unquote(parts.query or "").lower()
    full_l = f"{path_l}?{query_l}" if query_l else path_l

    # -- 'user@host' display trick ------------------------------------------
    if "@" in (parts.netloc or "") and parts.username:
        rep.add(Finding(
            "URL_USERINFO", "URL embeds a 'user@host' section (display trick)",
            "high", 30,
            f"Netloc '{parts.netloc}' — browsers render everything before "
            f"'@' as a hint while the real host follows it."))

    # -- bare-IP host ---------------------------------------------------------
    if ip_obj is not None:
        private_note = ("private/reserved range" if ip_obj.is_private
                        else "publicly routable")
        rep.add(Finding(
            "URL_IP_HOST", "URL host is a bare IP address",
            "medium" if ip_obj.is_private else "high",
            15 if ip_obj.is_private else 25,
            f"Host '{host}' ({private_note}) — no registrable domain "
            f"reputation to assess; common in kit staging, also common in "
            f"internal testing."))

    # -- punycode / homograph --------------------------------------------------
    puny_labels = [l for l in labels if l.lower().startswith("xn--")]
    has_non_ascii = any(ord(ch) > 127 for ch in parts.netloc)
    if puny_labels or has_non_ascii:
        decoded_parts = []
        for l in labels:
            if l.lower().startswith("xn--"):
                try:
                    decoded_parts.append(l.encode("ascii").decode("idna"))
                    continue
                except (UnicodeError, ValueError):
                    decoded_parts.append(l)
            else:
                decoded_parts.append(l)
        decoded = ".".join(decoded_parts)
        brand_hit = next((b for b in BRANDS if b in decoded.lower()), None)
        if brand_hit:
            rep.add(Finding(
                "URL_PUNYCODE_BRAND",
                "Internationalized/punycode host appears to imitate a brand",
                "high", 35,
                f"Punycode host decodes to '{decoded}' containing brand term "
                f"'{brand_hit}' — classic homograph pattern."))
        else:
            rep.add(Finding(
                "URL_PUNYCODE", "Punycode/IDN or non-ASCII hostname",
                "medium", 15,
                f"Host contains punycode/non-ASCII labels (decoded: "
                f"'{truncate(decoded, 80)}') — legitimate international "
                f"domains use this, as do homograph attacks.",
                "inconclusive"))

    # -- brand impersonation in hostname ---------------------------------------
    official = _host_is_official(host)
    if ip_obj is None and not official:
        hit_label = next((l for l in labels if any(b in l for b in BRANDS)),
                         None)
        hit_brand = (next((b for b in BRANDS if b in hit_label), None)
                     if hit_label else None)
        if hit_label and hit_brand:
            tokenized = any(t in hit_label or t in host
                            for t in SUSPICIOUS_TOKENS)
            if hit_label == hit_brand or tokenized:
                rep.add(Finding(
                    "URL_BRAND_HOST",
                    f"Brand name '{hit_brand}' in a hostname that is not an "
                    f"official '{BRANDS[hit_brand]}' domain",
                    "high", 30,
                    f"Host '{host}' contains brand term '{hit_brand}'; the "
                    f"official domain is '{BRANDS[hit_brand]}'."))
            else:
                rep.add(Finding(
                    "URL_BRAND_HOST_SOFT",
                    f"Brand term '{hit_brand}' appears in an unofficial hostname",
                    "low", 8,
                    f"Host '{host}' — could be a fan/support/regional site, "
                    f"or a lure.", "inconclusive"))

    # -- typosquat ---------------------------------------------------------------
    if ip_obj is None and not official and len(labels) >= 2:
        registrable = ".".join(labels[-2:])
        base_label = labels[-2]
        typo_found = False
        for dom in OFFICIAL_SUFFIXES:
            if registrable == dom:
                continue
            if _levenshtein(registrable, dom) <= 2:
                rep.add(Finding(
                    "URL_TYPOSQUAT",
                    f"Registrable domain '{registrable}' is lexically close "
                    f"to official domain '{dom}'",
                    "high", 30,
                    f"Edit distance <= 2 between '{registrable}' and "
                    f"'{dom}' — typical typosquatting."))
                typo_found = True
                break
        if not typo_found:
            norm = base_label.translate(_CHAR_SUBS)
            for brand, dom in BRANDS.items():
                if (len(brand) >= 5 and abs(len(base_label) - len(brand)) <= 3
                        and norm.startswith(brand)):
                    rep.add(Finding(
                        "URL_TYPOSQUAT",
                        f"Host label '{base_label}' resembles official domain "
                        f"'{dom}' after common character substitutions",
                        "high", 30,
                        f"'{base_label}' normalizes to '{norm}', which starts "
                        f"with the brand '{brand}' (official: {dom})."))
                    break

    # -- brand term in path --------------------------------------------------------
    if ip_obj is None and not official:
        brand_path = next((b for b in BRANDS if b in full_l), None)
        if brand_path and not any(
                f.rule_id in ("URL_BRAND_HOST", "URL_TYPOSQUAT",
                              "URL_PUNYCODE_BRAND") for f in rep.findings):
            rep.add(Finding(
                "URL_BRAND_PATH",
                f"Brand term '{brand_path}' appears in the URL path/query on "
                f"a non-official host",
                "low", 12,
                f"Path/query references '{brand_path}' while host '{host}' "
                f"is not an official '{BRANDS[brand_path]}' domain — "
                f"possible lure.", "inconclusive"))

    # -- reverse-tunnel hosting (Zphisher exposure pattern) -------------------------
    if _is_tunnel(host):
        rep.add(Finding(
            "URL_TUNNEL_HOST", "Hosted on a reverse-tunnel / forwarding domain",
            "high", 25,
            f"'{host}' is a tunnel domain. Zphisher-family kits expose the "
            f"local credential listener this way; developers also use "
            f"tunnels legitimately.", "zphisher"))

    # -- shortener ---------------------------------------------------------------------
    bare = host[4:] if host.startswith("www.") else host
    if bare in SHORTENERS:
        rep.add(Finding(
            "URL_SHORTENER", "Known URL-shortener domain — destination hidden",
            "medium", 15,
            f"'{host}' is a shortener; expand the link before judging it.",
            "inconclusive"))

    # -- risky TLD ------------------------------------------------------------------------
    if ip_obj is None and len(labels) > 1 and labels[-1] in RISKY_TLDS:
        rep.add(Finding(
            "URL_RISKY_TLD", f"URL uses the high-abuse TLD '.{labels[-1]}'",
            "low", 8,
            f"'{labels[-1]}' domains are cheap and heavily abused, though "
            f"many legitimate sites use them too.", "inconclusive"))

    # -- open-redirect parameters and encodings ----------------------------------------------
    try:
        qs = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    except ValueError:
        qs = {}
    for key, values in qs.items():
        if key.lower() not in REDIRECT_PARAMS:
            continue
        for val in values:
            decoded_val = urllib.parse.unquote(val)
            if (decoded_val.lower().startswith(("http://", "https://"))
                    or "://" in decoded_val.lower()):
                rep.add(Finding(
                    "URL_OPENREDIRECT_PARAM",
                    f"Open-redirect parameter '{key}' carries an absolute URL",
                    "medium", 18,
                    f"'{key}={truncate(val, 120)}' — frequently abused to "
                    f"bounce victims through a trusted domain."))
                break
            if (re.fullmatch(r"[A-Za-z0-9+/=]{16,}", val)
                    and _b64_contains(val, ("http", "redirect"))):
                rep.add(Finding(
                    "URL_OPENREDIRECT_PARAM",
                    f"Open-redirect parameter '{key}' carries a base64 "
                    f"destination",
                    "medium", 18,
                    f"'{key}={truncate(val, 80)}' decodes to URL/redirect "
                    f"content (decoded for inspection only)."))
                break
    if re.search(r"https?%3a|%2f%2f", lowered):
        rep.add(Finding(
            "URL_ENCODED_NESTED", "Percent-encoded nested URL inside the URL",
            "medium", 15,
            "Patterns like 'https%3A%2F%2F…' or '%2F%2F' indicate a URL "
            "smuggled inside another URL (redirect chaining)."))

    # -- credential-luring keywords -------------------------------------------------------------
    cred_hits = sorted({k for k in CRED_KEYWORDS if k in full_l or k in host})
    if cred_hits:
        rep.add(Finding(
            "URL_CRED_KEYWORDS", "Credential-luring keywords in the URL",
            "low", 8, "Found: " + ", ".join(cred_hits[:8]), "inconclusive"))
        if scheme == "http":
            rep.add(Finding(
                "URL_HTTP_CREDS",
                "Credential-related URL served over plaintext HTTP",
                "medium", 15,
                "No transport encryption on a URL whose keywords suggest it "
                "will handle credentials."))

    # -- structural heuristics ---------------------------------------------------------------------
    if len(url) > 100:
        rep.add(Finding("URL_LONG", "Unusually long URL", "low", 4,
                        f"Length {len(url)} characters."))
    if ip_obj is None and len(labels) >= 5:
        rep.add(Finding("URL_DEEP_SUBDOM", "Deeply nested subdomains",
                        "low", 6,
                        f"{len(labels)} DNS labels — brand names are often "
                        f"planted in subdomains.", "inconclusive"))
    if ip_obj is None and any(len(l) > 30 for l in labels):
        rep.add(Finding("URL_LONG_LABEL", "Very long DNS label", "low", 5,
                        "Long labels can hide a brand name at the far right "
                        "of the host."))
    if ip_obj is None and host.count("-") >= 3:
        rep.add(Finding("URL_MANY_HYPHENS", "Hyphen-heavy hostname", "low", 5,
                        f"{host.count('-')} hyphens — a common pattern in "
                        f"generated phishing hosts."))
    if (ip_obj is None and len(host) > 6
            and sum(ch.isdigit() for ch in host) / len(host) > 0.3):
        rep.add(Finding("URL_DIGIT_HOST", "Digit-heavy hostname", "low", 8,
                        f"Host '{host}'.", "inconclusive"))
    if port not in (None, 80, 443):
        rep.add(Finding("URL_ODD_PORT", "Non-standard port in URL", "low", 6,
                        f"Port {port} — phishing listeners often run on "
                        f"alternate ports."))
    if re.search(r"\.(exe|apk|scr|msi|zip|rar|7z|jar|hta|iso)(?:[?#]|$)",
                 path_l):
        rep.add(Finding("URL_EXECUTABLE",
                        "URL points at an executable/archive file", "low", 10,
                        f"Path ends with a binary/archive extension: "
                        f"{truncate(parts.path, 80)}"))
    return rep


# ============================================================================
# Mode 2 — Local HTML analysis (static only; JavaScript is never executed)
# ============================================================================

class _PageParser(HTMLParser):
    """Collects forms, inputs, metas, script sources, inline handlers and
    script text. Lenient by design: malformed markup is recovered, never
    executed."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._current: Optional[dict] = None
        self.metas: list[dict] = []
        self.script_srcs: list[str] = []
        self.iframes: list[str] = []
        self.inline_handlers: list[tuple[str, str, str]] = []
        self._script_chunks: list[str] = []
        self.script_text: str = ""
        self._depth_script = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        d: dict[str, str] = {}
        for k, v in attrs:
            k = (k or "").lower()
            if k not in d:
                d[k] = v or ""
        if tag not in ("body", "html"):
            for k, v in d.items():
                if k.startswith("on") and v:
                    self.inline_handlers.append((tag, k, v))
        if tag == "meta":
            self.metas.append(d)
        elif tag == "form":
            if self._current is not None:
                self.forms.append(self._current)
            self._current = {"action": d.get("action", ""),
                             "method": d.get("method", "get"), "inputs": []}
        elif tag == "input" and self._current is not None:
            self._current["inputs"].append(
                ((d.get("type") or "text").lower(), (d.get("name") or "").lower()))
        elif tag == "textarea" and self._current is not None:
            self._current["inputs"].append(
                ("textarea", (d.get("name") or "").lower()))
        elif tag == "script":
            self._depth_script += 1
            if d.get("src"):
                self.script_srcs.append(d["src"])
        elif tag == "iframe" and d.get("src"):
            self.iframes.append(d["src"])

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "script" and self._depth_script:
            self._depth_script -= 1
        elif tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def handle_data(self, data):
        if self._depth_script:
            self._script_chunks.append(data)


def _parse_html(text: str) -> tuple[_PageParser, str]:
    parser = _PageParser()
    err = ""
    try:
        parser.feed(text)
    except Exception as exc:  # malformed markup: keep recovered portion
        err = f"{type(exc).__name__}: {exc}"
    if parser._current is not None:
        parser.forms.append(parser._current)
        parser._current = None
    parser.script_text = "\n".join(parser._script_chunks)
    return parser, err


def _form_has_password(form: dict) -> bool:
    for ftype, fname in form.get("inputs", []):
        if ftype == "password":
            return True
        if fname in CRED_INPUT_NAMES and ftype in ("", "text", "password"):
            return True
    return False


def analyze_html_content(text: str, source: str) -> Report:
    rep = Report(
        target=source,
        mode="Mode 2 — Local HTML analysis",
        methods=[
            "Static HTML parsing (stdlib HTMLParser — JavaScript never executed)",
            "Credential-form and form-destination analysis",
            "Meta-refresh and JavaScript redirect detection (pattern-based)",
            "JavaScript obfuscation / packer / base64 payload scan",
            "Built-in Zphisher-family structural signatures",
        ],
        limitations=[
            "Static analysis only — runtime behavior (fetched scripts, "
            "dynamic DOM) is invisible.",
            "A saved copy of a legitimate login page can resemble a phishing "
            "page; provenance matters.",
            "Obfuscation checks are pattern-based: custom obfuscation may "
            "evade them, and heavy minification can trigger them.",
            "Browsers sometimes rewrite form actions when pages are saved, "
            "which can confuse destination analysis.",
        ],
    )

    parser, parse_err = _parse_html(text)
    if parse_err:
        rep.limitations.insert(
            0, f"Malformed markup encountered; analysis continued on the "
               f"recovered portion ({truncate(parse_err, 90)}).")

    raw = text
    script_text = parser.script_text
    forms = parser.forms
    has_pw = any(_form_has_password(f) for f in forms)
    pw_form = next((f for f in forms if _form_has_password(f)), None)

    # 1) credential form (context — a login page alone is NOT suspicious) ------
    if pw_form is not None:
        fields = ", ".join(sorted({n or t for (t, n) in pw_form["inputs"]}))
        rep.add(Finding(
            "HTML_CRED_FORM",
            "Credential form present (context — not suspicious on its own)",
            "info", 0,
            f"action='{pw_form.get('action') or '(self)'}' "
            f"method='{(pw_form.get('method') or 'get').lower()}'; "
            f"fields: {truncate(fields, 120)}"))

    # 2) form destinations -------------------------------------------------------
    for form in forms:
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "get").lower()
        form_pw = _form_has_password(form)
        if form_pw and method == "get":
            rep.add(Finding(
                "HTML_GET_CREDS", "Credential form submits via GET",
                "medium", 15,
                "GET places credentials into URLs and server logs — bad "
                "practice on any site, and a fingerprint of lazy kit "
                "templates."))
        a = action.lower()
        if a.startswith("javascript:"):
            rep.add(Finding(
                "HTML_ACTION_JAVASCRIPT", "Form action is a 'javascript:' URL",
                "high", 30,
                f"action='{truncate(action, 120)}' — script-driven "
                f"submission, common in kit templates."))
            continue
        if action.startswith("http://") or action.startswith("https://"):
            if a.startswith("http://"):
                rep.add(Finding(
                    "HTML_ACTION_INSECURE", "Form submits over plaintext HTTP",
                    "medium" if form_pw else "low", 12 if form_pw else 6,
                    f"action='{truncate(action, 120)}' — submitted "
                    f"credentials would travel unencrypted."))
            ahost = _host_of(action)
            if not ahost:
                continue
            if _is_tunnel(ahost):
                rep.add(Finding(
                    "HTML_ACTION_TUNNEL", "Form submits to a reverse-tunnel host",
                    "high" if form_pw else "medium", 25 if form_pw else 15,
                    f"action='{truncate(action, 120)}' — tunnel endpoints "
                    f"are the standard exposure method for Zphisher-family "
                    f"listeners.", "zphisher" if form_pw else "generic"))
            elif _host_is_official(ahost):
                if form_pw:
                    rep.add(Finding(
                        "HTML_ACTION_BRAND",
                        f"Credential form posts to the real brand domain "
                        f"'{ahost}'", "medium", 12,
                        "Typical of a saved copy of the genuine page; a few "
                        "clone kits also keep the original endpoint.",
                        "inconclusive"))
            elif form_pw:
                rep.add(Finding(
                    "HTML_ACTION_EXTERNAL",
                    "Credential form submits to an external origin",
                    "medium", 18,
                    f"action='{truncate(action, 120)}' — for a locally "
                    f"supplied file, off-origin submission cannot be "
                    f"verified as legitimate."))
            else:
                rep.add(Finding(
                    "HTML_ACTION_EXTERNAL_DATA",
                    "Form submits data to an external origin", "low", 10,
                    f"action='{truncate(action, 120)}'."))
        else:
            handler_name = (action.split("?")[0].split("#")[0]
                            .rstrip("/").rsplit("/", 1)[-1].lower())
            if handler_name in KIT_HANDLERS:
                if form_pw:
                    rep.add(Finding(
                        "HTML_ACTION_KIT_HANDLER",
                        f"Credential form submits to a bare PHP handler "
                        f"('{handler_name}')", "medium", 20,
                        f"action='{action}' — kit templates typically POST "
                        f"credentials to a same-directory PHP handler that "
                        f"stores or forwards them.", "zphisher"))
                else:
                    rep.add(Finding(
                        "HTML_ACTION_KIT_HANDLER",
                        f"Form submits to a bare PHP handler "
                        f"('{handler_name}')", "low", 10,
                        f"action='{action}'.", "inconclusive"))

    # 3) meta-refresh redirects -----------------------------------------------------
    for meta in parser.metas:
        if (meta.get("http-equiv") or "").strip().lower() != "refresh":
            continue
        content = meta.get("content") or ""
        m = re.match(r"\s*(\d+)\s*;\s*url\s*=\s*['\"]?([^'\";]+)", content,
                     re.IGNORECASE)
        if not m:
            continue
        delay = int(m.group(1))
        target = m.group(2).strip()
        thost = _host_of(target)
        if _is_tunnel(thost):
            rep.add(Finding(
                "HTML_META_TUNNEL", "Meta-refresh redirect to a tunnel host",
                "high", 22, f"content='{truncate(content, 100)}'",
                "zphisher"))
        elif _host_is_official(thost):
            if has_pw and delay <= 3:
                rep.add(Finding(
                    "HTML_META_BRAND_REDIRECT",
                    f"Instant redirect to the legitimate site '{thost}' "
                    f"alongside a credential form (harvest-and-forward "
                    f"pattern)", "medium", 22,
                    f"meta refresh delay={delay}s → "
                    f"'{truncate(target, 100)}' — after capturing "
                    f"credentials, kits bounce victims to the real site to "
                    f"avoid suspicion.", "zphisher"))
            else:
                rep.add(Finding(
                    "HTML_META_EXTERNAL",
                    "Fast meta-refresh redirect to another site", "low", 10,
                    f"meta refresh delay={delay}s → "
                    f"'{truncate(target, 100)}'.", "inconclusive"))
        elif thost and delay <= 3:
            rep.add(Finding(
                "HTML_META_EXTERNAL",
                "Fast meta-refresh redirect to an external host",
                "medium", 12,
                f"meta refresh delay={delay}s → '{truncate(target, 100)}'."))
        else:
            rep.add(Finding(
                "HTML_META_EXTERNAL", "Meta-refresh redirect present",
                "low", 6, f"content='{truncate(content, 100)}'.",
                "inconclusive"))

    # 4) JavaScript redirects (static patterns only — never executed) ----------------
    js_targets: list[str] = []
    for rx in (r"location(?:\.href)?\s*=\s*['\"]([^'\"]{4,200})['\"]",
               r"location\.replace\s*\(\s*['\"]([^'\"]{4,200})['\"]",
               r"location\.assign\s*\(\s*['\"]([^'\"]{4,200})['\"]"):
        for m in re.finditer(rx, script_text):
            js_targets.append(m.group(1))
    for t in dict.fromkeys(js_targets):
        thost = _host_of(t)
        if thost and _host_is_official(thost) and has_pw:
            rep.add(Finding(
                "HTML_JS_BRAND_REDIRECT",
                f"JavaScript redirects to the legitimate domain '{thost}' "
                f"while a credential form is present", "medium", 22,
                f"script contains redirect to '{truncate(t, 100)}' — "
                f"harvest-and-forward pattern.", "zphisher"))
        elif t.lower().startswith(("http://", "https://")):
            rep.add(Finding(
                "HTML_JS_REDIRECT", "JavaScript redirects to an external URL",
                "low", 10,
                f"redirect target: '{truncate(t, 100)}' (static pattern; "
                f"script not executed).", "inconclusive"))

    # 5) obfuscation / payloads ----------------------------------------------------------
    obf_counts = {
        name: len(re.findall(rx, raw))
        for name, rx in (
            ("eval()", r"\beval\s*\("),
            ("atob()", r"\batob\s*\("),
            ("unescape()", r"\bunescape\s*\("),
            ("String.fromCharCode", r"String\.fromCharCode"),
            ("document.write()", r"document\.write\s*\("),
            ("new Function()", r"new\s+Function\s*\("),
        )
    }
    present = [k for k, v in obf_counts.items() if v]
    if present:
        rep.add(Finding(
            "HTML_OBFUSCATION",
            "Dynamic/obfuscated JavaScript patterns present (never executed)",
            "medium", 18,
            ", ".join(f"{k} x{obf_counts[k]}" for k in present)
            + " — common in legitimate apps as well; presence alone is not "
              "proof of malice."))
    if re.search(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,"
                 r"\s*e\s*,\s*d", raw):
        rep.add(Finding(
            "HTML_PACKER", "JavaScript packer signature (p,a,c,k,e,d)",
            "medium", 25,
            "Signature of the classic Dean Edwards packer, heavily used to "
            "hide kit payloads."))
    hex_count = len(re.findall(r"\\x[0-9a-fA-F]{2}", raw))
    if hex_count >= 30:
        rep.add(Finding(
            "HTML_HEX_BLOB", "Dense hex-escape obfuscation in script content",
            "medium", 18, f"{hex_count} '\\xNN' sequences detected."))
    for blob in dict.fromkeys(re.findall(r"[A-Za-z0-9+/=]{32,}", raw)):
        decoded = _try_b64_decode(blob)
        if decoded and re.search(r"https?://|password|passwd|location|token",
                                 decoded, re.IGNORECASE):
            rep.add(Finding(
                "HTML_B64_PAYLOAD",
                "Base64 payload decodes to URL/credential/redirect content",
                "high", 25,
                f"decoded sample: {truncate(decoded, 120)!r} (decoded for "
                f"inspection only — nothing is executed)."))
            break

    # 6) inline handlers wiring inputs/forms to network or navigation --------------------
    for tag, attr, val in parser.inline_handlers:
        if tag in ("input", "form") and re.search(
                r"fetch\s*\(|XMLHttpRequest|\.send\s*\(|location\s*[.=]|"
                r"\.href\s*=", val or ""):
            rep.add(Finding(
                "HTML_HANDLER_EXFIL",
                "Inline event handler wires an input/form to network or "
                "navigation", "medium", 15,
                f"<{tag} {attr}='{truncate(val, 120)}'>"))
            break

    # 7) external scripts / iframes ---------------------------------------------------------
    for src in parser.script_srcs:
        shost = _host_of(src)
        if _is_tunnel(shost):
            rep.add(Finding(
                "HTML_EXT_SCRIPT_TUNNEL",
                "External script loaded from a reverse-tunnel host",
                "medium", 18, f"script src='{truncate(src, 120)}'."))
        elif shost and _is_risky_tld(shost):
            rep.add(Finding(
                "HTML_EXT_SCRIPT_RISKY",
                "External script loaded from a high-abuse TLD", "low", 12,
                f"script src='{truncate(src, 120)}'.", "inconclusive"))
        elif src.lower().startswith("http://") and has_pw:
            rep.add(Finding(
                "HTML_INSECURE_SCRIPT",
                "Script loaded over plaintext HTTP on a credential page",
                "low", 10, f"script src='{truncate(src, 120)}'."))
    if has_pw:
        for src in parser.iframes:
            shost = _host_of(src)
            if shost and not _host_is_official(shost):
                rep.add(Finding(
                    "HTML_IFRAME_EXTERNAL",
                    "External iframe embedded on a credential page",
                    "low", 10, f"iframe src='{truncate(src, 120)}'.",
                    "inconclusive"))
                break

    # 8) brand mentions on a credential page (possible impersonation) ------------------------
    low_raw = raw.lower()
    best_brand, best_count = None, 0
    for brand in BRANDS:
        c = low_raw.count(brand)
        if c > best_count:
            best_brand, best_count = brand, c
    if best_brand and has_pw:
        rep.add(Finding(
            "HTML_BRAND_MENTION",
            f"Page references '{best_brand}' branding while hosting "
            f"provenance is unverified", "medium", 15,
            f"'{best_brand}' appears {best_count} time(s) and the page "
            f"contains a credential form — possible impersonation, or a "
            f"saved copy of the legitimate page.", "inconclusive"))

    # 9) Zphisher-family structural combination -----------------------------------------------
    kit_trigger = any(f.rule_id in ("HTML_ACTION_KIT_HANDLER",
                                    "HTML_ACTION_TUNNEL", "HTML_META_TUNNEL")
                      for f in rep.findings)
    brand_redirect = any(f.rule_id in ("HTML_META_BRAND_REDIRECT",
                                       "HTML_JS_BRAND_REDIRECT")
                         for f in rep.findings)
    if has_pw and kit_trigger and brand_redirect:
        ev = "; ".join(
            f"{f.rule_id}: {truncate(f.evidence, 90)}"
            for f in rep.findings
            if f.rule_id in ("HTML_ACTION_KIT_HANDLER", "HTML_ACTION_TUNNEL",
                             "HTML_META_TUNNEL", "HTML_META_BRAND_REDIRECT",
                             "HTML_JS_BRAND_REDIRECT"))
        rep.add(Finding(
            "HTML_ZP_COMBO",
            "Credential form + kit-style handler/tunnel + instant redirect "
            "to the legitimate brand — structural pattern of Zphisher-family "
            "templates", "high", 25, ev, "zphisher"))
    return rep


def analyze_html_file(path: Path) -> Report:
    p = Path(path)
    if p.is_dir():
        raise IsADirectoryError(str(p))
    if not p.is_file():
        raise FileNotFoundError(str(p))
    with p.open("rb") as fh:
        data = fh.read(MAX_HTML_BYTES)
    text = data.decode("utf-8", errors="replace")
    rep = analyze_html_content(text, str(p))
    if p.stat().st_size > MAX_HTML_BYTES:
        rep.limitations.insert(
            0, f"File is larger than {MAX_HTML_BYTES // (1024 * 1024)} MB; "
               f"only the first portion was analyzed.")
    return rep


# ============================================================================
# Mode 3 — Server log analysis (offline; no third-party servers contacted)
# ============================================================================

def analyze_log_content(text: str, source: str) -> Report:
    rep = Report(
        target=source,
        mode="Mode 3 — Server log analysis",
        methods=[
            "Common/Combined Log Format parsing (offline, regex)",
            "Request-path signature matching against kit indicators",
            "Encoded-redirect query inspection",
            "Per-client-IP aggregation of suspicious requests",
        ],
        limitations=[
            "Logs show requests that reached the server, not their outcomes; "
            "a hit is an indicator, not proof.",
            "Only Common/Combined Log Format is understood; other formats "
            "may parse poorly.",
            "No third-party servers are contacted; analysis is limited to "
            "the supplied file.",
        ],
    )
    lines = text.splitlines()
    total = parsed = 0
    grouped: dict[str, dict] = {}
    ip_counts: dict[str, int] = {}
    for line in lines[:MAX_LOG_LINES]:
        if not line.strip():
            continue
        total += 1
        m = LOG_LINE_RE.match(line)
        if not m:
            continue
        parsed += 1
        d = m.groupdict()
        method = (d.get("method") or "").upper()
        path = d.get("path") or ""
        client = d.get("ip") or "?"
        low = urllib.parse.unquote(path).lower()
        base = low.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
        hit: Optional[tuple[str, str, str, int]] = None
        if method == "POST" and base in KIT_HANDLERS:
            hit = ("LOG_KIT_POST",
                   "POST to a bare PHP handler commonly used by "
                   "Zphisher-family kits", "zphisher", 20)
        elif base in KIT_HANDLERS:
            hit = ("LOG_KIT_PATH", "Request for a kit-style PHP handler path",
                   "zphisher", 12)
        elif any(name in low for name in KIT_ARTIFACT_NAMES):
            hit = ("LOG_KIT_ARTIFACT",
                   "Request path matches credential-store filenames used by "
                   "several kits", "zphisher", 18)
        elif (any(b in low for b in BRANDS)
              and any(k in low for k in ("login", "signin", "verify"))):
            hit = ("LOG_KIT_BRANDPATH",
                   "Brand-name login path pattern (e.g., "
                   "'/facebook/login.html') served from one host",
                   "zphisher", 12)
        elif re.search(r"(?:^|[?&])(?:url|redirect|next|goto)=https?%3a|"
                       r"https?%3a|%2f%2f", low):
            hit = ("LOG_ENCODED_REDIRECT",
                   "Query string carries an encoded/absolute redirect target",
                   "generic", 12)
        elif any(seg in low for seg in ("/.env", "/.git", "/.aws",
                                        "/wp-admin", "/phpmyadmin")):
            hit = ("LOG_RECON",
                   "Automated recon/probing pattern in request path",
                   "inconclusive", 6)
        if hit is None:
            continue
        ip_counts[client] = ip_counts.get(client, 0) + 1
        g = grouped.setdefault(hit[0], {"meta": hit, "count": 0,
                                        "samples": []})
        g["count"] += 1
        if len(g["samples"]) < 3:
            g["samples"].append(line)

    if total and parsed < total:
        rep.limitations.insert(
            0, f"{total - parsed} of {total} line(s) did not match "
               f"Common/Combined Log Format and were skipped.")
    if total == 0:
        rep.limitations.insert(0, "No log lines were found in the file.")
    if len(lines) > MAX_LOG_LINES:
        rep.limitations.append(
            f"Log truncated to the first {MAX_LOG_LINES} lines.")

    ip_summary = (", ".join(f"{ip} ({n})" for ip, n in
                            sorted(ip_counts.items(),
                                   key=lambda kv: -kv[1])[:5])
                  or "n/a")
    for rid, g in grouped.items():
        meta = g["meta"]
        samples = " || ".join(truncate(s, 130) for s in g["samples"])
        rep.add(Finding(
            rid, meta[1],
            "medium" if meta[3] >= 18 else ("low" if meta[3] >= 10 else "info"),
            meta[3],
            f"{g['count']} matching request(s). Client IP(s): {ip_summary}. "
            f"Sample line(s): {samples}",
            meta[2], count=g["count"]))
    return rep


def analyze_log_file(path: Path) -> Report:
    p = Path(path)
    if p.is_dir():
        raise IsADirectoryError(str(p))
    if not p.is_file():
        raise FileNotFoundError(str(p))
    with p.open("rb") as fh:
        data = fh.read(MAX_LOG_BYTES)
    return analyze_log_content(data.decode("utf-8", errors="replace"), str(p))


# ============================================================================
# Mode 4 — Optional threat intelligence (Google Safe Browsing)
# ----------------------------------------------------------------------------
# This is the ONLY part of the module that touches the network. Everything
# above works fully offline with no API key.
# ============================================================================

def query_safe_browsing(url: str, api_key: str,
                        timeout: float = NETWORK_TIMEOUT) -> dict:
    """POST the URL to Safe Browsing v4 threatMatches.find.

    Only the URL string is transmitted. The API key is read from the
    environment and is never printed, logged, or embedded in evidence.
    """
    body = {
        "client": {"clientId": "phishing-link-zphisher-detector",
                   "clientVersion": MODULE_VERSION},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    request = urllib.request.Request(
        f"{GSB_ENDPOINT}?key={urllib.parse.quote(api_key, safe='')}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read().decode("utf-8", errors="replace")
    return json.loads(payload) if payload else {}


def _confirm_send(url: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    try:
        if not sys.stdin or not sys.stdin.isatty():
            return False
        print(_yellow("\nThe URL (and only the URL string) will be sent over "
                      "HTTPS to Google Safe Browsing."))
        print(_yellow("No page content, no credentials, and no API key are "
                      "transmitted or displayed."))
        answer = input("Send this URL to the threat-intel provider? [y/N] "
                       ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def check_threat_intel(url: str, assume_yes: bool = False) -> Report:
    rep = analyze_url(url)   # offline layer always runs first
    rep.mode = "Mode 4 — Threat intelligence + offline URL analysis"
    rep.methods.append("Google Safe Browsing v4 threatMatches lookup "
                       "(optional; network)")
    rep.limitations.append("A 'no matches' result from Safe Browsing does "
                           "NOT guarantee the URL is safe.")

    api_key = os.environ.get(GSB_ENV_VAR, "").strip()
    if not api_key:
        rep.add(Finding(
            "INTEL_OFFLINE",
            "No API key configured — Safe Browsing lookup skipped "
            "(local-only mode)", "info", 0,
            f"Set the {GSB_ENV_VAR} environment variable to enable this "
            f"layer. All offline detection above still applies."))
        return rep

    if not _confirm_send(url, assume_yes):
        rep.add(Finding(
            "INTEL_SKIPPED",
            "Threat-intel lookup skipped — user did not consent to sending "
            "the URL", "info", 0,
            "Only the offline results above are shown."))
        return rep

    try:
        data = query_safe_browsing(url, api_key)
    except urllib.error.HTTPError as exc:
        rep.add(Finding(
            "INTEL_ERROR", f"Threat-intel request failed (HTTP {exc.code})",
            "info", 0,
            "Check the API key and quota. The key is never displayed or "
            "logged by this tool."))
        return rep
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        rep.add(Finding(
            "INTEL_ERROR",
            f"Threat-intel request failed ({type(exc).__name__})",
            "info", 0, truncate(str(exc), 120)))
        return rep
    except ValueError:
        rep.add(Finding(
            "INTEL_ERROR", "Threat-intel response could not be parsed",
            "info", 0, "Provider returned a non-JSON payload."))
        return rep

    matches = data.get("matches") or []
    if matches:
        threat_types = sorted({str(m.get("threatType")) for m in matches})
        rep.add(Finding(
            "INTEL_LISTED",
            "URL is listed in Google Safe Browsing as a known threat",
            "high", 45, f"threatType(s): {', '.join(threat_types)}"))
    else:
        rep.add(Finding(
            "INTEL_CLEAN",
            "Google Safe Browsing returned no matches for this URL",
            "info", 0,
            "Absence from the list is not proof of safety; new phishing "
            "pages are indexed continuously."))
    return rep


# ============================================================================
# Rule catalogue (viewable from menu option 5)
# ============================================================================

RULE_CATALOGUE: list[tuple[str, list[tuple[str, object, str, str]]]] = [
    ("URL rules (Mode 1)", [
        ("URL_DANGEROUS_SCHEME", 40, "generic", "javascript:/data:/vbscript:/file: scheme"),
        ("URL_USERINFO", 30, "generic", "'user@host' display trick"),
        ("URL_BRAND_HOST", 30, "generic", "brand name in a non-official hostname"),
        ("URL_TYPOSQUAT", 30, "generic", "domain lexically close to an official brand domain"),
        ("URL_IP_HOST", "15-25", "generic", "bare IP host (private/reserved ranges weighted lower)"),
        ("URL_PUNYCODE_BRAND", 35, "generic", "punycode/IDN host imitating a brand"),
        ("URL_PUNYCODE", 15, "inconclusive", "punycode/IDN or non-ASCII host"),
        ("URL_TUNNEL_HOST", 25, "zphisher", "ngrok/serveo/trycloudflare/localtunnel/portmap host"),
        ("URL_OPENREDIRECT_PARAM", 18, "generic", "redirect-style parameter carrying an absolute URL"),
        ("URL_ENCODED_NESTED", 15, "generic", "percent-encoded nested URL"),
        ("URL_HTTP_CREDS", 15, "generic", "credential keywords over plaintext HTTP"),
        ("URL_SHORTENER", 15, "inconclusive", "known shortener host"),
        ("URL_BRAND_PATH", 12, "inconclusive", "brand name in path on a non-official host"),
        ("URL_EXECUTABLE", 10, "generic", "path ends in executable/archive extension"),
        ("URL_DIGIT_HOST", 8, "inconclusive", "digit-heavy hostname"),
        ("URL_RISKY_TLD", 8, "inconclusive", "high-abuse TLD"),
        ("URL_CRED_KEYWORDS", 8, "inconclusive", "credential-luring keywords"),
        ("URL_BRAND_HOST_SOFT", 8, "inconclusive", "brand term in unofficial host, no lure tokens"),
        ("URL_ODD_PORT", 6, "inconclusive", "non-standard port"),
        ("URL_DEEP_SUBDOM", 6, "inconclusive", "deep subdomain nesting"),
        ("URL_MANY_HYPHENS", 5, "inconclusive", "hyphen-heavy hostname"),
        ("URL_LONG_LABEL", 5, "inconclusive", "very long DNS label"),
        ("URL_MALFORMED_PORT", 5, "generic", "invalid port component"),
        ("URL_LONG", 4, "inconclusive", "unusually long URL"),
    ]),
    ("HTML rules (Mode 2)", [
        ("HTML_ZP_COMBO", 25, "zphisher", "cred form + kit handler/tunnel + brand redirect combo"),
        ("HTML_ACTION_TUNNEL", "15-25", "zphisher", "form submits to a reverse-tunnel host"),
        ("HTML_META_TUNNEL", 22, "zphisher", "meta-refresh to a tunnel host"),
        ("HTML_META_BRAND_REDIRECT", 22, "zphisher", "instant redirect to real brand after cred form"),
        ("HTML_JS_BRAND_REDIRECT", 22, "zphisher", "JS redirect to real brand alongside cred form"),
        ("HTML_ACTION_KIT_HANDLER", "10-20", "zphisher", "form posts to bare PHP handler (login.php, post.php…)"),
        ("HTML_ACTION_JAVASCRIPT", 30, "generic", "form action is 'javascript:'"),
        ("HTML_B64_PAYLOAD", 25, "generic", "base64 blob decodes to URL/credential content"),
        ("HTML_PACKER", 25, "generic", "JavaScript packer signature (p,a,c,k,e,d)"),
        ("HTML_ACTION_EXTERNAL", 18, "generic", "credential form submits to an external origin"),
        ("HTML_OBFUSCATION", 18, "generic", "eval/atob/unescape/fromCharCode patterns"),
        ("HTML_HEX_BLOB", 18, "generic", "dense '\\xNN' obfuscation"),
        ("HTML_EXT_SCRIPT_TUNNEL", 18, "generic", "external script from a tunnel host"),
        ("HTML_GET_CREDS", 15, "generic", "credential form submits via GET"),
        ("HTML_HANDLER_EXFIL", 15, "generic", "inline handler wires input/form to network"),
        ("HTML_BRAND_MENTION", 15, "inconclusive", "brand branding on unverified credential page"),
        ("HTML_ACTION_BRAND", 12, "inconclusive", "cred form posts to the real brand domain"),
        ("HTML_META_EXTERNAL", "6-12", "inconclusive", "meta-refresh redirect"),
        ("HTML_EXT_SCRIPT_RISKY", 12, "inconclusive", "external script from high-abuse TLD"),
        ("HTML_ACTION_INSECURE", "6-12", "generic", "form submits over plaintext HTTP"),
        ("HTML_ACTION_EXTERNAL_DATA", 10, "generic", "non-credential form submits off-origin"),
        ("HTML_JS_REDIRECT", 10, "inconclusive", "JS redirect to an external URL"),
        ("HTML_IFRAME_EXTERNAL", 10, "inconclusive", "external iframe on a credential page"),
        ("HTML_INSECURE_SCRIPT", 10, "generic", "script over HTTP on a credential page"),
        ("HTML_CRED_FORM", 0, "info", "credential form present (context, not suspicious alone)"),
    ]),
    ("Log rules (Mode 3)", [
        ("LOG_KIT_POST", 20, "zphisher", "POST to a bare PHP handler (login.php, post.php…)"),
        ("LOG_KIT_ARTIFACT", 18, "zphisher", "requests for credential-store filenames"),
        ("LOG_KIT_PATH", 12, "zphisher", "requests for kit-style PHP handler paths"),
        ("LOG_KIT_BRANDPATH", 12, "zphisher", "brand-name login path served from one host"),
        ("LOG_ENCODED_REDIRECT", 12, "generic", "encoded/absolute redirect in query string"),
        ("LOG_RECON", 6, "inconclusive", "automated recon probes (/.env, /.git, …)"),
    ]),
    ("Threat intelligence (Mode 4 — requires API key)", [
        ("INTEL_LISTED", 45, "generic", "URL present in Google Safe Browsing"),
        ("INTEL_CLEAN", 0, "info", "no matches (not proof of safety)"),
        ("INTEL_OFFLINE / INTEL_SKIPPED / INTEL_ERROR", 0, "info", "layer not applied"),
    ]),
]


def print_rules_catalogue() -> None:
    print(_bold("\nDETECTION RULE CATALOGUE (built-in, local — nothing is "
                "downloaded)"))
    print(_c("Weights are heuristic triage points, not probabilities. The "
             "report score is the capped sum of triggered weights."))
    print(_c("Attribution legend:  generic = general phishing indicator · "
             "zphisher = pattern shared by Zphisher-family kits · "
             "inconclusive = context-dependent\n"))
    for group, rules in RULE_CATALOGUE:
        print(_cyan(f"  {group}"))
        for rid, weight, attr, desc in rules:
            print(f"    {rid:<40} +{str(weight):<6} [{attr:<12}] {desc}")
        print()
    print(_c("  Zphisher attribution is reported as 'possible' only when "
             "multiple kit-pattern indicators co-occur."))
    print(_c("  Structural signals (bare PHP handlers, harvest-and-forward "
             "redirects, tunnel hosting) carry more attribution weight than "
             "cosmetic ones (brand words, TLDs)."))


# ============================================================================
# Report rendering
# ============================================================================

WIDTH = 66


def _hr(ch: str = "─") -> str:
    return ch * WIDTH


def print_report(rep: Report) -> None:
    score = rep.score()
    conf = rep.confidence()
    verdict, verdict_note = rep.verdict()
    zfinds = rep.zphisher_findings()

    print()
    print(_bold(_hr("═")))
   
    print(_bold(_hr("═")))
    print(f"Target      : {rep.target}")
    print(f"Mode        : {rep.mode}")
    print(f"Generated   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Methods used:")
    for mth in rep.methods:
        print(f"  {_c('•')} {mth}")
    print(_c(_hr()))

    print(_bold("Suspicious indicators"))
    if not rep.findings:
        print("  " + _green("None detected by the active rules."))
    sev_color = {"high": _red, "medium": _yellow, "low": _blue, "info": _c}
    for f in sorted(rep.findings, key=lambda x: -x.weight):
        badge = sev_color.get(f.severity, str)(f.severity.upper())
        cnt = f" (x{f.count})" if f.count > 1 else ""
        print(f"  [{badge}] {f.rule_id:<24} +{f.weight:>2}  {f.title}{cnt}")
        if f.evidence:
            print(f"        evidence: {truncate(f.evidence, 150)}")
    print(_c(_hr()))

    print(_bold("Zphisher / phishing-kit attribution"))
    zv = rep.zphisher_verdict()
    print("  " + (_yellow(zv) if zfinds else zv))
    for f in zfinds:
        print(f"   - {f.rule_id}: {f.title}")
    print(_c("  Attribution is pattern-based; Zphisher-family kits share "
             "patterns with many forks, so toolkit identity cannot be "
             "confirmed without server-side artifacts."))
    print(_c(_hr()))

    filled = round(score / 5)
    bar = "█" * filled + "░" * (20 - filled)
    col = _red if score >= 70 else (_yellow if score >= 40
                                    else (_green if score < 20 else _yellow))
    print(f"Risk score  : {col(f'{score:>3}/100')}  [{col(bar)}]")
    print(f"Verdict     : {col(_bold(verdict))}")
    print(f"              {verdict_note}")
    conf_note = {
        "High": "Multiple independent, mutually-reinforcing indicators.",
        "Medium": "Some corroborating indicators; manual review worthwhile.",
        "Low": "Few or weak indicators; a low-confidence result may be "
               "wrong in either direction.",
    }[conf]
    print(f"Confidence  : {conf}")
    print(f"              {conf_note}")
    print(_c(_hr()))

    print(_bold("Supporting evidence (strongest indicators first)"))
    ranked = [f for f in sorted(rep.findings, key=lambda x: -x.weight)
              if f.weight > 0]
    if not ranked:
        print("  " + _c("(no weighted indicators — nothing to cite)"))
    for f in ranked[:5]:
        print(f"  {_cyan('›')} {f.rule_id}: "
              f"{truncate(f.evidence or f.title, 160)}")
    print()

    print(_bold("Recommended defensive actions"))
    for act in rep.recommended_actions():
        print(f"  {_yellow('»')} {act}")
    print()

    print(_bold("Limitations"))
    for lim in rep.limitations:
        print(f"  {_c('-')} {lim}")
    print(_c(_hr()))
    print(_c("Heuristic triage output — the risk score is NOT a verified "
             "probability of compromise."))
    print(_bold(_hr("═")))


# ============================================================================
# Interactive terminal interface
# ============================================================================


MENU = (
    _cyan("  [") + _green("1") + _cyan("] ") +
    _bold("Analyze URL") + "\n" +


    _red("  [0] ") + _bold("Return to Main Menu") + "\n"
)


def _print_banner() -> None:
    print()
    print(_red(r"""
  ____  _     _ ____  _   _ ___ ____  _   _ _   _
 |  _ \| |   | / ___|| | | |_ _/ ___|| | | | \ | |
 | |_) | |   | \___ \| |_| || |\___ \| |_| |  \| |
 |  __/| |___| |___) |  _  || | ___) |  _  | |\  |
 |_|   |_____|_|____/|_| |_|___|____/|_| |_|_| \_|
"""))

    print(_bold(_cyan(
        "       PHISHING LINK & ZPHISHER DETECTOR"
    )))
    print(_green("       Version " + MODULE_VERSION))
    print()
    print(_cyan("  " + "=" * 48))
    print(_yellow("       STATIC SECURITY ANALYSIS"))
    print(_cyan("  " + "=" * 48))
    print()
    print(_green("  [+] ") + "URL Pattern Analysis")
    print(_green("  [+] ") + "Local HTML Analysis")
    print(_green("  [+] ") + "Phishing Indicator Detection")
    print(_green("  [+] ") + "Offline Mode Available")
    print()
    print(_cyan("  " + "-" * 48))
    print(_bold("             MAIN MENU"))
    print(_cyan("  " + "-" * 48))
    print(MENU)
    print(_cyan("  " + "-" * 48))




def _print_banner() -> None:
    print()
    print(_red(r"""
██╗   ██╗██████╗ ██╗         ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗
██║   ██║██╔══██╗██║         ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
██║   ██║██████╔╝██║         ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
██║   ██║██╔══██╗██║         ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
╚██████╔╝██║  ██║███████╗    ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═
"""))
    print(_bold(_cyan(
        "              PHISHING LINK DETECTOR"
    )))
   
    print()
    print(_cyan("=" * 54))
    
    print(_cyan("=" * 54))
    print()
    print(_bold(_yellow("              MAIN MENU")))
    print(_cyan("-" * 54))
    print(MENU)
    print(_cyan("-" * 54))


def _ask(prompt: str) -> Optional[str]:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def _pause() -> None:
    _ask(f"\n{_c('Press Enter to continue...')}")


def _guarded(action) -> None:
    try:
        action()
    except ValueError as exc:
        print(_red(f"[!] Invalid input: {exc}"))
    except FileNotFoundError as exc:
        print(_red(f"[!] File not found: {exc.filename or exc}"))
    except PermissionError as exc:
        print(_red(f"[!] Permission denied: {exc.filename or exc}"))
    except IsADirectoryError as exc:
        print(_red(f"[!] Expected a file, got a directory: "
                   f"{exc.filename or exc}"))
    except KeyboardInterrupt:
        print(_c("\n[i] Cancelled."))
    except Exception as exc:  # keep the menu alive no matter what
        print(_red(f"[!] Unexpected error ({type(exc).__name__}): {exc}"))
    _pause()


def _scan_html_target(target: Path) -> None:
    if target.is_dir():
        files = sorted(
            (f for f in target.iterdir()
             if f.is_file() and f.suffix.lower() in {".html", ".htm"}),
            key=lambda f: f.name)[:MAX_DIR_FILES]
        if not files:
            print(_yellow("[i] No .html/.htm files found in that directory."))
            return
        print(f"\nScanning {len(files)} file(s)...\n")
        scored: list[tuple[Path, Report]] = []
        for f in files:
            try:
                rep = analyze_html_file(f)
            except (OSError, PermissionError) as exc:
                print(f"  ---       {f.name:<42} skipped "
                      f"({type(exc).__name__})")
                continue
            scored.append((f, rep))
            v, _ = rep.verdict()
            score_s = f"{rep.score():>3}/100"
            col = _red if rep.score() >= 40 else (
                _yellow if rep.score() >= 20 else _green)
            z = len(rep.zphisher_findings())
            print(f"  {col(score_s)}  {f.name:<42} {v:<22} "
                  f"Zphisher indicators: {z}")
        if not scored:
            return
        print()
        worst_path, worst_rep = max(scored, key=lambda t: t[1].score())
        print(_c(f"Full report for the highest-scoring file: "
                 f"{worst_path.name}"))
        print_report(worst_rep)
        if len(scored) > 1:
            print(_c("\nRe-run option [2] on individual files for their "
                     "full reports."))
    elif target.is_file():
        print_report(analyze_html_file(target))
    else:
        raise FileNotFoundError(str(target))


def _flow_url() -> None:
    print(_c("\n"))
    raw = _ask(" Enter Target: ")
    if not raw:
        return
    _guarded(lambda: print_report(analyze_url(raw)))


def _flow_html() -> None:
    print(_c("\n"))
    raw = _ask(" Path to an .html/.htm file or a directory (blank to "
               "cancel): ")
    if not raw:
        return
    raw = raw.strip().strip('"').strip("'")
    _guarded(_scan_html_target, Path(raw))


def _flow_logs() -> None:
    print(_c("\n)"))
    print(_c("Only analyze logs you are authorized to inspect. No "
             "third-party servers are contacted."))
    raw = _ask(" Path to the log file (blank to cancel): ")
    if not raw:
        return
    raw = raw.strip().strip('"').strip("'")
    _guarded(lambda: print_report(analyze_log_file(Path(raw))))


def _flow_intel() -> None:
    key = os.environ.get(GSB_ENV_VAR, "").strip()
    if key:
        print(_green(f"\n[i] API key found in {GSB_ENV_VAR} "
                     f"(value hidden)."))
    else:
        print(_yellow(f"\n[i] No API key configured ({GSB_ENV_VAR}). "
                      f"Offline analysis will still run."))
    raw = _ask(" URL to check (blank to cancel): ")
    if not raw:
        return
    _guarded(lambda: print_report(check_threat_intel(raw)))



def run() -> None:
    _enable_windows_ansi()

    while True:
        _print_banner()

        choice = _ask("Select an option: ")

        if choice is None or choice in (
            "0", "q", "quit", "exit", "b", "back"
        ):
            print(_c("Returning to the main menu..."))
            return

        if choice == "1":
            _flow_url()
        elif choice == "2":
            _flow_html()
        elif choice == "3":
            _flow_logs()
        elif choice == "4":
            _flow_intel()
        elif choice == "5":
            print_rules_catalogue()
            _pause()
        elif choice in ("t", "selftest"):
            run_selftests()
            _pause()
        else:
            print(_red("Invalid selection — enter a number from the menu."))
            _pause()

        
        choice = _ask(" Select an option: ")
        if choice is None or choice in ("0", "q", "quit", "exit", "b", "back"):
            print(_c("Returning to the main menu..."))
            return
        if choice == "1":
            _flow_url()
        elif choice == "2":
            _flow_html()
        elif choice == "3":
            _flow_logs()
        elif choice == "4":
            _flow_intel()
        elif choice == "5":
            print_rules_catalogue()
            _pause()
        elif choice in ("t", "selftest"):
            run_selftests()
            _pause()
        else:
            print(_red("Invalid selection — enter a number from the menu."))
            _pause()


# ============================================================================
# Embedded unit tests + fixtures   (python detector.py --selftest)
# ============================================================================

FIXTURE_BENIGN_URL = "https://github.com/torvalds/linux"

FIXTURE_SUSPICIOUS_URL = ("http://198.51.100.7:8080/paypal-verify/login"
                          "?redirect=https%3A%2F%2Fwww.paypal.com")

FIXTURE_BENIGN_LOGIN = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Acme Employee Portal - Sign in</title>
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
<main>
<h1>Acme Employee Portal</h1>
<p>Sign in with your company account to continue.</p>
<form id="login" action="/api/auth/login" method="post">
<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password">
<button type="submit">Sign in</button>
</form>
</main>
<script src="/static/app.js"></script>
<script>
document.getElementById('login').addEventListener('submit', function () {
  this.querySelector('#submit-note').textContent = 'Signing in...';
});
</script>
</body>
</html>
"""

FIXTURE_PHISH = """<!DOCTYPE html>
<html>
<head>
<title>Facebook - Log In or Sign Up</title>
<meta http-equiv="refresh" content="0; url=https://www.facebook.com/login/">
</head>
<body bgcolor="#3b5998">
<div class="login_form_container">
<img src="https://www.facebook.com/rsrc.php/v3/yA/r/fb_icon.png" alt="logo">
<form action="post.php" method="POST">
<input type="text" name="email" placeholder="Email or phone">
<input type="password" name="pass" placeholder="Password">
<input type="submit" value="Log In">
</form>
</div>
<script>
var target = atob('aHR0cHM6Ly93d3cuZmFjZWJvb2suY29tL2xvZ2lu');
setTimeout(function(){ window.location.href = target; }, 1500);
</script>
</body>
</html>
"""

FIXTURE_LOG = """203.0.113.9 - - [10/May/2024:14:03:11 +0000] "POST /login.php HTTP/1.1" 302 512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.9 - - [10/May/2024:14:03:14 +0000] "GET /facebook/login.html HTTP/1.1" 200 4213 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
198.51.100.2 - - [10/May/2024:14:05:00 +0000] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
198.51.100.2 - - [10/May/2024:14:05:02 +0000] "GET /static/style.css HTTP/1.1" 200 772 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
"""


class DetectorSelfTests(unittest.TestCase):
    """Run with:  python detector.py --selftest"""

    def test_harmless_url_scores_low(self):
        rep = analyze_url(FIXTURE_BENIGN_URL)
        self.assertLess(rep.score(), 20)
        self.assertFalse([f for f in rep.findings if f.severity == "high"])
        self.assertEqual(len(rep.zphisher_findings()), 0)

    def test_suspicious_url_triggers_multiple_layers(self):
        rep = analyze_url(FIXTURE_SUSPICIOUS_URL)
        rule_ids = {f.rule_id for f in rep.findings}
        self.assertIn("URL_IP_HOST", rule_ids)
        self.assertIn("URL_BRAND_PATH", rule_ids)
        self.assertIn("URL_OPENREDIRECT_PARAM", rule_ids)
        self.assertIn("URL_ENCODED_NESTED", rule_ids)
        self.assertGreaterEqual(rep.score(), 40)
        self.assertIn(rep.confidence(), ("Medium", "High"))

    def test_dangerous_scheme_flags_high(self):
        rep = analyze_url("javascript:alert(document.domain)")
        self.assertEqual(rep.findings[0].rule_id, "URL_DANGEROUS_SCHEME")
        self.assertEqual(rep.score(), 40)

    def test_benign_login_html_is_clean(self):
        rep = analyze_html_content(FIXTURE_BENIGN_LOGIN,
                                   "fixture:benign-login.html")
        self.assertLess(rep.score(), 20)
        self.assertFalse([f for f in rep.findings
                          if f.severity in ("medium", "high")])
        self.assertEqual(len(rep.zphisher_findings()), 0)
        self.assertTrue(any(f.rule_id == "HTML_CRED_FORM"
                            for f in rep.findings))

    def test_phish_html_flags_zphisher_indicators(self):
        rep = analyze_html_content(FIXTURE_PHISH, "fixture:phish-kit.html")
        rule_ids = {f.rule_id for f in rep.findings}
        self.assertIn("HTML_ACTION_KIT_HANDLER", rule_ids)
        self.assertIn("HTML_B64_PAYLOAD", rule_ids)
        self.assertGreaterEqual(len(rep.zphisher_findings()), 2)
        self.assertGreaterEqual(rep.score(), 60)
        self.assertIn("POSSIBLE", rep.zphisher_verdict())

    def test_html_file_interface_uses_pathlib(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "kit.html"
            p.write_text(FIXTURE_PHISH, encoding="utf-8")
            rep = analyze_html_file(p)
            self.assertGreaterEqual(rep.score(), 60)

    def test_server_log_analysis(self):
        rep = analyze_log_content(FIXTURE_LOG, "fixture:access.log")
        self.assertGreaterEqual(len(rep.zphisher_findings()), 1)
        joined = " ".join(f.evidence for f in rep.findings)
        self.assertNotIn("/index.html", joined)  # benign lines not flagged

    def test_invalid_inputs_raise_valueerror(self):
        with self.assertRaises(ValueError):
            analyze_url("")
        with self.assertRaises(ValueError):
            analyze_url("not a url at all")


def run_selftests() -> int:
    print(_bold(f"\nRunning embedded unit tests "
                f"({DetectorSelfTests.__name__})...\n"))
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        DetectorSelfTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print()
    if result.wasSuccessful():
        print(_green("All tests passed."))
        return 0
    print(_red("Some tests FAILED."))
    return 1


# ============================================================================
# CLI entry point
# ============================================================================

def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="detector.py",
        description="Phishing Link & Zphisher Detector — static, "
                    "evidence-based analysis. Nothing is executed or "
                    "fetched.")
    ap.add_argument("--url", metavar="URL", help="analyze a URL (Mode 1) and exit")
    ap.add_argument("--file", metavar="PATH", help="analyze an HTML file (Mode 2) and exit")
    ap.add_argument("--logs", metavar="PATH", help="analyze a server log file (Mode 3) and exit")
    ap.add_argument("--rules", action="store_true", help="print the detection rule catalogue and exit")
    ap.add_argument("--selftest", action="store_true", help="run the embedded unit tests and exit")
    ap.add_argument("--no-color", action="store_true", help="disable colored output")
    ap.add_argument("--yes", action="store_true", help="skip the threat-intel consent prompt (Mode 4)")
    args = ap.parse_args(argv)

    if args.no_color:
        set_color(False)
    _enable_windows_ansi()

    try:
        if args.selftest:
            return run_selftests()
        if args.rules:
            print_rules_catalogue()
            return 0
        if args.url:
            print_report(analyze_url(args.url))
            return 0
        if args.file:
            print_report(analyze_html_file(Path(args.file)))
            return 0
        if args.logs:
            print_report(analyze_log_file(Path(args.logs)))
            return 0
    except ValueError as exc:
        print(_red(f"[!] Invalid input: {exc}"))
        return 2
    except FileNotFoundError as exc:
        print(_red(f"[!] File not found: {exc.filename or exc}"))
        return 2
    except PermissionError as exc:
        print(_red(f"[!] Permission denied: {exc.filename or exc}"))
        return 2
    except IsADirectoryError as exc:
        print(_red(f"[!] Expected a file, got a directory: "
                   f"{exc.filename or exc}"))
        return 2

    run()          # interactive menu; [0] returns to the caller
    return 0


if __name__ == "__main__":
    sys.exit(main())
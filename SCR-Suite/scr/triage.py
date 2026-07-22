"""False-positive triage pass.

Scores every deduplicated finding and assigns:
  confidence      — high / medium / low  (how likely this is a REAL issue)
  fp_likelihood   — low / medium / high  (high = probably a false positive)
plus human-readable triage notes and per-category manual verification steps,
so the consultant can confirm quickly. NOTHING is auto-deleted — likely FPs
are down-ranked and flagged, never hidden from the JSON export.
"""
from __future__ import annotations

import re
from .model import Finding

TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|mocks?|fixtures?|examples?|samples?|demo|docs?)(/|$)",
    re.IGNORECASE)
VENDOR_PATH_RE = re.compile(
    r"(^|/)(node_modules|bower_components|vendor|third[_-]?party|packages|"
    r"jquery[\w.-]*|bootstrap[\w.-]*|dist|build|out|bin|obj|\.venv|venv|site-packages)(/|$)",
    re.IGNORECASE)
MINIFIED_RE = re.compile(r"\.(min|bundle|pack)\.(js|css)$|\.map$", re.IGNORECASE)
GENERATED_RE = re.compile(r"(^|/)(migrations|generated|autogen|\.designer\.)", re.IGNORECASE)

PLACEHOLDER_SECRET_RE = re.compile(
    r"(example|sample|dummy|placeholder|changeme|change_me|your[_-]?(api[_-]?)?key|"
    r"xxx+|test|fake|redacted|<.*>|todo|lorem|password123|admin123|secret123|012345|abcdef)",
    re.IGNORECASE)

# rules that are notoriously noisy without data-flow context
NOISY_RULE_HINTS = (
    "detected-generic", "generic-api-key", "insecure-hash", "md5-used",
    "audit.", "raw-html", "dangerouslysetinnerhtml", "prompt-injection",
    "missing-integrity", "target-blank", "insufficiently-random",
)

VERIFICATION = {
    "Cross-Site Scripting (XSS)": "Trace the tainted variable from user input to the sink. Confirm no output-encoding/sanitisation (e.g. framework auto-escaping, DOMPurify) is applied on the path. Attempt a benign payload in a test environment if possible.",
    "SQL Injection": "Check whether the query uses string concatenation/format with user input vs parameterised statements/ORM. Confirm the input source is user-controllable (request param, header, cookie).",
    "NoSQL / Query Injection": "Confirm user input reaches the query object unvalidated (e.g. $where, operator injection). Check schema/type coercion middleware.",
    "Command Injection": "Confirm user input reaches the shell/exec call and no allow-list validation exists. Check whether shell=True / string interpolation is used.",
    "Code Injection (eval)": "Verify the eval/deserialisation input can be influenced by a user. Constant/internal-only input is a quality issue, not a vulnerability.",
    "Path Traversal": "Confirm the path component originates from user input and no canonicalisation (realpath + prefix check) is done before file access.",
    "XML External Entity (XXE)": "Check parser configuration: are external entities / DTDs explicitly disabled? Confirm XML input is user-supplied.",
    "Insecure Deserialization": "Confirm the deserialised blob crosses a trust boundary (user upload, cookie, queue). Internal-only pickle/serialisation is lower risk.",
    "Broken Access Control": "Identify the authorisation check for this route/resource. Test with a lower-privileged or different user's session.",
    "IDOR (Insecure Direct Object Reference)": "Confirm the object id is user-supplied and the handler does not verify ownership/tenancy before access.",
    "Broken Authentication": "Review the auth flow: is the check enforced server-side on every request? Look for debug bypasses or default credentials.",
    "Cross-Site Request Forgery (CSRF)": "Confirm the state-changing endpoint lacks CSRF token validation and is cookie-authenticated (not pure bearer-token APIs).",
    "Cookie Security": "Confirm the cookie carries a session/auth value. Missing Secure/HttpOnly on non-sensitive cookies is informational.",
    "Missing Security Headers / Protection": "Verify at the HTTP response level (browser dev tools/proxy) — headers may be added by a reverse proxy/WAF in front of the app.",
    "Security Misconfiguration": "Confirm the setting applies to production configuration, not just dev/test profiles.",
    "Security Misconfiguration (CORS)": "Check if the permissive origin is reachable in production and whether credentials are allowed with wildcard origins.",
    "Hardcoded Credentials / Secrets": "Confirm the value is a real, live credential (not a placeholder/test key). Check if it grants access to production systems; rotate if real.",
    "Weak Cryptography": "Determine what the algorithm protects. MD5/SHA1 for cache keys or non-security checksums is not a vulnerability; for passwords/signatures it is.",
    "Weak Hashing": "Determine what the hash protects — password storage or signatures = real finding; cache keys/etags = false positive.",
    "Insecure Randomness": "Confirm the random value is security-relevant (token, password, session id). UI jitter/sampling use is a false positive.",
    "Improper Certificate Validation": "Confirm verify=False / trust-all reaches production code paths, not just local dev helpers.",
    "Server-Side Request Forgery (SSRF)": "Confirm the URL/host component is user-controllable and no allow-list is enforced. Check reachability of internal metadata endpoints.",
    "Open Redirect": "Confirm the redirect target comes from user input without an allow-list/relative-only check.",
    "Unrestricted File Upload": "Check extension/content-type/magic-byte validation and whether uploads land in a web-served or executable location.",
    "Vulnerable Dependency": "Confirm the vulnerable version is actually deployed (lockfile) and whether the vulnerable function/feature is used by the app (reachability).",
    "Information Exposure": "Confirm the data exposed is sensitive and reachable by an unauthorised party in production.",
    "Regex Denial of Service (ReDoS)": "Confirm the regex processes user-controlled input of meaningful length.",
    "Session Management": "Verify session lifetime/invalidations server-side; confirm tokens are invalidated on logout.",
}

_CONF_SCORE = {"high": 2, "medium": 1, "": 1, "low": 0}


def _own_lines(snippet: str) -> str:
    """Return only the finding's own line(s) from a snippet — read_snippet marks
    them with a leading '>>'. Falls back to the whole snippet if unmarked."""
    if not snippet:
        return ""
    marked = [ln for ln in snippet.splitlines() if ln.lstrip().startswith(">>")]
    return " ".join(marked) if marked else snippet


def triage(findings: list[Finding], read_snippet) -> list[Finding]:
    for f in findings:
        # populate the code snippet up front so scoring can inspect the real
        # source line (not just tool-supplied prose)
        if read_snippet and not f.snippet:
            f.snippet = read_snippet(f)
        score = 0
        notes = f.triage_notes  # dedupe may have pre-seeded corroboration note

        # 1. multi-tool corroboration is the strongest signal we have
        if len(f.tools) > 1:
            score += 2

        # 2. the tool's own confidence metadata
        score += _CONF_SCORE.get((f.tool_confidence or "").lower(), 1) - 1
        if (f.tool_confidence or "").lower() == "low":
            notes.append("Reporting tool itself rated confidence LOW")

        # 3. path heuristics
        path = f.file.lower()
        if VENDOR_PATH_RE.search(path):
            score -= 3
            notes.append("Located in vendored/third-party/build output — usually out of scope for SCR")
        elif TEST_PATH_RE.search(path):
            score -= 2
            notes.append("Located in test/example/doc code — typically not production-reachable")
        if MINIFIED_RE.search(path):
            score -= 2
            notes.append("Minified/bundled artifact — review the source file instead")
        if GENERATED_RE.search(path):
            score -= 1
            notes.append("Generated code — verify against the generator/template")

        # 4. secret-specific: placeholder detection — only inspect the finding's
        #    OWN line(s), not the surrounding context, so a neighbouring line
        #    (e.g. an example email) can't wrongly mark a real secret as an FP.
        if "Secret" in f.category or f.cwe in (798, 259, 321):
            # inspect the real code line only — never the static description prose
            # (which may itself contain words like "placeholder"/"example")
            hay = _own_lines(f.snippet)
            if hay and PLACEHOLDER_SECRET_RE.search(hay):
                score -= 2
                notes.append("Matched value looks like a placeholder/example credential")

        # 5. known-noisy rule families
        rid = f.rule_id.lower()
        if any(h in rid for h in NOISY_RULE_HINTS):
            score -= 1
            notes.append("Rule family is known to be noisy without data-flow context")

        # 6. taint-mode / dataflow rules are much more reliable
        if "taint" in rid or "flow" in rid:
            score += 1

        # 7. dependency findings with a concrete CVE are factual (version match)
        if f.category == "Vulnerable Dependency":
            score += 1
            notes.append("Version-match finding — confirm exploitability/reachability, not existence")

        if score >= 2:
            f.confidence, f.fp_likelihood = "high", "low"
        elif score >= 0:
            f.confidence, f.fp_likelihood = "medium", "medium"
        else:
            f.confidence, f.fp_likelihood = "low", "high"

        f.verification = VERIFICATION.get(
            f.category,
            "Manually trace the flagged code path and confirm user-controllable input reaches the sink in production configuration.")
    return findings

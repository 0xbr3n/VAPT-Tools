"""Common finding model + severity/category normalisation."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]

# CWE -> friendly vulnerability category (Fortify-style buckets)
CWE_CATEGORY = {
    79: "Cross-Site Scripting (XSS)",
    80: "Cross-Site Scripting (XSS)",
    83: "Cross-Site Scripting (XSS)",
    116: "Improper Output Encoding",
    89: "SQL Injection",
    564: "SQL Injection",
    943: "NoSQL / Query Injection",
    77: "Command Injection",
    78: "Command Injection",
    88: "Command Injection",
    94: "Code Injection",
    95: "Code Injection (eval)",
    1336: "Server-Side Template Injection (SSTI)",
    22: "Path Traversal",
    23: "Path Traversal",
    73: "Path Traversal",
    611: "XML External Entity (XXE)",
    776: "XML External Entity (XXE)",
    502: "Insecure Deserialization",
    284: "Broken Access Control",
    285: "Broken Access Control",
    862: "Broken Access Control (Missing AuthZ)",
    863: "Broken Access Control",
    639: "IDOR (Insecure Direct Object Reference)",
    287: "Broken Authentication",
    306: "Broken Authentication (Missing AuthN)",
    521: "Weak Password Policy",
    613: "Session Management",
    384: "Session Fixation",
    352: "Cross-Site Request Forgery (CSRF)",
    614: "Cookie Security",
    1004: "Cookie Security",
    315: "Cookie Security",
    693: "Missing Security Headers / Protection",
    1021: "Clickjacking / Missing Headers",
    16: "Security Misconfiguration",
    798: "Hardcoded Credentials / Secrets",
    259: "Hardcoded Credentials / Secrets",
    321: "Hardcoded Credentials / Secrets",
    547: "Hardcoded Credentials / Secrets",
    327: "Weak Cryptography",
    326: "Weak Cryptography",
    328: "Weak Hashing",
    330: "Insecure Randomness",
    338: "Insecure Randomness",
    295: "Improper Certificate Validation",
    319: "Cleartext Transmission",
    918: "Server-Side Request Forgery (SSRF)",
    601: "Open Redirect",
    434: "Unrestricted File Upload",
    200: "Information Exposure",
    209: "Information Exposure (Error Details)",
    532: "Information Exposure (Logs)",
    276: "Incorrect Permissions",
    732: "Incorrect Permissions",
    615: "Information Exposure (Comments)",
    1188: "Hardcoded Path / Environment",
    400: "Denial of Service",
    1333: "Regex Denial of Service (ReDoS)",
    770: "Denial of Service",
    90: "LDAP Injection",
    643: "XPath Injection",
    113: "HTTP Response Splitting",
    444: "HTTP Request Smuggling",
    937: "Vulnerable Dependency",
    1104: "Vulnerable Dependency",
    1035: "Vulnerable Dependency",
}

# keyword fallback when no CWE available (checked in order)
KEYWORD_CATEGORY = [
    ("xss", "Cross-Site Scripting (XSS)"),
    ("cross-site-scripting", "Cross-Site Scripting (XSS)"),
    ("dom", "Cross-Site Scripting (XSS)"),
    ("sql", "SQL Injection"),
    ("nosql", "NoSQL / Query Injection"),
    ("command-injection", "Command Injection"),
    ("subprocess", "Command Injection"),
    ("os-command", "Command Injection"),
    ("ssti", "Server-Side Template Injection (SSTI)"),
    ("template-injection", "Server-Side Template Injection (SSTI)"),
    ("path-traversal", "Path Traversal"),
    ("pathtraversal", "Path Traversal"),
    ("xxe", "XML External Entity (XXE)"),
    ("deserial", "Insecure Deserialization"),
    ("pickle", "Insecure Deserialization"),
    ("idor", "IDOR (Insecure Direct Object Reference)"),
    ("access-control", "Broken Access Control"),
    ("authoriz", "Broken Access Control"),
    ("authent", "Broken Authentication"),
    ("csrf", "Cross-Site Request Forgery (CSRF)"),
    ("cookie", "Cookie Security"),
    ("httponly", "Cookie Security"),
    ("secure-flag", "Cookie Security"),
    ("header", "Missing Security Headers / Protection"),
    ("hsts", "Missing Security Headers / Protection"),
    ("csp", "Missing Security Headers / Protection"),
    ("cors", "Security Misconfiguration (CORS)"),
    ("secret", "Hardcoded Credentials / Secrets"),
    ("password", "Hardcoded Credentials / Secrets"),
    ("api-key", "Hardcoded Credentials / Secrets"),
    ("token", "Hardcoded Credentials / Secrets"),
    ("credential", "Hardcoded Credentials / Secrets"),
    ("crypto", "Weak Cryptography"),
    ("md5", "Weak Hashing"),
    ("sha1", "Weak Hashing"),
    ("random", "Insecure Randomness"),
    ("tls", "Improper Certificate Validation"),
    ("ssl", "Improper Certificate Validation"),
    ("certificate", "Improper Certificate Validation"),
    ("ssrf", "Server-Side Request Forgery (SSRF)"),
    ("redirect", "Open Redirect"),
    ("upload", "Unrestricted File Upload"),
    ("redos", "Regex Denial of Service (ReDoS)"),
    ("debug", "Security Misconfiguration"),
    ("cve-", "Vulnerable Dependency"),
    ("vulnerab", "Vulnerable Dependency"),
    ("eval", "Code Injection (eval)"),
]

# OWASP Top 10 2021 mapping by category (best effort, for the report)
CATEGORY_OWASP = {
    "Cross-Site Scripting (XSS)": "A03:2021 Injection",
    "SQL Injection": "A03:2021 Injection",
    "NoSQL / Query Injection": "A03:2021 Injection",
    "Command Injection": "A03:2021 Injection",
    "Code Injection": "A03:2021 Injection",
    "Code Injection (eval)": "A03:2021 Injection",
    "Server-Side Template Injection (SSTI)": "A03:2021 Injection",
    "LDAP Injection": "A03:2021 Injection",
    "XPath Injection": "A03:2021 Injection",
    "HTTP Response Splitting": "A03:2021 Injection",
    "Improper Output Encoding": "A03:2021 Injection",
    "Path Traversal": "A01:2021 Broken Access Control",
    "Broken Access Control": "A01:2021 Broken Access Control",
    "Broken Access Control (Missing AuthZ)": "A01:2021 Broken Access Control",
    "IDOR (Insecure Direct Object Reference)": "A01:2021 Broken Access Control",
    "Open Redirect": "A01:2021 Broken Access Control",
    "Cross-Site Request Forgery (CSRF)": "A01:2021 Broken Access Control",
    "Broken Authentication": "A07:2021 Identification and Authentication Failures",
    "Broken Authentication (Missing AuthN)": "A07:2021 Identification and Authentication Failures",
    "Weak Password Policy": "A07:2021 Identification and Authentication Failures",
    "Session Management": "A07:2021 Identification and Authentication Failures",
    "Session Fixation": "A07:2021 Identification and Authentication Failures",
    "Cookie Security": "A05:2021 Security Misconfiguration",
    "Missing Security Headers / Protection": "A05:2021 Security Misconfiguration",
    "Clickjacking / Missing Headers": "A05:2021 Security Misconfiguration",
    "Security Misconfiguration": "A05:2021 Security Misconfiguration",
    "Security Misconfiguration (CORS)": "A05:2021 Security Misconfiguration",
    "Incorrect Permissions": "A05:2021 Security Misconfiguration",
    "XML External Entity (XXE)": "A05:2021 Security Misconfiguration",
    "Hardcoded Credentials / Secrets": "A07:2021 Identification and Authentication Failures",
    "Weak Cryptography": "A02:2021 Cryptographic Failures",
    "Weak Hashing": "A02:2021 Cryptographic Failures",
    "Insecure Randomness": "A02:2021 Cryptographic Failures",
    "Improper Certificate Validation": "A02:2021 Cryptographic Failures",
    "Cleartext Transmission": "A02:2021 Cryptographic Failures",
    "Insecure Deserialization": "A08:2021 Software and Data Integrity Failures",
    "Server-Side Request Forgery (SSRF)": "A10:2021 Server-Side Request Forgery",
    "Vulnerable Dependency": "A06:2021 Vulnerable and Outdated Components",
    "Information Exposure": "A01:2021 Broken Access Control",
    "Information Exposure (Error Details)": "A05:2021 Security Misconfiguration",
    "Information Exposure (Comments)": "A05:2021 Security Misconfiguration",
    "Information Exposure (Logs)": "A09:2021 Security Logging and Monitoring Failures",
    "Hardcoded Path / Environment": "A05:2021 Security Misconfiguration",
    "Cleartext Transmission": "A02:2021 Cryptographic Failures",
    "Unrestricted File Upload": "A04:2021 Insecure Design",
    "Denial of Service": "A04:2021 Insecure Design",
    "Regex Denial of Service (ReDoS)": "A04:2021 Insecure Design",
    "Sensitive Data Exposure (PII)": "A02:2021 Cryptographic Failures",
}


def categorize(cwe: Optional[int], rule_id: str = "", title: str = "") -> str:
    if cwe and cwe in CWE_CATEGORY:
        return CWE_CATEGORY[cwe]
    hay = (rule_id + " " + title).lower()
    for kw, cat in KEYWORD_CATEGORY:
        if kw in hay:
            return cat
    return "Other"


def normalize_severity(raw, cvss=None) -> str:
    """Map any tool severity string / CVSS score onto the common scale."""
    if cvss is not None:
        try:
            c = float(cvss)
            if c >= 9.0:
                return "critical"
            if c >= 7.0:
                return "high"
            if c >= 4.0:
                return "medium"
            if c > 0:
                return "low"
        except (TypeError, ValueError):
            pass
    s = str(raw or "").strip().lower()
    mapping = {
        "critical": "critical", "blocker": "critical",
        "high": "high", "error": "high", "severe": "high",
        "medium": "medium", "moderate": "medium", "warning": "medium", "major": "medium",
        "low": "low", "minor": "low", "note": "low",
        "info": "info", "informational": "info", "none": "info", "unknown": "medium",
    }
    return mapping.get(s, "medium")


@dataclass
class Finding:
    tool: str
    rule_id: str
    title: str
    description: str
    severity: str            # critical/high/medium/low/info
    file: str                # path relative to scan target
    line: int
    end_line: int = 0
    cwe: Optional[int] = None
    owasp: str = ""
    category: str = "Other"
    tool_confidence: str = ""   # what the tool itself reported (if anything)
    snippet: str = ""
    remediation: str = ""
    reference: str = ""
    # dependency findings: the concrete component + versions involved
    component: str = ""          # e.g. golang.org/x/net  or  log4j-core
    version: str = ""            # the version actually found in the code/manifest
    fixed_version: str = ""      # the version to upgrade to (if the tool knows it)
    # populated by dedupe/triage:
    tools: list = field(default_factory=list)      # all tools that agreed
    duplicates: int = 0
    confidence: str = "medium"                     # our triaged confidence
    fp_likelihood: str = "unknown"                 # low/medium/high (high = likely FP)
    triage_notes: list = field(default_factory=list)
    verification: str = ""
    # populated by the optional LLM reasoning pass (llm_triage) — advisory only,
    # never auto-deletes a finding. Empty when the LLM pass is disabled.
    llm_verdict: str = ""            # true_positive / likely_false_positive / needs_review / ""
    llm_confidence: str = ""         # high / medium / low
    llm_reasoning: str = ""          # one-line rationale
    fid: str = ""

    def finalize(self):
        if not self.category or self.category == "Other":
            self.category = categorize(self.cwe, self.rule_id, self.title)
        if not self.owasp:
            self.owasp = CATEGORY_OWASP.get(self.category, "")
        if self.severity not in SEVERITIES:
            self.severity = normalize_severity(self.severity)
        if not self.tools:
            self.tools = [self.tool]
        if not self.end_line:
            self.end_line = self.line
        h = hashlib.sha1(
            f"{self.tool}|{self.rule_id}|{self.file}|{self.line}".encode("utf-8", "replace")
        ).hexdigest()[:12]
        self.fid = h
        return self

    def to_dict(self):
        return asdict(self)

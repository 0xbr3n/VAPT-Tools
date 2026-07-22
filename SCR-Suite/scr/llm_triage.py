"""Optional LLM reasoning pass — runs AFTER the deterministic triage.

Two jobs, both advisory (nothing is ever auto-deleted — consistent with triage):

  1. review_findings()  — for each finding, reason about true-positive vs
     false-positive by INSPECTING THE CODE SNIPPET for mitigations the pattern
     scanners can't see (parameterisation, output-encoding, allow-lists, safe
     loaders, placeholder/test values). Writes llm_verdict/confidence/reasoning
     and a triage note. Complements the deterministic path/corroboration score.

  2. suggest_vectors() — reason about the whole codebase (languages, frameworks,
     what was already found) and propose ADDITIONAL attack vectors a consultant
     should manually check that automated SAST typically misses (business logic,
     authZ/IDOR, SSRF, prototype pollution, mass assignment, race conditions …).

Backends (config "llm": {"backend": ...}):
  * "poc"      (default) — NO model call. Deterministic reasoning derived locally
                from the finding + snippet + language profile. Fully offline,
                repeatable. This is what runs in an air-gapped demo.
  * "onprem"   — POST to an internal, self-hosted OpenAI-compatible endpoint
                (LLM_ENDPOINT / config llm.endpoint). Temperature 0 + fixed seed.
  * "disabled" — pass does nothing.

The on-prem call uses only the standard library (urllib) — no new dependency.
In "poc"/"disabled" mode NOTHING leaves the machine.
"""
from __future__ import annotations

import hashlib
import json
import os
import re

from .model import Finding
from .util import log

# ---- config -----------------------------------------------------------------
def _llm_cfg(cfg: dict) -> dict:
    c = dict(cfg.get("llm", {}))
    # env overrides (so production can flip backend without editing config.json)
    c["backend"] = os.environ.get("LLM_BACKEND", c.get("backend", "poc")).lower()
    c["endpoint"] = os.environ.get("LLM_ENDPOINT", c.get("endpoint", ""))
    c["model"] = os.environ.get("LLM_MODEL", c.get("model", "internal-model"))
    c.setdefault("influence_ranking", False)  # advisory-only by default
    c.setdefault("max_model_calls", 400)       # cap per scan when backend=onprem
    return c


def backend_info(cfg: dict) -> dict:
    c = _llm_cfg(cfg)
    return {"backend": c["backend"],
            "endpoint": c["endpoint"] if c["backend"] == "onprem" else "(offline)",
            "model": c["model"] if c["backend"] != "disabled" else "(disabled)",
            "data_egress": "NONE" if c["backend"] in ("poc", "disabled") else "internal-only"}


# ---- snippet mitigation signals (used by POC reasoning) ---------------------
_OWN = lambda s: " ".join(l for l in (s or "").splitlines() if l.lstrip().startswith(">>")) or (s or "")

_MITIGATION = {
    "SQL Injection": re.compile(r"(\?|:\w+|%s|@\w+|\bbind\b|prepar|parameteri|\.query\([^,]+,\s*[\[\(]|ORM|entitymanager|namedquery)", re.I),
    "Cross-Site Scripting (XSS)": re.compile(r"(escape|encode|sanitiz|dompurify|textcontent|innertext|\|\s*e\b|htmlspecialchars|autoescap|v-text)", re.I),
    "Command Injection": re.compile(r"(shlex\.quote|shell\s*=\s*False|\[[\"'][^\"']+[\"']\s*,|execve|allowlist|whitelist|escapeshellarg)", re.I),
    "Path Traversal": re.compile(r"(realpath|canonical|basename|abspath|normpath|startswith\(|Paths\.get|secure_filename)", re.I),
    "Server-Side Request Forgery (SSRF)": re.compile(r"(allowlist|whitelist|ip_address|is_private|urlparse|resolve|deny)", re.I),
    "Insecure Deserialization": re.compile(r"(safe_load|SafeLoader|SafeConstructor|json\.loads|allowlist|resolveClass)", re.I),
    "Weak Hashing": re.compile(r"(etag|cache|checksum|non[- ]?security|dedup|content[- ]?hash|integrity)", re.I),
    "Weak Cryptography": re.compile(r"(etag|cache|checksum|non[- ]?security|test)", re.I),
    "Improper Certificate Validation": re.compile(r"(dev|test|localhost|self[- ]?signed|# *nosec|assert)", re.I),
}
_PLACEHOLDER = re.compile(
    r"(example|sample|dummy|placeholder|changeme|change_me|your[_-]?(api[_-]?)?key|"
    r"xxx+|test|fake|redacted|<.*>|todo|lorem|0000000|1111111|1234567|4111111111111111|foobar)", re.I)
_TEST_CARD = re.compile(r"(4111111111111111|4242424242424242|5555555555554444|378282246310005)")


# ---- 1. per-finding review --------------------------------------------------
def review_findings(findings: list[Finding], cfg: dict) -> dict:
    c = _llm_cfg(cfg)
    if c["backend"] == "disabled":
        return {"reviewed": 0, "backend": "disabled"}

    calls = 0
    stats = {"true_positive": 0, "likely_false_positive": 0, "needs_review": 0}
    for f in findings:
        if c["backend"] == "onprem" and calls < c["max_model_calls"] and _worth_model(f):
            verdict = _review_onprem(f, c)
            calls += 1
        else:
            verdict = _review_poc(f)
        f.llm_verdict = verdict["verdict"]
        f.llm_confidence = verdict["confidence"]
        f.llm_reasoning = verdict["reasoning"]
        stats[verdict["verdict"]] = stats.get(verdict["verdict"], 0) + 1
        f.triage_notes.append(f"LLM: {verdict['verdict'].replace('_',' ')} "
                              f"({verdict['confidence']}) - {verdict['reasoning']}")
        # optional: let a confident LLM FP-call nudge ranking (off by default)
        if c["influence_ranking"] and verdict["verdict"] == "likely_false_positive" \
                and verdict["confidence"] == "high" and f.fp_likelihood != "high":
            f.fp_likelihood = "high"
            f.triage_notes.append("Down-ranked to likely-FP on high-confidence LLM agreement")
    return {"reviewed": len(findings), "model_calls": calls, "backend": c["backend"], **stats}


def _worth_model(f: Finding) -> bool:
    """Only spend an on-prem model call on findings where reasoning adds value —
    i.e. not the already-clear-cut ones."""
    if f.fp_likelihood == "medium":
        return True
    if f.category in ("Vulnerable Dependency",):  # factual version match — skip
        return False
    return f.severity in ("critical", "high")


def _review_poc(f: Finding) -> dict:
    """Deterministic reasoning: inspect the finding's own code line for
    mitigations / placeholders the pattern scanner couldn't weigh."""
    line = _OWN(f.snippet)
    cat = f.category

    # secrets / PII: placeholder or known test value => likely FP
    if "Secret" in cat or "PII" in cat or f.cwe in (798, 259, 321, 359):
        if _TEST_CARD.search(line):
            return _v("likely_false_positive", "high",
                      "Value is a well-known test/synthetic card number, not live cardholder data.")
        if _PLACEHOLDER.search(line):
            return _v("likely_false_positive", "medium",
                      "Matched value resembles a placeholder/example/test credential rather than a live secret.")
        return _v("true_positive", "high" if len(f.tools) > 1 else "medium",
                  "Literal secret/PII in source with no placeholder markers; treat as real until proven a test value and rotate.")

    # injection / crypto: does the same line already carry a mitigation?
    mit = _MITIGATION.get(cat)
    if mit and line and mit.search(line):
        return _v("likely_false_positive", "medium",
                  f"The flagged line appears to already apply a mitigation "
                  f"({cat.lower()} defence present on the sink line); confirm it covers the tainted path.")

    # dependency findings are factual version matches
    if cat == "Vulnerable Dependency":
        return _v("true_positive", "medium",
                  "Version-match against a known CVE; verify the vulnerable code path is reachable/used.")

    # otherwise defer to deterministic triage signal
    if f.fp_likelihood == "high":
        note = f.triage_notes[-1] if f.triage_notes else "down-ranked by path/context heuristics"
        return _v("likely_false_positive", "medium",
                  f"Deterministic signals lean false-positive ({note[:120]}).")
    if f.fp_likelihood == "low":
        corrob = f"corroborated by {len(f.tools)} tools" if len(f.tools) > 1 else "single-tool but high-signal rule"
        return _v("true_positive", "high" if len(f.tools) > 1 else "medium",
                  f"No mitigation visible on the sink line; {corrob}. Trace user input to confirm exploitability.")
    return _v("needs_review", "medium",
              "Signals are mixed and no mitigation is visible on the sink line; manual data-flow check required.")


def _v(verdict, confidence, reasoning):
    return {"verdict": verdict, "confidence": confidence, "reasoning": reasoning}


# ---- 2. additional-vector reasoning ----------------------------------------
def suggest_vectors(profile: dict, findings: list[Finding], cfg: dict) -> list[dict]:
    c = _llm_cfg(cfg)
    if c["backend"] == "disabled":
        return []
    if c["backend"] == "onprem":
        try:
            return _vectors_onprem(profile, findings, c)
        except Exception as exc:
            log(f"llm: on-prem vector suggestion failed ({exc}); using offline reasoning")
    return _vectors_poc(profile, findings)


# language/framework -> vectors SAST commonly under-detects
_LANG_VECTORS = {
    "java": [
        ("Insecure deserialization", "ObjectInputStream / readObject on untrusted data, and SnakeYAML/XMLDecoder gadget chains.", "Grep for readObject, ObjectInputStream, XMLDecoder, and Yaml() without SafeConstructor; check message queues/session stores."),
        ("Spring SpEL / expression injection", "User input reaching SpelExpressionParser or @Value/#{...} evaluates as code.", "Trace request params into SpelExpressionParser.parseExpression / Thymeleaf inline expressions."),
        ("Mass assignment (@RequestBody binding)", "Binding request bodies straight onto entities can set fields the user shouldn't (isAdmin, balance).", "Review @RequestBody/@ModelAttribute DTOs vs entity fields; check for @JsonIgnore / allow-lists."),
        ("Actuator / management exposure", "Exposed env, heapdump, mappings endpoints leak secrets or allow heap capture.", "Check management.endpoints.web.exposure and whether Spring Security guards /actuator."),
    ],
    "javascript": [
        ("Prototype pollution", "Recursive merge/clone/set with attacker-controlled keys pollutes Object.prototype.", "Audit lodash.merge/set, Object.assign loops, and any deep-merge of req.body/query."),
        ("SSRF via server-side fetch", "Node servers fetching a user-supplied URL (axios/got/fetch) can hit internal metadata endpoints.", "Trace req input into axios/got/http.request URLs; check for allow-lists and IP-range denial."),
        ("NoSQL operator injection", "req.body objects passed to Mongo queries allow $where/$ne/$gt operator injection.", "Confirm inputs are cast to string/schema-validated before reaching find()/update()."),
        ("ReDoS", "User input tested against catastrophic-backtracking regexes stalls the event loop.", "Review regexes with nested quantifiers ((a+)+) applied to request data."),
        ("JWT algorithm confusion", "Accepting alg from the token (none / RS256->HS256) forges tokens.", "Confirm verify() pins the expected algorithm explicitly."),
    ],
    "typescript": None,  # alias -> javascript
    "python": [
        ("Server-Side Template Injection", "render_template_string / Jinja with user input evaluates expressions.", "Grep render_template_string, Template().render, and f-strings into template engines."),
        ("Unsafe deserialization", "pickle.loads, yaml.load (no SafeLoader), and jsonpickle over untrusted data run code.", "Trace deserialised blobs from uploads/cookies/queues; confirm safe_load."),
        ("Command exec via subprocess", "shell=True or os.system with interpolated input.", "Confirm arg lists (not shell strings) and no user input in the command."),
        ("Framework debug/secret-key", "Flask/Django DEBUG=True or a hardcoded SECRET_KEY enables RCE/console and session forgery.", "Check settings for DEBUG, SECRET_KEY, ALLOWED_HOSTS in production config."),
    ],
    "php": [
        ("File inclusion (LFI/RFI)", "include/require with user input enables local/remote file inclusion.", "Grep include/require/include_once with request variables."),
        ("Type juggling / loose comparison", "== on hashes/tokens/passwords allows auth bypass (0e... collisions).", "Find == comparisons on secrets; require === / hash_equals."),
        ("unserialize() on user data", "PHP object injection via unserialize of cookies/params.", "Confirm no user-controlled unserialize; use JSON."),
    ],
    "csharp": [
        ("Insecure deserialization", "BinaryFormatter / LosFormatter / JSON TypeNameHandling.All over untrusted data.", "Grep BinaryFormatter, TypeNameHandling, JavaScriptSerializer with a resolver."),
        ("Mass assignment (model binding)", "Over-posting binds properties the user shouldn't control.", "Check [Bind]/DTOs vs entity models; look for AutoMapper over full entities."),
        ("LDAP / XPath injection", "Concatenated LDAP/XPath filters from user input.", "Trace input into DirectorySearcher / SelectNodes."),
    ],
    "go": [
        ("SSRF", "http.Get/Client with a user-supplied URL reaches internal services.", "Trace request input into http client URLs; check allow-lists."),
        ("Path traversal in file servers", "filepath.Join with user input escaping the root.", "Confirm filepath.Clean + prefix check before ServeFile/os.Open."),
        ("SQL injection", "fmt.Sprintf into db.Query instead of placeholders.", "Confirm parameterised queries ($1/?) everywhere."),
    ],
}

_IAC_VECTORS = [
    ("Publicly exposed resources", "0.0.0.0/0 ingress, public S3/blob, open management ports (22/3389).", "Review security-group/NSG rules and bucket ACLs/policies in the IaC."),
    ("Hardcoded provider credentials", "AWS/Azure/GCP keys in .tf/.tfvars or pipeline variables.", "Grep provider blocks and *.tfvars for access keys/secrets."),
    ("Privileged / root containers", "privileged:true, runAsRoot, hostPath mounts, no resource limits.", "Review Dockerfiles/K8s manifests for least-privilege."),
]


def _vectors_poc(profile: dict, findings: list[Finding]) -> list[dict]:
    langs = set(profile.get("languages", []))
    if "typescript" in langs:
        langs.add("javascript")
    seen_cats = {f.category for f in findings}
    out: list[dict] = []

    # cross-cutting checks SAST structurally cannot prove — always relevant
    out += [
        {"area": "Broken access control / IDOR", "risk": "high",
         "why": "SAST rarely proves a MISSING authorisation check; these are the most common real findings and are invisible to pattern rules.",
         "how": "Enumerate every state-changing / object-fetching route and confirm server-side ownership + role checks. Test with a lower-privileged and a second-tenant session."},
        {"area": "Business-logic flaws", "risk": "high",
         "why": "Price/quantity tampering, negative amounts, workflow step-skipping, replay — no scanner understands intent.",
         "how": "Model the critical workflows (payment, transfer, approval) and test boundary/negative/out-of-order inputs."},
        {"area": "Authentication flow & session", "risk": "high",
         "why": "Bypasses, weak reset tokens, missing server-side session invalidation, MFA gaps.",
         "how": "Review the full auth path server-side: password reset entropy, logout invalidation, remember-me, account lockout."},
        {"area": "Race conditions / TOCTOU", "risk": "medium",
         "why": "Double-spend, coupon reuse, check-then-act gaps are timing-dependent and invisible to static analysis.",
         "how": "Look for read-modify-write on shared state (balances, stock, quotas) without locks/transactions."},
    ]

    for lang in sorted(langs):
        vs = _LANG_VECTORS.get(lang)
        if not vs:
            continue
        for area, why, how in vs:
            out.append({"area": f"[{lang}] {area}", "risk": "medium", "why": why, "how": how})

    if profile.get("iac") or profile.get("dotnet") is None:
        pass
    if profile.get("iac"):
        for area, why, how in _IAC_VECTORS:
            out.append({"area": f"[IaC] {area}", "risk": "medium", "why": why, "how": how})

    # context-driven follow-ups based on what was already found
    if any("Secret" in c or "PII" in c for c in seen_cats):
        out.append({"area": "Secret history & rotation", "risk": "high",
                    "why": "This scan is a point-in-time snapshot; a secret removed from HEAD may still live in git history.",
                    "how": "Run gitleaks over full history (--log-opts=\"--all\"); rotate every confirmed live secret."})
    if "Vulnerable Dependency" in seen_cats:
        out.append({"area": "Dependency reachability & transitives", "risk": "medium",
                    "why": "A CVE in a dependency only matters if the vulnerable function is actually called; transitive deps are often missed.",
                    "how": "Confirm the vulnerable API is invoked; review the full transitive tree (SBOM) not just direct manifests."})
    if not any("Cross-Site Request Forgery" in c for c in seen_cats):
        out.append({"area": "CSRF on state-changing endpoints", "risk": "medium",
                    "why": "No CSRF finding surfaced — verify it's genuinely handled, not just unscanned.",
                    "how": "Confirm anti-CSRF tokens (or SameSite + custom-header checks) on all cookie-authenticated POST/PUT/DELETE."})
    return out


def write_vectors_file(vectors: list[dict], path, meta: dict) -> None:
    lines = [
        "# LLM-suggested additional attack vectors",
        "",
        f"Target: `{meta.get('target','')}`  ·  generated by the SCR Automater LLM reasoning pass",
        f"Backend: **{meta.get('llm_backend','poc')}** (advisory — these are checks to run MANUALLY; ",
        "the automated tools above do not reliably cover them).",
        "",
    ]
    for i, v in enumerate(vectors, 1):
        lines.append(f"### {i}. {v['area']}  _(priority: {v.get('risk','medium')})_")
        lines.append(f"- **Why it's often missed:** {v['why']}")
        lines.append(f"- **How to check:** {v['how']}")
        lines.append("")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
    except OSError as e:
        log(f"llm: could not write vectors file: {e}")


# ---- on-prem backend (production; not used in the offline demo) -------------
def _seed(text: str) -> int:
    return int(hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(), 16) % (2**31)


def _review_onprem(f: Finding, c: dict) -> dict:  # pragma: no cover - needs endpoint
    prompt = (
        "You are a senior application-security consultant validating a static-analysis "
        "finding. Decide if it is a real issue. Inspect the code snippet for mitigations "
        "(parameterisation, output-encoding, allow-lists, safe loaders, placeholder/test "
        "values). Be conservative; if unsure use needs_review.\n"
        'Respond with STRICT JSON: {"verdict": one of ["true_positive","likely_false_positive","needs_review"], '
        '"confidence": one of ["high","medium","low"], "reasoning": "one sentence"}\n\n'
        f"Category: {f.category}\nRule: {f.rule_id}\nSeverity: {f.severity}\n"
        f"File: {f.file}:{f.line}\nTools agreeing: {', '.join(f.tools)}\n"
        f"Deterministic FP-likelihood: {f.fp_likelihood}\n\nCode:\n{f.snippet[:1500]}\n"
    )
    raw = _chat(prompt, _seed(f.fid or f.file), c)
    try:
        obj = json.loads(_extract_json(raw))
        v = obj.get("verdict")
        if v not in ("true_positive", "likely_false_positive", "needs_review"):
            v = "needs_review"
        return _v(v, obj.get("confidence", "medium"), str(obj.get("reasoning", ""))[:300])
    except Exception:
        return _v("needs_review", "low", "On-prem model returned unparseable output; manual review.")


def _vectors_onprem(profile: dict, findings: list[Finding], c: dict) -> list[dict]:  # pragma: no cover
    seen = sorted({f.category for f in findings})
    prompt = (
        "You are a senior application-security consultant. Given the codebase profile and the "
        "vulnerability categories already found by automated SAST, list additional attack vectors a "
        "human should MANUALLY check that SAST typically misses (authz/IDOR, business logic, SSRF, "
        "prototype pollution, mass assignment, race conditions, deserialization gadgets, etc.).\n"
        'Respond with STRICT JSON: {"vectors":[{"area":"...","risk":"high|medium|low","why":"...","how":"..."}]}\n\n'
        f"Languages: {', '.join(profile.get('languages', []))}\n"
        f"IaC present: {profile.get('iac')}\nManifests: {', '.join(profile.get('manifests', [])[:15])}\n"
        f"Categories already found: {', '.join(seen)}\n"
    )
    raw = _chat(prompt, _seed("vectors:" + ",".join(profile.get("languages", []))), c)
    obj = json.loads(_extract_json(raw))
    vs = obj.get("vectors", [])
    # merge with the deterministic baseline so on-prem never returns LESS coverage
    base = _vectors_poc(profile, findings)
    seen_areas = {v["area"].lower() for v in vs}
    for b in base:
        if b["area"].lower() not in seen_areas:
            vs.append(b)
    return vs


def _extract_json(raw: str) -> str:
    raw = raw.strip()
    a, b = raw.find("{"), raw.rfind("}")
    return raw[a:b + 1] if a >= 0 and b > a else raw


def _chat(prompt: str, seed: int, c: dict) -> str:  # pragma: no cover - needs endpoint
    import urllib.request
    body = json.dumps({
        "model": c["model"],
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0, "top_p": 1, "seed": seed, "stream": False,
        "response_format": {"type": "json_object"},   # force valid JSON (Ollama/vLLM)
    }).encode("utf-8")
    req = urllib.request.Request(
        c["endpoint"].rstrip("/") + "/v1/chat/completions",
        data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]

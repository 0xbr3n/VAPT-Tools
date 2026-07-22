# LLM Reasoning Layer + Coverage Additions

This documents what was added on top of the existing (already strong) SCR
Automater pipeline. **Everything here is additive and non-breaking** — the
deterministic scan, dedupe, triage, report, and DRG export behave exactly as
before; the LLM layer is a new, optional, offline-by-default pass that never
deletes a finding (same philosophy as `triage.py`).

---

## 1. Gap analysis (what was missing)

The orchestrator, adapters, dedupe, CWE→OWASP mapping and deterministic triage
were already solid. Three gaps:

1. **No LLM reasoning** — triage was 100% deterministic. No layer to (a) reason
   about false positives by reading the code, or (b) suggest attack vectors the
   tools miss.
2. **PII detection missing** — the manual rules covered emails but not the
   identifiers that matter most in SG engagements: **NRIC/FIN**, **credit-card
   PANs**, and **committed private keys**.
3. **A few real vector gaps** — weak ciphers (DES/RC4/Blowfish/ECB), unsafe YAML
   load, prototype pollution, XPath injection, hardcoded JWT signing secret,
   Spring Actuator exposure, insecure Electron `webPreferences`, wildcard
   `postMessage`.

---

## 2. New manual rules (12) — `manual_rules.json`

Flow through the existing dedupe + triage + report with **zero code change**:

| Rule id | Category | Sev |
|---|---|---|
| `manual-pii-nric` | Sensitive Data Exposure (PII) | medium |
| `manual-pii-creditcard` | Sensitive Data Exposure (PII) | high |
| `manual-private-key-block` | Hardcoded Credentials / Secrets | critical |
| `manual-weak-cipher` | Weak Cryptography | high |
| `manual-ecb-mode` | Weak Cryptography | high |
| `manual-yaml-unsafe-load` | Insecure Deserialization | high |
| `manual-prototype-pollution` | Security Misconfiguration (CWE-1321) | medium |
| `manual-xpath-injection` | XPath Injection | medium |
| `manual-jwt-hardcoded-secret` | Hardcoded Credentials / Secrets | high |
| `manual-spring-actuator-exposure` | Security Misconfiguration | medium |
| `manual-electron-nodeintegration` | Security Misconfiguration | medium |
| `manual-postmessage-wildcard` | Security Misconfiguration | low |

`Sensitive Data Exposure (PII)` was registered in `model.CATEGORY_OWASP`
(→ A02:2021). Broad/low-signal rules are given low confidence so the triage pass
flags them for a quick manual confirm rather than drowning the report.

---

## 3. LLM reasoning pass — `scr/llm_triage.py`

Runs automatically **after** the deterministic triage. Two jobs:

### (a) Per-finding false-positive review — `review_findings()`
For every finding it produces an advisory verdict —
`true_positive` / `likely_false_positive` / `needs_review` — with confidence and
a one-line rationale, written to `llm_verdict` / `llm_confidence` /
`llm_reasoning` (in `findings.json`/CSV) **and appended as a triage note so it
already renders in the existing HTML report**. It adds signal the pattern
scanners can't: it inspects the finding's **own code line** for mitigations
(parameterisation, output-encoding, allow-lists, safe loaders) and for
placeholder/test values (e.g. it correctly downgrades the `4111 1111 1111 1111`
test card to a high-confidence false positive).

Advisory only by default — it does **not** change ranking. Set
`llm.influence_ranking: true` to let a *high-confidence* LLM false-positive
verdict down-rank a finding to likely-FP (which then also drops it from the
default DRG export).

### (b) Additional-vector suggestions — `suggest_vectors()`
Reasons about the whole codebase (detected languages/frameworks + what was
already found) and writes **`llm_vectors.md`** — a prioritised list of attack
vectors to check **manually** that SAST structurally misses: broken access
control / IDOR, business-logic flaws, auth/session, race conditions, plus
language-specific ones (Java deserialization/SpEL/mass-assignment/Actuator;
JS prototype-pollution/SSRF/NoSQL/ReDoS/JWT-confusion; Python SSTI/pickle/
subprocess/debug; etc.), and follow-ups driven by findings (secret git-history
sweep, dependency reachability, CSRF confirmation).

---

## 4. Backends, determinism, data egress

Configured under `"llm"` in `config.default.json` (or env
`LLM_BACKEND`/`LLM_ENDPOINT`/`LLM_MODEL`):

| backend | behaviour | egress |
|---|---|---|
| `poc` (default) | deterministic reasoning derived locally from the finding + snippet + language profile. **No model call.** | none |
| `onprem` | POST to an internal OpenAI-compatible endpoint (vLLM/Ollama/TGI), temperature 0 + evidence-seed | internal only |
| `disabled` | pass does nothing | none |

`poc` is fully offline and **repeatable** — same code, same verdicts — so it
runs on the air-gapped laptop with no model at all. `onprem` only talks to the
internal endpoint; on failure it degrades to the deterministic result. Only the
standard library is used (`urllib`) — no new dependency.

---

## 5. Usage

```
# default: LLM pass ON in offline poc mode
python -m scr --target "C:\path\to\client\source"

# turn it off
python -m scr --target ... --no-llm

# use the internal model
set LLM_BACKEND=onprem
set LLM_ENDPOINT=http://llm.internal:8000
set LLM_MODEL=qwen2.5-32b-instruct
python -m scr --target ...            # or: --llm-backend onprem
```

New outputs per scan: `llm_vectors.md`, plus `llm_verdict`/`llm_confidence`/
`llm_reasoning` fields in `findings.json` and `findings.csv`, and LLM notes
inline in `report.html`.

---

## 6. Future (adapters are ~60 lines each)
Wire real vision/extended reasoning into `_chat()` for richer FP triage; add
gosec (Go), SpotBugs+FindSecBugs (compiled Java), KICS (IaC), Syft (SBOM) as
new adapters; and feed `llm_vectors.md` into the DRG report as a "manual review
scope" appendix.

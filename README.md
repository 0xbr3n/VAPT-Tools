# Web VAPT Toolkit -- Consolidated Build

Single-file consolidation of the original modular toolkit (`main.py` +
13 separate tool files) into one Python script that can be turned into
a standalone binary with **zero internet** and **zero Python install**
required on the target machine.

## Files

| File              | Purpose                                                      |
|-------------------|--------------------------------------------------------------|
| `vapt_toolkit.py` | The one consolidated script -- all 13 tools in here.         |
| `requirements.txt`| Runtime deps (build-time only).                              |
| `build.sh`        | Linux / macOS build script.                                  |
| `build.bat`       | Windows build script.                                        |
| `README.md`       | This file.                                                   |

## What changed in this revision

**Tool 2 (JWT) was completely rebuilt as a unified REPL.** The old
flat-list style (re-paste the JWT for every option) is gone. The new
workflow holds an active token + decoded form + session context as
persistent state across all sub-operations. Decode is always one
keypress (`d`) and forge ops chain naturally through a history.

Menu groups inside the JWT tool:

```
Token & Session: [d] decode  [t] load token  [s] session context
Audit:           [a] risk flags  [j] JWKS probe  [r] test plan + export
Forge:           [1] alg=none           [2] alg confusion (RS->HS)
                 [3] KID injection      [4] JKU swap
                 [5] embed JWK (RSA)    [6] embed JWK (sym 'k')
                 [7] tamper claims      [8] re-sign HMAC
                 [9] HS256 brute-force  [10] modulus recovery
                 [11] PEM <-> JWK utilities
Other:           [h] history (reload prior)  [q] back
```

Key UX wins:
- **Decode never re-prompts.** Press `d` from any menu state.
- **Two JWK embedding modes are explicit.** [5] = generate fresh RSA
  keypair, embed full JWK (kty=RSA, n, e), sign with private key.
  [6] = symmetric `k` parameter (kty=oct, k=base64url-secret),
  HS256-signed with the same bytes.
- **Forge ops chain.** Every forge offers "set this as new active
  token" so you can do alg=none -> tamper claims -> re-sign in
  sequence without repasting.
- **History `[h]`** lists every token generated this session and lets
  you reload any one as the active token (incl. the original).
- **Crypto via `cryptography` library** (already bundled for the
  SSL/TLS tool) -- no pycryptodome dependency.

## Usage

### Run as a Python script (development)
```bash
pip install -r requirements.txt
python vapt_toolkit.py            # interactive menu
python vapt_toolkit.py 2          # jump straight to JWT workflow
```

### Build a standalone binary (the offline-target case)

**Linux / macOS:**
```bash
chmod +x build.sh
./build.sh
./dist/vapt_toolkit
```

**Windows:**
```cmd
build.bat
dist\vapt_toolkit.exe
```

PyInstaller bundles the Python interpreter and every dep into one
executable. After building, the binary needs nothing on the target.

### PyInstaller does not cross-compile

You build on the OS+arch you want to ship to:

| Target               | Build host                |
|----------------------|---------------------------|
| Linux x86_64         | Linux x86_64              |
| Windows 64-bit       | Windows 64-bit            |
| macOS Apple Silicon  | macOS Apple Silicon       |
| macOS Intel          | macOS Intel               |

## All 13 tools

```
[1]  Host Header Injection Tester
[2]  JWT Workflow (audit + forge, unified REPL)   <-- rebuilt
[3]  Insecure Headers Enumeration
[4]  SSL / TLS Audit (Protocols, Cert, Ciphers)
[5]  Request Smuggling Exploitation
[6]  CORS Misconfiguration Checks
[7]  Open Redirect Tester
[8]  HTTP Methods / Dangerous Verbs Check
[9]  Reflected XSS Quick Probe
[10] SSRF Candidate Detector
[11] IDOR Heuristics (Numeric ID Mutation)
[12] Cache Poisoning Signal Checks
[13] Clickjacking PoC Generator + Header Check
```

## Authorized testing only

These tools probe live targets. Only run them against systems you own
or have written authorization to test.

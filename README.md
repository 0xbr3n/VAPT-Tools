# VAPT-Tools
VAPT Tools is a collection of automation scripts for security testing across Web, Mobile, and Cloud. Organized by domain, it streamlines vulnerability assessment, exploits common attack vectors, and outputs clear reports for authorized penetration testing.

# 🌐 Web VAPT Tools

The **Web VAPT** folder contains automation scripts focused on web application penetration testing.  
Currently included:

---

## 1. Host Header Injection Tester
- Automates detection of host header injection vulnerabilities.
- Implements multiple attack vectors:
  - Flawed validation (non‑numeric ports, arbitrary subdomains, compromised subdomains)
  - Duplicate Host headers
  - Absolute URL in request line
  - Line wrapping (indented Host)
  - Host override headers (`X-Forwarded-Host`, `X-Host`, `Forwarded`, etc.)
- Interactive workflow with sensible defaults:
  - Target URL
  - Malicious callback domain (default: `attacker.com`)
  - Subdomain keyword (default: `attacker`)
  - Authentication headers (none/bearer/cookie)
  - Downgrade HTTPS → HTTP and force HTTP/1.1 options
- Outputs grouped results (**Successful**, **Interesting**, **Failed**) and saves a JSON report.

**Usage:**
```bash
python host.py
```

**📸 Screenshot Usage**
<img width="1746" height="1352" alt="image" src="https://github.com/user-attachments/assets/b891a03e-455d-4150-8e4b-1c12c05846e6" />


Follow the prompts to configure your test. Results are printed to the terminal and saved in host_inject_report.json.

## 2. JWT Exploitation Utilities
- Automates JSON Web Token exploitation techniques.
- Supports JKU/JWKS hosting, signature bypasses, and cryptographic attack chains.
- Designed for extensibility and integration with GitHub Pages for callback endpoints.
**Usage:**
```bash
python jwt_exploit.py
```

Interactive prompts guide you through token manipulation and exploitation scenarios.


**📸 Screenshot Usage**
<img width="2736" height="921" alt="image" src="https://github.com/user-attachments/assets/0a093a08-8655-4f33-a37f-b27fee030188" />

⚠️ Note
These tools are intended only for authorized security testing and educational purposes.
Do not use them against systems without explicit permission.

## 🙏 Credits
Special thanks to **iamdenis1234** for their work on deriving public keys from two different JWTs obtained during testing.  
Their contribution helped shape the JWT exploitation utilities included in this repository.


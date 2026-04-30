#!/usr/bin/env python3
"""
Headers Attacker
Workflow to test for insecure or missing HTTP security headers.
Supports both authenticated and unauthenticated scanning.
Deduplicates URLs with identical base paths (ignores query parameters).
Outputs misconfigurations with optional detail brackets.
"""

import requests
import sys
from urllib.parse import urlparse, urlunparse
from colorama import Fore, Style, init
from collections import defaultdict

# Initialize colorama for cross-platform colored output
init(autoreset=True)

SECURITY_HEADERS = {
    "X-XSS-Protection": "Deprecated header; should not be used.",
    "X-Frame-Options": "Protects against clickjacking.",
    "X-Content-Type-Options": "Prevents MIME type sniffing.",
    "Content-Security-Policy": "Mitigates XSS and data injection.",
    "Strict-Transport-Security": "Enforces HTTPS via HSTS.",
    "Referrer-Policy": "Controls referrer information leakage.",
    "Permissions-Policy": "Restricts powerful browser features.",
    "Cross-Origin-Resource-Policy": "Prevents cross-origin data leaks.",
    "Cross-Origin-Opener-Policy": "Isolates browsing contexts.",
    "Cross-Origin-Embedder-Policy": "Enforces secure embedding."
}

def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

def run_interactive():
    print("=== Headers Attacker ===")
    print("Paste your list of URLs (from BurpSuite: Right-click → Copy all URLs).")
    print("End input with an empty line.\n")

    urls = []
    while True:
        line = input()
        if not line.strip():
            break
        urls.append(line.strip())

    if not urls:
        print("No URLs provided. Exiting.")
        sys.exit(1)

    unique_urls = {}
    for u in urls:
        base = normalize_url(u)
        if base not in unique_urls:
            unique_urls[base] = u

    print(f"\n[+] {len(urls)} URLs provided, reduced to {len(unique_urls)} unique base paths.\n")

    print("Do you need authentication headers?")
    print("1. No authentication")
    print("2. Bearer token")
    print("3. Cookie")
    auth_choice = input("Enter choice number: ").strip()

    headers = {}
    if auth_choice == "2":
        token = input("Enter Bearer token: ").strip()
        headers["Authorization"] = f"Bearer {token}"
    elif auth_choice == "3":
        cookie = input("Enter Cookie string: ").strip()
        headers["Cookie"] = cookie

    print("\nChoose output format:")
    print("1. Group by misconfigured header → list URLs beneath each header")
    print("2. Group by URL → list misconfigured headers for each target")
    output_choice = input("Enter choice number: ").strip()

    print("\nFor Option 1, how should URLs be displayed?")
    print("1. Plain URLs only")
    print("2. URLs with brackets showing what was misconfigured/missing")
    url_display_choice = input("Enter choice number: ").strip()

    print("\n[+] Starting header misconfiguration scan...\n")

    results_by_url = {}
    results_by_header = defaultdict(list)

    for base, representative_url in unique_urls.items():
        try:
            resp = requests.get(representative_url, headers=headers, timeout=10, verify=False)
            found_headers = resp.headers
            issues = []

            for header, description in SECURITY_HEADERS.items():
                # Special case: X-XSS-Protection (deprecated, only flag if present)
                if header == "X-XSS-Protection":
                    if header in found_headers:
                        val = found_headers[header]
                        issues.append(f"{header} → Present (deprecated, value '{val}')")
                        results_by_header[header].append((representative_url, f"Present '{val}'"))
                    continue

                if header not in found_headers:
                    issues.append(f"{header} → Missing")
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
                                if age < 15552000:  # 6 months in seconds
                                    misconfigured = f"max-age too low ({age})"
                            except:
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
                        issues.append(f"{header} → Misconfigured ({misconfigured})")
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

    print("[+] Scan complete. Misconfigured headers highlighted with optional details.")

if __name__ == "__main__":
    run_interactive()

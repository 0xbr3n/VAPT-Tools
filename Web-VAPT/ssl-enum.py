#!/usr/bin/env python3
"""
SSL Audit Tool (Python version of testssl-like checks)
Features:
- ASCII banner and color-coded output
- Protocol support checks
- Cipher enumeration with strong/weak grouping
- Certificate checks (subject, issuer, expiry, signature algorithm, key length)
- Offline CVE references for weak cipher families
"""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
from colorama import Fore, Style, init
from cryptography import x509
from cryptography.hazmat.backends import default_backend

init(autoreset=True)

# ---------------------------
# ASCII Banner
# ---------------------------

BANNER = f"""{Fore.CYAN}{Style.BRIGHT}
 ___    ___    _             ___                             
(  _`\\ (  _`\\ ( )           (  _`\\                           
| (_(_)| (_(_)| |    ______ | (_(_)  ___   _   _   ___ ___   
`\\__ \\ `\\__ \\ | |  _(______)|  _)_ /' _ `\\( ) ( )/' _ ` _ `\\ 
( )_) |( )_) || |_( )       | (_( )| ( ) || (_) || ( ) ( ) | 
`\\____)`\\____)(____/'       (____/'(_) (_)`\\___/'(_) (_) (_) 
{Style.RESET_ALL}
"""

# ---------------------------
# Helpers
# ---------------------------

def parse_host(target):
    p = urlparse(target.strip())
    host = p.hostname or target.strip()
    port = p.port or 443
    return host, port

def is_weak(cipher_name):
    cname = cipher_name.lower()
    return "cbc" in cname or "sha1" in cname or "md5" in cname or "rc4" in cname

LOCAL_CVE_MAP = {
    "rc4": [
        "CVE-2013-2566: RC4 biases allow plaintext recovery",
        "CVE-2015-2808: RC4 stream cipher deemed insecure"
    ],
    "cbc": [
        "CVE-2011-3389: BEAST attack against TLS CBC",
        "CVE-2014-3566: POODLE attack against SSLv3 CBC"
    ],
    "sha1": [
        "CVE-2005-2086: Weaknesses in SHA1 MAC",
        "CVE-2017-18217: SHA1 collision attacks"
    ],
    "md5": [
        "CVE-2004-2761: MD5 collision vulnerabilities",
        "CVE-2008-2100: MD5 certificate forgery"
    ]
}

def get_local_cves(cipher_name):
    cname = cipher_name.lower()
    for key, cves in LOCAL_CVE_MAP.items():
        if key in cname:
            return cves
    return []

# ---------------------------
# Protocol Checks
# ---------------------------

def check_protocols(host, port):
    print(f"\n{Fore.MAGENTA}=== Protocol Support ==={Style.RESET_ALL}")
    protocols = {
        "TLSv1.0": ssl.PROTOCOL_TLSv1,
        "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
        "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
        "TLSv1.3": ssl.PROTOCOL_TLS_CLIENT
    }
    for pname, proto in protocols.items():
        try:
            ctx = ssl.SSLContext(proto)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    print(f"  - {pname}: {Fore.GREEN}SUPPORTED{Style.RESET_ALL}")
        except Exception:
            print(f"  - {pname}: {Fore.RED}NOT SUPPORTED{Style.RESET_ALL}")

# ---------------------------
# Certificate Checks
# ---------------------------

def check_certificate(host, port):
    print(f"\n{Fore.MAGENTA}=== Certificate Checks ==={Style.RESET_ALL}")
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der_cert = ssock.getpeercert(True)  # raw DER
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
            cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())

            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            exp = cert.not_valid_after_utc   # <-- use the UTC property

            print(f"  - Subject: {subject}")
            print(f"  - Issuer: {issuer}")
            print(f"  - Expires: {exp}")
            if exp < datetime.now(timezone.utc):
                print(f"    {Fore.RED}Certificate expired!{Style.RESET_ALL}")

            sigalg = cert.signature_hash_algorithm.name
            print(f"  - Signature Algorithm: {sigalg}")
            if sigalg in ["sha1", "md5"]:
                print(f"    {Fore.RED}Weak signature algorithm!{Style.RESET_ALL}")

            key = cert.public_key()
            try:
                key_size = key.key_size
                print(f"  - Key Size: {key_size} bits")
                if key_size < 2048:
                    print(f"    {Fore.RED}Weak key size!{Style.RESET_ALL}")
            except Exception:
                pass

# ---------------------------
# Cipher Enumeration
# ---------------------------

def openssl_to_iana(name: str) -> str:
    """Best-effort mapping of common OpenSSL cipher suite names to IANA names."""
    m = {
        # TLS 1.3 (already IANA-style)
        "TLS_AES_256_GCM_SHA384": "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256": "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_CCM_SHA256": "TLS_AES_128_CCM_SHA256",
        "TLS_AES_128_CCM_8_SHA256": "TLS_AES_128_CCM_8_SHA256",

        # TLS 1.2 GCM
        "AES128-GCM-SHA256": "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "AES256-GCM-SHA384": "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "DHE-RSA-AES128-GCM-SHA256": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "DHE-RSA-AES256-GCM-SHA384": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",

        # AES-CCM
        "AES128-CCM": "TLS_RSA_WITH_AES_128_CCM",
        "AES256-CCM": "TLS_RSA_WITH_AES_256_CCM",
        "AES128-CCM8": "TLS_RSA_WITH_AES_128_CCM_8",
        "AES256-CCM8": "TLS_RSA_WITH_AES_256_CCM_8",
        "DHE-RSA-AES128-CCM": "TLS_DHE_RSA_WITH_AES_128_CCM",
        "DHE-RSA-AES256-CCM": "TLS_DHE_RSA_WITH_AES_256_CCM",

        # ARIA-GCM
        "ARIA128-GCM-SHA256": "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
        "ARIA256-GCM-SHA384": "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
        "ECDHE-RSA-ARIA128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
        "ECDHE-RSA-ARIA256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
        "ECDHE-ECDSA-ARIA128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
        "ECDHE-ECDSA-ARIA256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",

        # Camellia (SHA256/SHA384)
        "CAMELLIA128-SHA256": "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "CAMELLIA256-SHA384": "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA384",
        "ECDHE-RSA-CAMELLIA128-SHA256": "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "ECDHE-RSA-CAMELLIA256-SHA384": "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
        "ECDHE-ECDSA-CAMELLIA128-SHA256": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
        "ECDHE-ECDSA-CAMELLIA256-SHA384": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",

        # ChaCha20-Poly1305 (TLS 1.2)
        "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "DHE-RSA-CHACHA20-POLY1305": "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",

        # AES-CBC (SHA / SHA256)
        "AES128-SHA": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "AES256-SHA": "TLS_RSA_WITH_AES_256_CBC_SHA",
        "AES128-SHA256": "TLS_RSA_WITH_AES_128_CBC_SHA256",
        "AES256-SHA256": "TLS_RSA_WITH_AES_256_CBC_SHA256",

        # 3DES
        "DES-CBC3-SHA": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",

        # RC4
        "RC4-MD5": "TLS_RSA_WITH_RC4_128_MD5",
        "RC4-SHA": "TLS_RSA_WITH_RC4_128_SHA",
        "ECDHE-RSA-RC4-SHA": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        "ECDHE-ECDSA-RC4-SHA": "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        "RSA-RC4-128-SHA": "TLS_RSA_WITH_RC4_128_SHA",

        # MD5
        "RSA-MD5": "TLS_RSA_WITH_MD5",
        "DES-CBC3-MD5": "TLS_RSA_WITH_3DES_EDE_CBC_MD5",

        # SEED
        "SEED-SHA": "TLS_RSA_WITH_SEED_CBC_SHA",
    }
    return m.get(name, f"(unknown IANA name for {name})")


def is_weak(cipher_name: str) -> bool:
    """Classify weak ciphers by keywords."""
    cname = cipher_name.lower()
    return (
        "cbc" in cname or
        "rc4" in cname or
        "md5" in cname or
        ("sha" in cname and not cname.endswith("sha256") and not cname.endswith("sha384") and not cname.endswith("sha512")) or
        "null" in cname or
        "export" in cname
    )


def check_ciphers(host, port):
    print(f"\n{Fore.MAGENTA}=== Cipher Enumeration ==={Style.RESET_ALL}")

    CIPHER_LIST = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",

    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",

    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    "TLS_DHE_RSA_WITH_AES_128_CCM",
    "TLS_DHE_RSA_WITH_AES_256_CCM",
    "TLS_DHE_RSA_WITH_AES_128_CCM_8",
    "TLS_DHE_RSA_WITH_AES_256_CCM_8",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",

    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",

    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",

    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",

    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",

    "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",

    "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",

    "TLS_ECDH_ANON_WITH_AES_256_CBC_SHA",
    "TLS_ECDH_ANON_WITH_AES_128_CBC_SHA",

    "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",

    "TLS_PSK_WITH_AES_256_GCM_SHA384",
    "TLS_PSK_WITH_AES_128_GCM_SHA256",
    "TLS_PSK_WITH_AES_256_CBC_SHA384",
    "TLS_PSK_WITH_AES_128_CBC_SHA256",
    "TLS_PSK_WITH_AES_256_CBC_SHA",
    "TLS_PSK_WITH_AES_128_CBC_SHA",
    "TLS_PSK_WITH_RC4_128_SHA",
    "TLS_PSK_WITH_3DES_EDE_CBC_SHA",

    "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
    "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
    "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
    "TLS_DHE_PSK_WITH_RC4_128_SHA",
    "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",

    "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
    "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
    "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
    "TLS_RSA_PSK_WITH_RC4_128_SHA",
    "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",

    "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
    "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
    "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
    "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
    "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
    "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",

    "TLS_RSA_WITH_NULL_MD5",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_RSA_WITH_NULL_SHA256",

    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    "TLS_ECDH_RSA_WITH_RC4_128_SHA",

    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",

    "TLS_RSA_WITH_DES_CBC_SHA",
    "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    "TLS_DHE_DSS_WITH_DES_CBC_SHA",

    "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",
    "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5",
    "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
    "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
    "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
    "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",

    "TLS_NULL_WITH_NULL_NULL",

    "SSL_RSA_WITH_NULL_MD5",
    "SSL_RSA_WITH_NULL_SHA",
    "SSL_RSA_WITH_RC4_128_MD5",
    "SSL_RSA_WITH_RC4_128_SHA",
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_RSA_WITH_DES_CBC_SHA",
    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "SSL_DHE_RSA_WITH_DES_CBC_SHA",
    "SSL_DHE_DSS_WITH_DES_CBC_SHA",
    "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
    "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",

    "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
    "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
    "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    "TLS_DH_anon_WITH_RC4_128_MD5",
    "TLS_DH_anon_WITH_DES_CBC_SHA",
    "TLS_DH_anon_WITH_RC4_128_SHA",
    "TLS_DH_anon_WITH_NULL_SHA",
    "TLS_DH_anon_WITH_NULL_MD5",

    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",

    "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
    "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
    "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
    "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
    "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",

    "TLS_RSA_WITH_SEED_CBC_SHA",
    "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
    "TLS_DHE_DSS_WITH_SEED_CBC_SHA",

    "TLS_GOSTR341094_WITH_28147_CNT_IMIT",
    "TLS_GOSTR341001_WITH_28147_CNT_IMIT",
    "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
    "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
    "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
    "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
    "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S",

    "TLS_PSK_WITH_NULL_SHA",
    "TLS_PSK_WITH_NULL_SHA256",
    "TLS_PSK_WITH_NULL_SHA384",
    "TLS_DHE_PSK_WITH_NULL_SHA",
    "TLS_DHE_PSK_WITH_NULL_SHA256",
    "TLS_DHE_PSK_WITH_NULL_SHA384",
    "TLS_RSA_PSK_WITH_NULL_SHA",
    "TLS_RSA_PSK_WITH_NULL_SHA256",
    "TLS_RSA_PSK_WITH_NULL_SHA384",

    "TLS_KRB5_WITH_DES_CBC_SHA",
    "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
    "TLS_KRB5_WITH_RC4_128_SHA",
    "TLS_KRB5_WITH_IDEA_CBC_SHA",
    "TLS_KRB5_WITH_DES_CBC_MD5",
    "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
    "TLS_KRB5_WITH_RC4_128_MD5",
    "TLS_KRB5_WITH_IDEA_CBC_MD5",

    "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
    "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
    "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
    "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
    "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
    "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"
]


    strong_total, weak_total, unsupported_total = set(), set(), set()

    # TLS 1.3 negotiated once
    try:
        ctx13 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx13.check_hostname = False
        ctx13.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx13.wrap_socket(sock, server_hostname=host) as ssock:
                negotiated = ssock.cipher()[0]
                version = ssock.version()
                if version and version.startswith("TLSv1.3"):
                    iana_name = openssl_to_iana(negotiated)
                    print(f"  - {iana_name} (TLS 1.3): {Fore.GREEN}OK{Style.RESET_ALL}")
                    strong_total.add(iana_name)
    except Exception:
        pass

    for cipher in CIPHER_LIST:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # IMPORTANT: set_ciphers() only understands OpenSSL names.
            # If you keep IANA names, most will fail here.
            ctx.set_ciphers(cipher)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    negotiated = ssock.cipher()[0]
                    if negotiated not in strong_total and negotiated not in weak_total:
                        if is_weak(negotiated):
                            print(f"  - {cipher}: {Fore.RED}WEAK{Style.RESET_ALL}")
                            weak_total.add(cipher)
                        else:
                            print(f"  - {cipher}: {Fore.GREEN}OK{Style.RESET_ALL}")
                            strong_total.add(cipher)
        except Exception:
            if cipher not in unsupported_total:
                print(f"  - {cipher}: {Fore.YELLOW}Not supported{Style.RESET_ALL}")
                unsupported_total.add(cipher)

    # Summary
    print(f"\n{Fore.BLUE}{Style.BRIGHT}=== Cipher Summary ==={Style.RESET_ALL}\n")

    print(f"{Fore.GREEN}Strong Ciphers:{Style.RESET_ALL}")
    print("  - None" if not strong_total else "\n".join(f"  - {c}" for c in sorted(strong_total)))

    print(f"\n{Fore.RED}Weak Ciphers (CBC, RC4, SHA1, MD5, NULL, EXPORT):{Style.RESET_ALL}")
    print("  - None" if not weak_total else "\n".join(f"  - {c}" for c in sorted(weak_total)))

    print(f"\n{Fore.YELLOW}Unsupported Ciphers:{Style.RESET_ALL}")
    print("  - None" if not unsupported_total else "\n".join(f"  - {c}" for c in sorted(unsupported_total)))

    total_tested = len(strong_total) + len(weak_total) + len(unsupported_total)
    print(f"\n{Fore.CYAN}Unique ciphers tested: {total_tested} | Strong: {len(strong_total)} | Weak: {len(weak_total)} | Unsupported: {len(unsupported_total)}{Style.RESET_ALL}")


def run_interactive():
    print(BANNER)
    target = input(f"{Fore.CYAN}Enter target URL (e.g. https://example.com): {Style.RESET_ALL}").strip()
    host, port = parse_host(target)

    print(f"\n[+] Target: {Fore.CYAN}{host}:{port}{Style.RESET_ALL}")

    check_protocols(host, port)
    check_certificate(host, port)
    check_ciphers(host, port)

    print(f"\n{Fore.BLUE}{Style.BRIGHT}=== Audit Complete ==={Style.RESET_ALL}")

# ---------------------------
# Main entry
# ---------------------------

if __name__ == "__main__":
    run_interactive()
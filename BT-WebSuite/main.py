#!/usr/bin/env python3
"""Web VAPT Tools Launcher

Loads tools by FILE PATH (so hyphen filenames work). Each tool must expose run_interactive().
"""

from __future__ import annotations

import os
import sys
import importlib.util
from typing import Dict, Tuple

TOOLS: Dict[str, Tuple[str, str]] = {
    "1": ("Host Header Injection Tester", "host-attacker.py"),
    "2": ("JWT Exploitation Tool", "jwt-attacker-fixed.py"),
    "3": ("Insecure Headers Enumeration", "headers.py"),
    "4": ("SSL / TLS Audit (Protocols, Cert, Ciphers)", "ssl-enum.py"),
    "5": ("Request Smuggling Exploitation", "smuggling.py"),
    "6": ("CORS Misconfiguration Checks", "cors.py"),
    "7": ("Open Redirect Tester", "open-redirect.py"),
    "8": ("HTTP Methods / Dangerous Verbs Check", "http-methods.py"),
    "9": ("Reflected XSS Quick Probe (Heuristic)", "xss-reflected.py"),
    "10": ("SSRF Candidate Detector (Passive + Optional Probes)", "ssrf-detector.py"),
    "11": ("IDOR Heuristics (Numeric ID Mutation)", "idor-heuristics.py"),
    "12": ("Cache Poisoning Signal Checks (Heuristic)", "cache-signals.py"),
}

BOX_WIDTH = 68


def _here() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def print_menu() -> None:
    print("+" + "-" * BOX_WIDTH + "+")
    print("|   Which workflow do you want to run?                                  |")
    print("+" + "-" * BOX_WIDTH + "+")
    for key in sorted(TOOLS.keys(), key=lambda x: int(x)):
        desc, _ = TOOLS[key]
        line = f"[{key}] {desc}"
        print(f"|  {line:<{BOX_WIDTH-4}}|")
    print("+" + "-" * BOX_WIDTH + "+")


def load_module_from_path(py_path: str):
    mod_name = "tool_" + os.path.splitext(os.path.basename(py_path))[0].replace("-", "_")
    spec = importlib.util.spec_from_file_location(mod_name, py_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module spec from: {py_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


def main() -> None:
    ascii_art = r"""
,-----.                           ,--.               ,--.          ,--.   ,--.       ,--.        ,---.          ,--.  ,--.           
|  |) /_ ,--.--. ,---. ,--,--,  ,-|  | ,---. ,--,--, |  |,---.     |  |   |  | ,---. |  |-.     '   .-' ,--.,--.`--',-'  '-. ,---.  
|  .-.  \|  .--'| .-. :|      \' .-. || .-. ||      \`-'(  .-'     |  |.'.|  || .-. :| .-. '    `.  `-. |  ||  |,--.'-.  .-'| .-. : 
|  '--' /|  |   \   --.|  ||  |\ `-' |' '-' '|  ||  |   .-'  `)    |   ,'.   |\   --.| `-' |    .-'    |'  ''  '|  |  |  |  \   --. 
`------' `--'    `----'`--''--' `---'  `---' `--''--'   `----'     '--'   '--' `----' `---'     `-----'  `----' `--'  `--'   `----' 
"""
    print(ascii_art)
    print_menu()

    choice = input("\nEnter choice number: ").strip()
    if choice not in TOOLS:
        print("Invalid choice. Exiting.")
        sys.exit(1)

    desc, filename = TOOLS[choice]
    py_path = os.path.join(_here(), filename)
    if not os.path.exists(py_path):
        print(f"Tool file not found: {py_path}")
        sys.exit(1)

    print(f"\n[+] Launching: {desc}\n")

    try:
        module = load_module_from_path(py_path)
    except Exception as e:
        print(f"[!] Failed to load tool: {e}")
        sys.exit(1)

    if not hasattr(module, "run_interactive"):
        print(f"[!] Tool '{filename}' does not define run_interactive().")
        sys.exit(1)

    try:
        module.run_interactive()
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.")
    except Exception as e:
        print(f"\n[!] Tool crashed: {e}")


if __name__ == "__main__":
    main()

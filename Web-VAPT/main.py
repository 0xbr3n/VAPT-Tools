#!/usr/bin/env python3
"""
Web VAPT Tools Launcher
Central menu to run different Web Attack Workflows
"""

import importlib
import sys

# Map menu options to script module names
TOOLS = {
    "1": ("Host Header Injection Tester", "host-attacker"),
    "2": ("JWT Exploitation Tool", "jwt-attacker"),
    "3": ("Insecure Headers Enumeration", "headers"),
    "4": ("SSL Ciphers Enumeration", "ssl-enum"),
    "5": ("Request Smuggling Exploitation", "smuggling"),
    "6": ("Cross Origin Resource Sharing", "cors")
    # Add future tools here:
    # "7": ("Cross Site Request Forgery", "CSRF"),
    # "8": ("Cross Site Scripting", "XSS"),
}

BOX_WIDTH = 48  # width inside the box

def print_menu():
    print("+" + "-" * BOX_WIDTH + "+")
    print("|   Which attack workflow do you want to run?   |")
    print("+" + "-" * BOX_WIDTH + "+")
    for key, (desc, _) in TOOLS.items():
        # pad each option to fit the box width
        line = f"[{key}] {desc}"
        print(f"|  {line:<{BOX_WIDTH-4}}|")
    print("+" + "-" * BOX_WIDTH + "+")

def main():
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

    desc, module_name = TOOLS[choice]
    print(f"\n[+] Launching {desc}...\n")

    try:
        # Dynamically import the chosen module
        module = importlib.import_module(module_name)

        # Expect each module to have a run_interactive() function
        if hasattr(module, "run_interactive"):
            module.run_interactive()
        else:
            print(f"Module '{module_name}' does not define run_interactive().")
    except ImportError:
        print(f"Could not import module '{module_name}'. Make sure the file {module_name}.py exists.")

if __name__ == "__main__":
    main()

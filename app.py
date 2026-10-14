from pathlib import Path
import subprocess
import sys
import hashlib
import hmac
import getpass

ROOT = Path(__file__).resolve().parent
REQUIREMENTS = ROOT / "requirements.txt"

# Password: CyberSquad
PASSWORD_HASH = hashlib.sha256(
    b"CyberSquad"
).hexdigest()

TOOLS = {
    
    
    "1": ("Metadata Tool", ROOT / "metadata" / "metadata.py"),
    "2": ("Web Vulnerability Scanner", ROOT / "tools" / "scan.py"),
    "3": ("URL Detector", ROOT / "tools" / "detector.py"),
    "4": ("Anonymous Chat", ROOT / "anonymous_chat" / "main.py"),
    "5": ("Number to Information", ROOT / "tools" / "phoneinfo.py"),
    "6": ("DDOS ATTACK", ROOT / "tools" / "trafficcheck.py"),
}


def password_lock():
    print("\n" + "=" * 48)
    print("              CYBERSQUAD SECURITY")
    print("=" * 48)

    for attempt in range(3):
        try:
            password = getpass.getpass("Enter Password: ")
        except (EOFError, KeyboardInterrupt):
            print("\nAccess cancelled.")
            return False
        

        entered_hash = hashlib.sha256(
            password.encode("utf-8")
        ).hexdigest()

        if hmac.compare_digest(entered_hash, PASSWORD_HASH):
            print("\n[+] Access granted!\n")
            return True

        print("[!] Wrong password!")

    print("[!] Access denied.")
    return False


def install_requirements():
    if not REQUIREMENTS.is_file():
        print("[!] requirements.txt not found.")
        print("[!] Create it beside app.py.")
        return False

    print("[+] Checking/installing Python requirements...")

    try:
        subprocess.run(
            [
                sys.executable, "-m", "pip",
                "install", "-r", str(REQUIREMENTS)
            ],
            check=True
        )
        print("[+] Requirements ready!\n")
        return True

    except subprocess.CalledProcessError:
        print("[!] Installation failed. Check internet and pip.")
        return False


def banner():
    print(r"""
   ____      _
  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ██╗██╗   ██╗██╗  ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝╚██╔══██╗████╗  ██║██║   ██║╚██╗██╔╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔██╗ ██║██║   ██║ ╚███╔╝
██║       ╚██╔╝  ██╔══██╗██╔══██╗██╔══██╗██║╚██╗██║██║   ██║ ██╔██╗
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚████║╚██████╔╝██╔╝ ██╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝
       CYBERNUX | CYBERSECURITY TOOLKIT
""")


def show_menu():
    print("=" * 48)
    print("                    MAIN MENU")
    print("=" * 48)

    for number, (name, _) in TOOLS.items():
        print(f"  [{number}] {name}")

    print("  [0] Exit")
    print("=" * 48)


def launch_tool(number):
    name, script = TOOLS[number]

    if not script.is_file():
        print(f"\n[ERROR] File not found:\n{script}")
        input("\nPress Enter to return to menu...")
        return

    print(f"\n[+] Launching: {name}")
    
    print("-" * 48)

    try:
        result = subprocess.run(
            [sys.executable, "-u", str(script)],
            cwd=str(script.parent),
            check=False
        )

        if result.returncode != 0:
            print(f"\n[!] Tool exited with code {result.returncode}.")

    except KeyboardInterrupt:
        print("\n[!] Tool interrupted by user.")

    except OSError as error:
        print(f"\n[ERROR] Could not launch tool: {error}")

    input("\nPress Enter to return to CyberNux menu...")


def main():
    # Password is required before installing dependencies or opening the menu.
    if not password_lock():
        raise SystemExit(1)

    if not install_requirements():
        raise SystemExit(1)

    while True:
        banner()
        show_menu()

        try:
            choice = input("\nCyberNux > ").strip()

        except (EOFError, KeyboardInterrupt):
            print("\n\n[*] CyberNux closed.")
            break

        if choice == "0":
            print("\n[*] Exiting CyberNux. Goodbye!")
            break

        if choice not in TOOLS:
            print("\n[!] Invalid option. Choose 0-5.")
            input("Press Enter to continue...")
            continue

        if choice == "5":
            print(
                "\n[!] Scan only systems you own "
                "or have explicit permission to test."
            )

        launch_tool(choice)
        print()


if __name__ == "__main__":
    main()

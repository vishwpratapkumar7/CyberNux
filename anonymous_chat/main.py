#!/usr/bin/env python3
# Anonymous Chat - launcher / menu
#
# [1] Chat on Browser  -> serves index.html (server.py) and opens the browser
# [2] Exit
#
# The chat runs entirely in your browser. This launcher only starts the
# local frontend server - it needs just the Python standard library.

import os
import sys
import time

if os.name == "nt":
    os.system("")  # enable ANSI colours on Windows 10+ consoles

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, GREEN, YELLOW, CYAN = "\033[91m", "\033[92m", "\033[93m", "\033[96m"

FONT = {
    "A": (" ██  ", "█   █", "█████", "█   █", "█   █"),
    "C": (" ████", "█    ", "█    ", "█    ", " ████"),
    "H": ("█   █", "█   █", "█████", "█   █", "█   █"),
    "M": ("█   █", "██ ██", "█ █ █", "█   █", "█   █"),
    "N": ("█   █", "██  █", "█ █ █", "█  ██", "█   █"),
    "O": (" ███ ", "█   █", "█   █", "█   █", " ███ "),
    "S": (" ████", "█    ", " ███ ", "    █", "████ "),
    "T": ("█████", "  █  ", "  █  ", "  █  ", "  █  "),
    "U": ("█   █", "█   █", "█   █", "█   █", " ███ "),
    "Y": ("█   █", "█   █", " ███ ", "  █  ", "  █  "),
}


def draw_word(word, colour):
    rows = [""] * 5
    for ch in word:
        for i in range(5):
            rows[i] += FONT[ch][i] + " "
    for row in rows:
        print(colour + row + RESET)


def banner():
    print()
    draw_word("ANONYMOUS", RED)
    draw_word("CHAT", CYAN)
    print(DIM + "─" * 54 + RESET)
    print(GREEN + "» anonymous group chat · no sign-up · no logs on your device «" + RESET)
    print(DIM + "  secure websocket link · runs entirely in your browser" + RESET)
    print()


def menu():
    print(f"{YELLOW}[1]{RESET} Chat on Browser")
    print(f"{YELLOW}[2]{RESET} Exit")
    print()


def run_browser():
    try:
        import server
        print(f"{CYAN}[*] starting the frontend server …{RESET}")
        print(f"{CYAN}[*] it will open in your browser — press Ctrl+C here to stop it.{RESET}")
        server.main()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print(f"{RED}[!] frontend server error: {exc}{RESET}")
        time.sleep(1.5)


def main():
    while True:
        print("\033[2J\033[H", end="")
        banner()
        menu()
        try:
            choice = input(f"{CYAN}{BOLD}select>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            choice = "2"
        if choice == "1":
            run_browser()      # returns here after Ctrl+C — menu redraws
        elif choice == "2":
            print(f"{GREEN}[*] stay anonymous — bye!{RESET}")
            time.sleep(0.6)
            break
        else:
            print(f"{RED}[!] invalid choice — enter 1 or 2{RESET}")
            time.sleep(1.4)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(0)
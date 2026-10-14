import itertools
import json
import sys
import threading
import time
import requests

# Clean Dark / Cyber Theme ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

# APIs
API_URLS = (
    ("HI-TECH DATABASE API", "https://hi-tech-database-api.vercel.app/search", "q", {}),
    ("TRUECALLER INFO API", "https://truecallerinfo-api.vercel.app/search", "phone", {}),
    
)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}


# Radar Animation Function
def radar_searching(stop_event):
    radar_frames = [
        "◜ [ •       ]",
        "◠ [  •      ]",
        "◝ [   •     ]",
        "◞ [    •    ]",
        "◡ [     •   ]",
        "◟ [      •  ]",
        "◜ [       • ]",
        "◠ [      •  ]",
        "◝ [     •   ]",
        "◞ [    •    ]",
        "◡ [   •     ]",
        "◟ [  •      ]",
    ]
    spinner = itertools.cycle(radar_frames)
    while not stop_event.is_set():
        sys.stdout.write(f"\r{RED}{next(spinner)} Searching Information on Darkweb...{RESET}")
        sys.stdout.flush()
        time.sleep(0.08)

    # Line clear karne ke liye
    sys.stdout.write("\r" + " " * 65 + "\r")
    sys.stdout.flush()


def print_banner():
    banner = f"""
{RED}{BOLD}  ██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗
  ██╔══██╗██║  ██║██╔═══██╗████╗  ██║██╔════╝
  ██████╔╝███████║██║   ██║██╔██╗ ██║█████╗  
  ██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║██╔══╝  
  ██║     ██║  ██║╚██████╔╝██║ ╚████║███████╗
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝{RESET}
{GRAY}─────────────────────────────────────────────────────────────{RESET}
{GREEN}{BOLD}[★] Multi-Source Intelligence & Lookup Tool [★]{RESET}
{GRAY}─────────────────────────────────────────────────────────────{RESET}
"""
    print(banner)


def fetch_api_data(url: str, param_key: str, extra_params: dict, query_value: str):
    params = {param_key: query_value}
    if extra_params:
        params.update(extra_params)

    try:
        response = requests.get(url, params=params, headers=HEADERS, timeout=12)
        if response.status_code == 200:
            try:
                data = response.json()
                if data:
                    return data
            except ValueError:
                if response.text.strip():
                    return response.text
        return None
    except Exception:
        return None


def main():
    print_banner()
    query_input = input(f"{GREEN}{BOLD}Enter Phone Number: {RESET}").strip()

    if not query_input:
        print(f"{RED}[!] Input cannot be empty.{RESET}")
        return

    print()

    # Radar Animation Start
    stop_event = threading.Event()
    radar_thread = threading.Thread(target=radar_searching, args=(stop_event,))
    radar_thread.start()

    final_data = None
    source_name = None

    try:
        # Fallback sequence
        for name, endpoint, param_name, extra_params in API_URLS:
            res = fetch_api_data(endpoint, param_name, extra_params, query_input)
            if res:
                final_data = res
                source_name = name
                break
    finally:
        # Stop animation
        stop_event.set()
        radar_thread.join()

    # Status check: Found or Not Found
    if final_data:
        print(f"{GREEN}{BOLD}╔══════════════════════════════════════════════╗{RESET}")
        print(f"{GREEN}{BOLD}║         [✓] Information Found!               ║{RESET}")
        print(f"{GREEN}{BOLD}╚══════════════════════════════════════════════╝{RESET}")
      

        print(f"{GREEN}[+] Extracted Data:{RESET}")
        if isinstance(final_data, (dict, list)):
            print(f"{GREEN}{json.dumps(final_data, indent=2, ensure_ascii=False)}{RESET}\n")
        else:
            print(f"{GREEN}{final_data}{RESET}\n")
    else:
        print(f"{RED}{BOLD}╔══════════════════════════════════════════════╗{RESET}")
        print(f"{RED}{BOLD}║         [✗] No Information Found!            ║{RESET}")
        print(f"{RED}{BOLD}╚══════════════════════════════════════════════╝{RESET}\n")


if __name__ == "__main__":
    main()
# Developed with chatGPT debugging as well as chatGPT code generation (about 20% of the code is written by chatGPT, with major debugging help as well)
# Developed mainly as a learning project for logic handling, magic number avoidance, and parsing
# Not intended for production use, security, or efficiency

import sys
import subprocess
from urllib.parse import urlparse

FUZZ_PATHS = [
    # --- Admin / Management ---
    "admin", "admin/", "admin.php", "admin/login",
    "admin/login.php", "admin/dashboard", "admin_panel", "admin-panel",
    "admin_old", "admin.bak",

    # --- WordPress ---
    "wp-admin", "wp-admin/", "wp-login.php", "wp-content",
    "wp-content/uploads", "wp-config.php", "xmlrpc.php",

    # --- Login / Auth ---
    "login", "login.php", "logout", "register",
    "signup", "auth", "auth/login", "user",
    "users", "account", "profile", "password_reset",
    "forgot",

    # --- Backups / Old / Temp ---
    "backup", "backup.zip", "backup.tar.gz", "site.zip",
    "db.sql", "config.bak", "config.old", "config.php~",
    "index.php~", "index.bak",

    # --- Debug / Dev / Test ---
    "debug", "debug.php", "test", "test.php",
    "dev", "dev.php", "staging", "beta",
    "qa", "_ignition", "__debug__"
]

def help_menu():
    help_text = [
        "SiteFuzzer - A simple web fuzzing tool",
        "",
        "Usage: python3 Main.py [options]",
        "",
        "Options:",
        "  -U <URL>            Target URL with /F placeholder for fuzzing",
        "  -F <wordlist>       Wordlist file for fuzzing paths",
        "  -H <Header>         Additional HTTP header to include (can be used multiple times)",
        "  -C <Cookie>         Additional cookie to include (can be used multiple times)",
        "  -E <extension>      File extension to append (can be used multiple times)",
        "  -SP                 Skip ping check before fuzzing",
        "  -h                  Show this help menu",
        "",
        "Example:",
        "  python3 Main.py -U http://example.com/F -F wordlist.txt -H 'User-Agent: CustomAgent' -C 'sessionid=abc123' -E .php -E .bak",
    ]
    print("\n".join(help_text))
    sys.exit(0)

def main():
    tokens = sys.argv[1:]
    if "-h" in tokens:
        help_menu()

    if not valid_fuzzing_arguments(tokens):
        print("[!] Invalid arguments")
        sys.exit(1)

    parsed = get_args(tokens)

    # Validate URL
    if "-U" not in parsed:
        print("[!] -U <URL> is required")
        sys.exit(1)

    parsed_url = urlparse(parsed["-U"][0])
    host_only = parsed_url.hostname

    
    if not parsed_url.scheme:
        print("[!] URL must include scheme (http:// or https://)")
        sys.exit(1)

    if not host_only:
        print("[!] Invalid URL")
        sys.exit(1)

    # Ping check unless skipped
    if "-SP" not in parsed:
        if not check_if_host_reachable(host_only):
            print("[!] Host not reachable")
            sys.exit(1)

    # Enforce /F placeholder
    if "/F" not in parsed["-U"][0]:
        print("[!] URL must contain /F placeholder (example: http://site/F)")
        sys.exit(1)

    print("[+] Arguments parsed successfully")

    host = parsed["-U"][0]
    fuzz_file = parsed.get("-F", [None])[0]

    headers = parsed.get("-H", [])
    cookies = parsed.get("-C", [])
    exts = parsed.get("-E", [])

    if not fuzz_file:
        print("[!] Fuzzing requires -F <wordlist>")
        sys.exit(1)

    fuzz_site(host, fuzz_file, headers, cookies, exts)

def check_if_host_reachable(host) -> bool: # Define a function to check if the host is reachable, points the returned value to a boolean, if 1, it's false, if 0, it's true
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", host], # Hard coded to avoid a command injection vulnerability
        stdout=subprocess.DEVNULL, # Discard the output
        stderr=subprocess.DEVNULL  # Discard the error output
    )
    return result.returncode == 0 # Return True if the host is reachable (return code 0), else False

def valid_fuzzing_arguments(tokens):
    valid_opts_with_fuzzing = [
        "-U", "-F", "-H", 
        "-C", "-E"
    ]
    valid_opts_without_fuzzing = ["-SP"]

    valid_opts = valid_opts_with_fuzzing + valid_opts_without_fuzzing

    if not tokens:
        print("[!] No arguments provided.")
        return False
    if tokens[0] == "-h":
        return True

    i = 0
    while i < len(tokens):
        token = tokens[i]

        if not token.startswith("-"):
            print(f"[!] Unexpected value: {token}")
            return False

        if token not in valid_opts:
            print(f"[!] Unknown option: {token}")
            return False

        if token in valid_opts_with_fuzzing:
            if i + 1 >= len(tokens):
                print(f"[!] Option {token} requires a value")
                return False
            i += 2
        else:
            i += 1

    return True

def get_args(input_args):
    args = {}
    current_key = None

    for token in input_args:
        if token.startswith("-"):
            current_key = token
            args.setdefault(current_key, [])
        elif current_key:
            args[current_key].append(token)

    return args

def fuzz_site(host, fuzz_file, headers=None, cookies=None, exts=None):

    append_headers = headers or []
    append_cookies = cookies or []
    append_extensions = exts if exts else [""]
    append_extensions = [
        e if not e or e.startswith(".") else f".{e}"
        for e in append_extensions
    ]


    interesting_codes = {"200", "301", "302", "401", "403", "500"}

    with open(fuzz_file, "r") as f:
        paths = [line.strip() for line in f if line.strip()]

    for path in paths:
        for ext in append_extensions:
            full_path = f"{path}{ext}"
            url = host.replace("/F", f"/{full_path}")

            cmd = [
                "curl", "--max-time", "5", 
                "-s", "-o", "/dev/null",
                "-w", "%{http_code}",
                url
            ]

            for header in append_headers:
                cmd.extend(["-H", header])

            for cookie in append_cookies:
                cmd.extend(["-b", cookie])

            response = subprocess.run(cmd, capture_output=True, text=True)
            status_code = response.stdout.strip()
            if status_code not in interesting_codes:
                continue

            is_interesting_path = any(
                p in full_path for p in FUZZ_PATHS
            )

            if is_interesting_path or status_code in interesting_codes - {"200", "302"}:
                print(f"[+] Interesting: {url} | {status_code}")
            else:
                print(f"[-] {url} | {status_code}")

if __name__ == "__main__":
    main()

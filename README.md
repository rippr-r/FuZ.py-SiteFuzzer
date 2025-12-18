# FuZ.py

**FuZ** is a educational web path fuzzing tool written in Python.
This project was created as a **one-off learning exercise** and is **not intended for production use or long-term maintenance**.

It focuses on practicing:

* Argument parsing and validation
* Logic flow handling
* Avoiding magic numbers
* Basic subprocess usage
* Defensive coding patterns (e.g., avoiding command injection)

> Approximately ~20% of the code was generated with ChatGPT assistance, with significant debugging help throughout development.

---

## ⚠️ Disclaimer

* **Not production-ready**
* **Not optimized for performance**
* **Not designed for security auditing at scale**
* **No future maintenance planned**

This tool exists purely as a learning artifact.

---

## Features

* Path fuzzing via a `/F` URL placeholder
* Custom wordlist support
* Optional file extension appending
* Custom headers and cookies
* Simple host reachability check (ping)
* HTTP response code filtering
* Highlights potentially interesting paths (admin, auth, backups, etc.)

---

## Usage

```bash
python3 Main.py [options]
```

### Required

* `-U <URL>` — Target URL **must contain `/F`** as the fuzzing placeholder
* `-F <wordlist>` — Wordlist containing paths to fuzz

### Optional

* `-H <Header>` — Additional HTTP header (repeatable)
* `-C <Cookie>` — Additional cookie (repeatable)
* `-E <extension>` — File extension to append (repeatable)
* `-SP` — Skip ping check before fuzzing
* `-h` — Show help menu

---

## Example

```bash
python3 Main.py \
  -U http://example.com/F \
  -F wordlist.txt \
  -H "User-Agent: CustomAgent" \
  -C "sessionid=abc123" \
  -E php 
```

---

## How It Works

1. Validates CLI arguments and required options
2. Ensures the target URL contains a `/F` placeholder
3. Optionally checks host reachability via `ping`
4. Reads fuzzing paths from a wordlist
5. Appends optional file extensions
6. Replaces `/F` with each generated path
7. Sends requests using `curl`
8. Filters and highlights “interesting” HTTP responses

---

## Interesting Response Codes

The following HTTP status codes are considered notable:

* `200` – OK
* `301`, `302` – Redirects
* `401`, `403` – Authentication / authorization related
* `500` – Server error

Paths matching common sensitive patterns (admin panels, backups, configs, etc.) are emphasized in output.

---

## Requirements

* Python 3.x
* `curl` available in PATH
* Unix-like system (uses `ping -c`)

---

## Project Status

🚧 **Archived / One-off Project**

This tool will **not** be actively developed or maintained.

---

## License

No license specified.

Use at your own risk and **only against systems you own or have explicit permission to test**.

---

## Educational Notes

If you are reviewing or learning from this code:

* AI was used for debugging and code generation / completion
* Expect explicit logic rather than abstractions
* Expect trade-offs in efficiency and robustness
* Expect verbosity intended for clarity over elegance

That is intentional.

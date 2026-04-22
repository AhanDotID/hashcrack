#!/usr/bin/env python3
# ============================================================
#  HashCrack - Hash Identifier + Dictionary Cracker
#  by Ahan Pahlevi | CianjurSec | github.com/AhanDotID/hashcrack
# ============================================================

import argparse
import hashlib
import re
import sys
import time
from pathlib import Path

# ─── ANSI Colors ─────────────────────────────────────────────────────────────

R      = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[38;5;82m"
CYAN   = "\033[38;5;51m"
RED    = "\033[38;5;196m"
YELLOW = "\033[38;5;226m"
GRAY   = "\033[38;5;240m"
WHITE  = "\033[38;5;255m"
PURPLE = "\033[38;5;135m"
ORANGE = "\033[38;5;214m"

def c(text, color): return f"{color}{text}{R}"

# ─── Banner ──────────────────────────────────────────────────────────────────

BANNER = f"""
{PURPLE}{BOLD}
  ██╗  ██╗ █████╗ ███████╗██╗  ██╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗
  ██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
  ███████║███████║███████╗███████║██║     ██████╔╝███████║██║     █████╔╝ 
  ██╔══██║██╔══██║╚════██║██╔══██║██║     ██╔══██╗██╔══██║██║     ██╔═██╗ 
  ██║  ██║██║  ██║███████║██║  ██║╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{R}
  {GREEN}{BOLD}Hash Identifier + Dictionary Cracker{R}
  {GRAY}by Ahan Pahlevi | CianjurSec | github.com/AhanDotID/hashcrack{R}
"""

# ─── Hash patterns ────────────────────────────────────────────────────────────

HASH_PATTERNS = [
    # (name, regex, length, note)
    ("MD5",          r"^[a-f0-9]{32}$",   32, "Very common, broken"),
    ("SHA-1",        r"^[a-f0-9]{40}$",   40, "Deprecated, broken"),
    ("SHA-256",      r"^[a-f0-9]{64}$",   64, "Widely used"),
    ("SHA-512",      r"^[a-f0-9]{128}$",  128, "Strong"),
    ("SHA-224",      r"^[a-f0-9]{56}$",   56, "SHA-2 family"),
    ("SHA-384",      r"^[a-f0-9]{96}$",   96, "SHA-2 family"),
    ("SHA3-256",     r"^[a-f0-9]{64}$",   64, "SHA-3 family"),
    ("SHA3-512",     r"^[a-f0-9]{128}$",  128, "SHA-3 family"),
    ("RIPEMD-160",   r"^[a-f0-9]{40}$",   40, "Bitcoin addresses"),
    ("BLAKE2s",      r"^[a-f0-9]{64}$",   64, "Modern, fast"),
    ("BLAKE2b",      r"^[a-f0-9]{128}$",  128, "Modern, fast"),
    ("MySQL4",       r"^[a-f0-9]{16}$",   16, "Old MySQL password"),
    ("CRC32",        r"^[a-f0-9]{8}$",    8,  "Checksum only"),
    ("bcrypt",       r"^\$2[ayb]\$.{56}$", None, "Strong, salted"),
    ("MD5 Crypt",    r"^\$1\$.{8}\$.{22}$", None, "Unix MD5"),
    ("SHA-512 Crypt",r"^\$6\$.+\$.{86}$",  None, "Unix SHA-512"),
    ("NTLM",         r"^[a-f0-9]{32}$",   32, "Windows password hash"),
    ("WPA/WPA2",     r"^[a-f0-9]{64}$",   64, "WiFi password hash"),
    ("Whirlpool",    r"^[a-f0-9]{128}$",  128, "Rare"),
]

HASH_ALGORITHMS = {
    "MD5":      "md5",
    "SHA-1":    "sha1",
    "SHA-256":  "sha256",
    "SHA-512":  "sha512",
    "SHA-224":  "sha224",
    "SHA-384":  "sha384",
    "SHA3-256": "sha3_256",
    "SHA3-512": "sha3_512",
    "RIPEMD-160": "ripemd160",
    "BLAKE2s":  "blake2s",
    "BLAKE2b":  "blake2b",
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def print_section(title, icon="◈"):
    print(f"\n  {CYAN}{icon} {BOLD}{title}{R}")
    print(f"  {GRAY}{'─' * 58}{R}")

def print_field(label, value, color=WHITE):
    if value:
        print(f"    {GRAY}{label:<20}{R} {color}{value}{R}")

# ─── Hash Identifier ─────────────────────────────────────────────────────────

def identify_hash(hash_str):
    hash_str = hash_str.strip()
    candidates = []

    for name, pattern, length, note in HASH_PATTERNS:
        if re.match(pattern, hash_str, re.IGNORECASE):
            candidates.append((name, note))

    return candidates

def show_identification(hash_str):
    print_section("Hash Identification", "🔍")
    print_field("Input Hash", hash_str[:64] + ("..." if len(hash_str) > 64 else ""), CYAN)
    print_field("Length", f"{len(hash_str)} chars")

    candidates = identify_hash(hash_str)

    if not candidates:
        print(f"\n    {RED}[!] Unknown hash type or invalid format{R}")
        return []

    print(f"\n    {YELLOW}Possible hash types:{R}")
    for i, (name, note) in enumerate(candidates):
        marker = f"{GREEN}[+]{R}" if i == 0 else f"{GRAY}[~]{R}"
        print(f"    {marker} {WHITE}{name:<15}{R} {GRAY}- {note}{R}")

    return [name for name, _ in candidates]

# ─── Hash compute ─────────────────────────────────────────────────────────────

def compute_hash(word, algorithm):
    try:
        algo = algorithm.lower().replace("-", "").replace("_", "")

        mapping = {
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
            "sha224": "sha224",
            "sha384": "sha384",
            "sha3256": "sha3_256",
            "sha3512": "sha3_512",
            "ripemd160": "ripemd160",
            "blake2s": "blake2s",
            "blake2b": "blake2b",
        }

        hashname = mapping.get(algo, algo)
        h = hashlib.new(hashname)
        h.update(word.encode("utf-8", errors="ignore"))
        return h.hexdigest()
    except Exception:
        return None

# ─── Dictionary Cracker ───────────────────────────────────────────────────────

def crack_hash(hash_str, wordlist_path, algorithms, verbose=False):
    print_section("Dictionary Attack", "🔨")

    hash_str = hash_str.strip().lower()

    # load wordlist
    try:
        wl = Path(wordlist_path)
        if not wl.exists():
            print(f"    {RED}[!] Wordlist not found: {wordlist_path}{R}")
            return None

        with open(wl, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"    {RED}[!] Error loading wordlist: {e}{R}")
        return None

    total = len(words)
    print_field("Wordlist", str(wordlist_path))
    print_field("Words loaded", f"{total:,}")
    print_field("Algorithms", ", ".join(algorithms))
    print(f"\n    {CYAN}[~]{R} Cracking... Press Ctrl+C to stop\n")

    start = time.time()
    tried = 0
    found = None

    try:
        for word in words:
            for algo in algorithms:
                hashed = compute_hash(word, algo)
                if hashed and hashed == hash_str:
                    elapsed = time.time() - start
                    found = (word, algo)

                    print(f"\r    {' ' * 60}")
                    print(f"    {GREEN}{BOLD}[✓] CRACKED!{R}")
                    print(f"\n    {GRAY}{'─' * 40}{R}")
                    print_field("Plaintext", word, f"{GREEN}{BOLD}")
                    print_field("Algorithm", algo, YELLOW)
                    print_field("Hash", hash_str, CYAN)
                    print_field("Tried", f"{tried:,} words")
                    print_field("Time", f"{elapsed:.2f}s")
                    print_field("Speed", f"{int(tried/elapsed):,} h/s" if elapsed > 0 else "N/A")
                    print(f"    {GRAY}{'─' * 40}{R}")
                    return found

            tried += 1

            # progress every 5000
            if tried % 5000 == 0:
                elapsed = time.time() - start
                speed = int(tried / elapsed) if elapsed > 0 else 0
                pct = tried / total * 100
                print(f"\r    {GRAY}[~]{R} {tried:,}/{total:,} ({pct:.1f}%) - {speed:,} h/s   ", end="", flush=True)

    except KeyboardInterrupt:
        print(f"\n\n    {YELLOW}[!] Interrupted by user{R}")

    elapsed = time.time() - start
    if not found:
        print(f"\r    {' ' * 70}")
        print(f"    {RED}[✗] Hash not cracked{R}")
        print_field("Tried", f"{tried:,} words")
        print_field("Time", f"{elapsed:.2f}s")
        print(f"\n    {GRAY}Tips: Try a larger wordlist like rockyou.txt{R}")

    return None

# ─── Hash Generator ──────────────────────────────────────────────────────────

def generate_hashes(text):
    print_section("Hash Generator", "⚙️")
    print_field("Input", text, CYAN)
    print()

    algos = [
        ("MD5",       "md5"),
        ("SHA-1",     "sha1"),
        ("SHA-256",   "sha256"),
        ("SHA-512",   "sha512"),
        ("SHA-224",   "sha224"),
        ("SHA-384",   "sha384"),
        ("SHA3-256",  "sha3_256"),
        ("SHA3-512",  "sha3_512"),
        ("BLAKE2s",   "blake2s"),
        ("BLAKE2b",   "blake2b"),
    ]

    for name, algo in algos:
        try:
            h = hashlib.new(algo)
            h.update(text.encode())
            digest = h.hexdigest()
            print(f"    {GRAY}{name:<12}{R} {WHITE}{digest}{R}")
        except Exception:
            pass

# ─── Built-in mini wordlist ───────────────────────────────────────────────────

MINI_WORDLIST = """password
123456
password123
admin
letmein
qwerty
abc123
monkey
master
dragon
111111
baseball
iloveyou
trustno1
sunshine
princess
welcome
shadow
superman
michael
football
charlie
donald
password1
qwerty123
passw0rd
hello
test
root
toor
alpine
secret
changeme
nothing
1234
12345
123456789
1234567890
0987654321
hunter2
pass
god
love
sex
money
fuck
ass
login
default
guest
demo
user
administrator
letmein1
abc
pass123
p@ssword
p@ss1234
Pa$$w0rd
P@ssword1
Summer2024
Winter2024
Spring2024
Fall2024
January1
February1
""".strip().splitlines()

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="hashcrack",
        description="Hash Identifier + Dictionary Cracker",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python hashcrack.py -i 5f4dcc3b5aa765d61d8327deb882cf99
  python hashcrack.py -i <hash> -w rockyou.txt
  python hashcrack.py -i <hash> -w wordlist.txt -a sha256
  python hashcrack.py -g "password123"
  python hashcrack.py -i <hash> --mini
        """
    )

    parser.add_argument("-i", "--identify",  metavar="HASH", help="Hash to identify and/or crack")
    parser.add_argument("-w", "--wordlist",  metavar="FILE", help="Wordlist file for cracking")
    parser.add_argument("-a", "--algorithm", metavar="ALGO", help="Force specific algorithm (md5, sha1, sha256, etc.)")
    parser.add_argument("-g", "--generate",  metavar="TEXT", help="Generate hashes from plaintext")
    parser.add_argument("--mini",            action="store_true", help="Use built-in mini wordlist (no file needed)")
    parser.add_argument("--no-color",        action="store_true", help="Disable colored output")

    args = parser.parse_args()

    if args.no_color:
        global R, BOLD, GREEN, CYAN, RED, YELLOW, GRAY, WHITE, PURPLE, ORANGE
        R = BOLD = GREEN = CYAN = RED = YELLOW = GRAY = WHITE = PURPLE = ORANGE = ""

    print(BANNER)

    if not any([args.identify, args.generate]):
        parser.print_help()
        sys.exit(0)

    # ── Generate mode
    if args.generate:
        generate_hashes(args.generate)
        print()
        return

    # ── Identify mode
    if args.identify:
        hash_str = args.identify.strip()
        candidates = show_identification(hash_str)

        # determine algos to try
        if args.algorithm:
            algos_to_try = [args.algorithm.upper()]
        elif candidates:
            # filter to crackable ones
            crackable = [c for c in candidates if c in HASH_ALGORITHMS]
            algos_to_try = crackable if crackable else candidates
        else:
            algos_to_try = ["MD5", "SHA-1", "SHA-256"]

        # crack
        if args.mini:
            # use built-in wordlist
            import tempfile, os
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tmp.write("\n".join(MINI_WORDLIST))
            tmp.close()
            crack_hash(hash_str, tmp.name, algos_to_try)
            os.unlink(tmp.name)

        elif args.wordlist:
            crack_hash(hash_str, args.wordlist, algos_to_try)

        else:
            print(f"\n  {YELLOW}[~]{R} No wordlist provided. Options:")
            print(f"      Use {CYAN}--mini{R}       → try built-in common passwords")
            print(f"      Use {CYAN}-w rockyou.txt{R} → use your own wordlist\n")

    print()

if __name__ == "__main__":
    main()

# #️⃣ HashCrack

```
  ██╗  ██╗ █████╗ ███████╗██╗  ██╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗
  ██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
  ███████║███████║███████╗███████║██║     ██████╔╝███████║██║     █████╔╝ 
  ██╔══██║██╔══██║╚════██║██╔══██║██║     ██╔══██╗██╔══██║██║     ██╔═██╗ 
  ██║  ██║██║  ██║███████║██║  ██║╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

**Hash Identifier + Dictionary Cracker** written in Python

> Built by Ahan Pahlevi | CianjurSec - for educational & CTF purposes only.

---

## ✨ Features

- 🔍 **Hash Identifier** - Auto-detect hash type (MD5, SHA-1, SHA-256, bcrypt, NTLM, dll)
- 🔨 **Dictionary Cracker** - Crack hash pakai wordlist (rockyou.txt, dll)
- ⚙️ **Hash Generator** - Generate hash dari plaintext (10 algoritma sekaligus)
- ⚡ **Built-in Mini Wordlist** - 60+ common passwords, no file needed
- 🎨 **Color-coded output** - mudah dibaca
- 🔧 **Force algorithm** - paksa algoritma tertentu kalau sudah tau tipenya

---

## 📦 Installation

```bash
git clone https://github.com/AhanDotID/hashcrack
cd hashcrack
python hashcrack.py -h
```

> Tidak perlu install library tambahan - hanya menggunakan Python standard library!

---

## 🚀 Usage

```
Usage: hashcrack.py [options]

Options:
  -i, --identify HASH     Hash to identify and/or crack
  -w, --wordlist FILE     Wordlist file for cracking
  -a, --algorithm ALGO    Force specific algorithm (md5, sha1, sha256, etc.)
  -g, --generate TEXT     Generate hashes from plaintext
  --mini                  Use built-in mini wordlist (no file needed)
  --no-color              Disable colored output
```

---

## 📖 Examples

**Identify hash type:**
```bash
python hashcrack.py -i 5f4dcc3b5aa765d61d8327deb882cf99
```

**Identify + crack pakai mini wordlist:**
```bash
python hashcrack.py -i 5f4dcc3b5aa765d61d8327deb882cf99 --mini
```

**Crack pakai rockyou.txt:**
```bash
python hashcrack.py -i <hash> -w rockyou.txt
```

**Force algoritma SHA-256:**
```bash
python hashcrack.py -i <hash> -w wordlist.txt -a sha256
```

**Generate semua hash dari text:**
```bash
python hashcrack.py -g "password123"
```

---

## 🔍 Supported Hash Types (Identification)

| Hash | Length | Notes |
|------|--------|-------|
| MD5 | 32 | Very common, broken |
| SHA-1 | 40 | Deprecated |
| SHA-256 | 64 | Widely used |
| SHA-512 | 128 | Strong |
| SHA-224 | 56 | SHA-2 family |
| SHA-384 | 96 | SHA-2 family |
| SHA3-256 | 64 | SHA-3 family |
| SHA3-512 | 128 | SHA-3 family |
| NTLM | 32 | Windows passwords |
| bcrypt | variable | Salted, strong |
| BLAKE2s/b | 64/128 | Modern, fast |
| RIPEMD-160 | 40 | Bitcoin |

---

## 💡 Tips CTF

```bash
# Dapat hash di CTF? Langsung coba:
python hashcrack.py -i <hash> --mini

# Kalau tidak ketemu, pakai rockyou:
python hashcrack.py -i <hash> -w /usr/share/wordlists/rockyou.txt

# Generate hash untuk verifikasi jawaban:
python hashcrack.py -g "flag{ctf_answer}"
```

---

## ⚠️ Disclaimer

HashCrack dibuat untuk **keperluan CTF, forensics, dan edukasi keamanan siber**. Gunakan hanya pada sistem yang kamu miliki atau punya izin eksplisit. Penulis tidak bertanggung jawab atas penyalahgunaan tool ini.

---

## 🛠️ Related Tools

- [SubSleuth](https://github.com/AhanDotID/subsleuth) - Subdomain finder
- [DirHunt](https://github.com/AhanDotID/dirhunt) - Directory bruteforcer

---

Made with ❤️ by Ahan Pahlevi | CianjurSec

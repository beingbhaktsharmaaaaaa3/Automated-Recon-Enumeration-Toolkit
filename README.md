# 🔍 Recon & Enumeration Toolkit

> Automated recon and enumeration framework for pentesting engagements.  
> Runs DNS enumeration, port scanning, subdomain brute-force, web fingerprinting, WHOIS lookup, and banner grabbing — all in one command.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)

---

## ⚠️ Legal Disclaimer

> **This tool is for authorized penetration testing and security research only.**  
> You are responsible for ensuring you have explicit written permission before running this tool against any target.  
> The authors accept no liability for unauthorized or illegal use.

---

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
  - [Standard install](#standard-install)
  - [Using a virtual environment (recommended)](#using-a-virtual-environment-recommended)
  - [Installing nmap (optional)](#installing-nmap-optional)
- [Usage](#-usage)
  - [Basic examples](#basic-examples)
  - [All flags](#all-flags)
- [Modules](#-modules)
- [Output & Reports](#-output--reports)
- [Recommended Wordlists](#-recommended-wordlists)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

| Module | What it does |
|--------|-------------|
| **DNS enumeration** | Queries A, AAAA, MX, NS, TXT, CNAME, SOA records. Attempts AXFR zone transfer against each nameserver. |
| **Port scanner** | Multi-threaded socket-based scanner with optional nmap integration (`-sV -sC --open -T4`). |
| **Subdomain brute-force** | Concurrent subdomain enumeration against a built-in or custom wordlist. |
| **Web fingerprinting** | Detects CMS, frameworks, CDN, server software. Audits security headers and cookie flags. |
| **WHOIS lookup** | Registrar, org, creation/expiry dates, emails, ASN. Falls back to raw socket if library unavailable. |
| **Banner grabbing** | Service-specific probes on open ports (FTP, SSH, SMTP, Redis, HTTP, etc.) to pull version strings. |
| **Report generator** | Saves structured JSON + human-readable TXT report after every scan. |

- Accepts **hostnames, IP addresses, or full URLs** as target
- All modules **degrade gracefully** — missing optional libraries skip that feature without crashing
- Rich colour terminal output (falls back to plain text if `rich` is not installed)
- Fully threaded — scan speed controlled via `--threads`

---

## 🧰 Requirements

### Python

Python **3.8 or higher** is required.

```bash
python3 --version
```

### Python packages

| Package | Role | Required? |
|---------|------|-----------|
| `dnspython` | DNS record queries and zone transfer | Recommended |
| `requests` | HTTP fingerprinting | Recommended |
| `python-whois` | WHOIS lookups | Optional (socket fallback exists) |
| `rich` | Colour terminal output and tables | Optional (plain text fallback exists) |

### System tools

| Tool | Role | Required? |
|------|------|-----------|
| `nmap` | Enhanced port scanning via `--nmap` flag | Optional |

---

## 🚀 Installation

### Standard install

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/recon-toolkit.git
cd recon-toolkit

# 2. Install Python dependencies
pip install dnspython requests python-whois rich
```

---

### Using a virtual environment (recommended)

Using a virtual environment keeps the toolkit's dependencies isolated from your system Python. This is the best approach and also fixes most installation errors.

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/recon-toolkit.git
cd recon-toolkit

# 2. Create a virtual environment
python3 -m venv venv

# 3. Activate it
#    On Linux / macOS:
source venv/bin/activate

#    On Windows (Command Prompt):
venv\Scripts\activate.bat

#    On Windows (PowerShell):
venv\Scripts\Activate.ps1

# 4. Install dependencies inside the venv
pip install dnspython requests python-whois rich

# 5. Run the tool
python3 recon_toolkit.py -t example.com

# 6. When you're done, deactivate the venv
deactivate
```

> **Tip:** Next time you come back, just `cd recon-toolkit` and re-run step 3 (activate) before using the tool.

---

### Installing nmap (optional)

nmap is only needed if you pass the `--nmap` flag. Without it, the built-in socket scanner is used automatically.

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install nmap

# Fedora / RHEL
sudo dnf install nmap

# macOS (Homebrew)
brew install nmap

# Windows
# Download the installer from https://nmap.org/download.html
```

---

## 🖥️ Usage

### Basic examples

```bash
# Full scan against a domain — runs all 6 modules
python3 recon_toolkit.py -t example.com

# Full scan with custom output path
python3 recon_toolkit.py -t example.com -o ./reports/engagement1

# Scan an IP address (ports, banners, web, whois)
python3 recon_toolkit.py -t 192.168.1.100 --modules ports banners web whois

# DNS and subdomain recon only
python3 recon_toolkit.py -t example.com --modules dns subs

# Fast full-port scan with nmap
python3 recon_toolkit.py -t example.com --modules ports --ports 1-65535 --nmap

# Web fingerprinting only, custom threads and timeout
python3 recon_toolkit.py -t example.com --modules web --threads 50 --timeout 5.0

# Subdomain brute-force with a custom wordlist
python3 recon_toolkit.py -t example.com --modules subs \
  --wordlist /path/to/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Pass a full URL — scheme and path are stripped automatically
python3 recon_toolkit.py -t https://example.com/some/path
```

---

### All flags

```
usage: recon_toolkit.py [-h] -t TARGET
                        [--modules {dns,ports,subs,web,whois,banners} ...]
                        [--ports PORTS] [--nmap]
                        [--wordlist WORDLIST]
                        [--threads THREADS] [--timeout TIMEOUT]
                        [-o OUTPUT] [--json-only] [--no-banner] [-v]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-t / --target` | — | **Required.** Hostname, IP address, or URL |
| `--modules` | all | Space-separated list of modules to run: `dns` `ports` `subs` `web` `whois` `banners` |
| `--ports` | top 30 | Port range `1-1024` or comma-separated list `80,443,8080` |
| `--nmap` | off | Use nmap instead of the socket scanner (requires nmap installed) |
| `--wordlist` | built-in | Path to a custom subdomain wordlist file |
| `--threads` | `100` | Number of concurrent threads for port and subdomain scanning |
| `--timeout` | `1.5` | Socket timeout in seconds — increase for slow/remote targets |
| `-o / --output` | auto | Base path for output files. Creates `<base>.json` and `<base>.txt` |
| `--json-only` | off | Save only the JSON report, skip the text report |
| `--no-banner` | off | Suppress the ASCII art banner (useful for scripted/CI use) |
| `-v / --verbose` | off | Verbose logging |

---

## 🔬 Modules

### DNS enumeration (`dns`)

Queries all standard record types and attempts a zone transfer against every nameserver discovered.

```bash
python3 recon_toolkit.py -t example.com --modules dns
```

Records queried: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`

A successful zone transfer (AXFR) is a critical finding — it exposes the full internal DNS structure of the target.

---

### Port scanner (`ports`)

Two modes:

- **Socket mode (default):** Pure Python, no dependencies, highly threaded.
- **nmap mode (`--nmap`):** Delegates to nmap with service/version detection (`-sV -sC --open -T4`).

```bash
# Socket scan — top ports
python3 recon_toolkit.py -t 10.0.0.1 --modules ports

# Socket scan — full port range, 500 threads
python3 recon_toolkit.py -t 10.0.0.1 --modules ports --ports 1-65535 --threads 500

# nmap scan — common ports
python3 recon_toolkit.py -t example.com --modules ports --nmap
```

Open ports are automatically passed to the banner grabber and web fingerprinter when those modules are also active.

---

### Subdomain brute-force (`subs`)

Resolves `<word>.<target>` for each entry in the wordlist concurrently. Falls back to a built-in 80-word list if no custom list is provided.

```bash
python3 recon_toolkit.py -t example.com --modules subs \
  --wordlist ./wordlists/subdomains.txt \
  --threads 100
```

For serious coverage, pair with a large wordlist from [SecLists](https://github.com/danielmiessler/SecLists).

---

### Web fingerprinting (`web`)

Sends HTTP/HTTPS requests to detected web ports and identifies:

- **Technology stack** — WordPress, Drupal, Laravel, Django, React, Angular, Vue, Spring Boot, Tomcat, and more
- **Server software** — Nginx, Apache, IIS, Cloudflare, AWS ELB
- **Security headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Information leakage** — `Server`, `X-Powered-By`, `X-Generator`, `X-AspNet-Version`
- **Cookie flags** — missing `Secure` and `HttpOnly` attributes

```bash
python3 recon_toolkit.py -t example.com --modules web
```

---

### WHOIS lookup (`whois`)

```bash
python3 recon_toolkit.py -t example.com --modules whois
```

Returns registrar, org, creation date, expiry date, name servers, emails, country, and DNSSEC status. Works on both domains and IP addresses (IP WHOIS returns ASN, CIDR block, ISP).

---

### Banner grabbing (`banners`)

Sends protocol-specific probes to open ports and reads the response to extract version strings.

```bash
python3 recon_toolkit.py -t example.com --modules ports banners
```

Probes included for: FTP, SSH, SMTP, HTTP, POP3, IMAP, MySQL, PostgreSQL, Redis, and generic TCP.

---

## 📄 Output & Reports

Every scan automatically saves two files.

**JSON report** — machine-parseable, good for piping into other tools:
```
recon_example_com_20240510_143022.json
```

**Text report** — human-readable, good for client handoff:
```
recon_example_com_20240510_143022.txt
```

Specify a custom base path with `-o`:

```bash
python3 recon_toolkit.py -t example.com -o ./reports/client_acme
# produces: ./reports/client_acme.json
#           ./reports/client_acme.txt
```

To save JSON only:

```bash
python3 recon_toolkit.py -t example.com -o ./reports/client_acme --json-only
```

---

## 📚 Recommended Wordlists

The built-in subdomain wordlist has 80 common entries — enough for a quick check. For thorough engagements, use [SecLists](https://github.com/danielmiessler/SecLists):

```bash
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
```

Then pass the wordlist:

```bash
# Fast — 5,000 entries
python3 recon_toolkit.py -t example.com --modules subs \
  --wordlist /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Thorough — 20,000 entries
python3 recon_toolkit.py -t example.com --modules subs \
  --wordlist /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
```

---

## 🛠️ Troubleshooting

### `ModuleNotFoundError: No module named 'dns'`

dnspython is not installed. Fix:

```bash
pip install dnspython
```

If that still doesn't work, your `pip` may be pointing to a different Python than `python3`. Try:

```bash
python3 -m pip install dnspython
```

---

### `pip: command not found`

```bash
# Linux / macOS
sudo apt install python3-pip      # Debian/Ubuntu
brew install python3              # macOS (includes pip)

# Or bootstrap pip manually
python3 -m ensurepip --upgrade
```

---

### Packages install but the tool still can't find them

This usually means you have multiple Python environments. **Use a virtual environment** (see [installation guide above](#using-a-virtual-environment-recommended)) — it guarantees the tool runs with exactly the packages you installed.

---

### `Permission denied` when running the script

Make the script executable:

```bash
chmod +x recon_toolkit.py
./recon_toolkit.py -t example.com
```

Or always run it explicitly with:

```bash
python3 recon_toolkit.py -t example.com
```

---

### nmap not found even after installing

Make sure nmap is in your PATH:

```bash
which nmap        # should return a path
nmap --version    # should print version info
```

If it's installed but not in PATH (common on Windows), add its directory to your system PATH environment variable, or provide the full path in a wrapper script.

---

### Scan is very slow

- Increase `--threads` (e.g. `--threads 300`)
- Increase `--timeout` if the target is on a slow/remote network (e.g. `--timeout 3.0`)
- Narrow the port range with `--ports` instead of scanning all 65535

---

### SSL certificate errors on web fingerprinting

The toolkit already disables SSL verification for self-signed certificates. If you still see SSL-related crashes, ensure `requests` and `urllib3` are up to date:

```bash
pip install --upgrade requests urllib3
```

---

### `OSError: [Errno 24] Too many open files`

You've hit the OS file descriptor limit. Lower the thread count:

```bash
python3 recon_toolkit.py -t example.com --threads 50
```

Or raise the system limit temporarily:

```bash
ulimit -n 4096
```

---

### Windows-specific: `venv\Scripts\Activate.ps1 cannot be loaded`

PowerShell's execution policy is blocking the activation script. Fix:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
venv\Scripts\Activate.ps1
```

---

## 🤝 Contributing

Contributions are welcome! If you have a module idea, bug fix, or improvement:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-module`
3. Commit your changes: `git commit -m "Add HTTP directory brute-force module"`
4. Push the branch: `git push origin feature/my-module`
5. Open a Pull Request

**Ideas for new modules:**
- HTTP directory/file brute-force
- CVE lookup from banner version strings
- Screenshot capture of discovered web pages
- CIDR range scanning
- SMTP user enumeration
- SMB enumeration

---

## 📜 License

This project is licensed under the MIT License.

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

*Built for security professionals. Use responsibly.*

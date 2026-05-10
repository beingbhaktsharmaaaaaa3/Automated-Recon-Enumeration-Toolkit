# 🔍 Recon & Enumeration Toolkit v2.0

> A modular, automated recon and enumeration framework built for professional pentesting engagements.
> Runs DNS enumeration, port scanning (TCP + UDP), subdomain brute-force, passive recon, web fingerprinting, SSL/TLS analysis, WHOIS lookup, banner grabbing with CVE hints, and generates JSON + TXT + HTML reports — all from a single command.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)
![Version](https://img.shields.io/badge/Version-2.0-purple?style=flat-square)

---

## ⚠️ Legal Disclaimer

> **This tool is for authorized penetration testing and security research only.**
> Running this tool against systems you do not have explicit written permission to test is illegal.
> The authors accept no liability for unauthorized or illegal use.
> The tool prints this warning on every launch.

---

## 📋 Table of Contents

- [What's New in v2.0](#-whats-new-in-v20)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [All Flags](#-all-flags)
- [Modules](#-modules)
- [Stealth Mode](#-stealth-mode)
- [Passive Recon](#-passive-recon)
- [Resume / Checkpoint](#-resume--checkpoint)
- [Config File](#-config-file)
- [Output & Reports](#-output--reports)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🆕 What's New in v2.0

| Feature | Details |
|---------|---------|
| **Stealth mode** | `--stealth` reduces threads to ≤20 and adds randomized jitter between probes |
| **UDP scanning** | `--udp` scans common UDP ports: DNS, SNMP, NTP, DHCP, IKE, mDNS, and more |
| **Passive recon** | `--passive` queries crt.sh and Wayback Machine CDX API before brute-forcing |
| **SSL/TLS analysis** | Checks TLS version, cipher strength, certificate expiry, SANs, weak ciphers |
| **CVE hint matching** | Banner grabber matches 25+ known vulnerable version strings to CVE IDs |
| **HTML report** | Dark-theme HTML report with stats grid, CVE table, endpoint breakdown |
| **Resume / checkpoint** | `--resume` continues an interrupted scan from where it stopped |
| **Config file** | `--config config.yaml` — set defaults without typing flags every time |
| **File logging** | `--logfile` writes a full timestamped log to disk |
| **Cookie fix** | Cookie security check now correctly reads `cookie.secure` attributes |
| **Non-standard port detection** | Probes services to identify HTTP/SSH/Redis on unexpected ports |
| **Workflow chaining** | Subdomains auto-fed into web fingerprinter; ports auto-fed into banner grabber |
| **Multi-file architecture** | Split into `core/`, `modules/`, `reports/`, `utils/` |

---

## ✨ Features

| Module | What it does |
|--------|-------------|
| **DNS enumeration** | A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA · PTR/reverse DNS · DNSSEC · AXFR zone transfer |
| **Port scanner** | Multi-threaded TCP + UDP · socket or nmap · stealth mode · non-standard port detection |
| **Subdomain brute-force** | Concurrent wordlist + passive crt.sh + Wayback Machine |
| **Web fingerprinting** | 25+ tech signatures · security headers · SSL/TLS · cookie flags · robots.txt · sitemap |
| **WHOIS lookup** | Registrar · org · dates · emails · ASN · two-stage socket fallback |
| **Banner grabbing** | Service-specific probes · CVE hint matching on 25+ vulnerable version strings |
| **Report generator** | JSON · TXT · dark-theme HTML |

---

## 📁 Project Structure

```
recon_v2/
├── main.py                  ← CLI entry point, orchestrator, workflow chaining
├── config.yaml              ← Default config file (edit and reuse)
├── requirements.txt         ← Python dependencies
│
├── core/
│   ├── __init__.py
│   └── logger.py            ← Rich terminal output + file logging
│
├── modules/
│   ├── __init__.py
│   ├── dns_enum.py          ← DNS records, PTR, DNSSEC, zone transfer
│   ├── port_scanner.py      ← TCP + UDP, stealth mode, nmap wrapper
│   ├── subdomain.py         ← Brute-force + passive (crt.sh, Wayback)
│   ├── web_fingerprint.py   ← Tech detection, SSL/TLS, headers, cookies
│   ├── whois_lookup.py      ← WHOIS with two-stage socket fallback
│   └── banner_grab.py       ← Service probes + CVE hint matching
│
├── reports/
│   ├── __init__.py
│   └── generator.py         ← JSON, TXT, HTML report generator
│
└── utils/
    ├── __init__.py
    └── validators.py        ← Input validation (ports, threads, targets)
```

---

## 🧰 Requirements

**Python 3.8 or higher required.**

```bash
python3 --version
```

### Python packages

| Package | Role | Required? |
|---------|------|-----------|
| `dnspython` | DNS records, zone transfer, PTR lookup | Recommended |
| `requests` | HTTP fingerprinting, passive recon | Recommended |
| `python-whois` | WHOIS lookups | Optional (socket fallback built-in) |
| `rich` | Colour output and tables | Optional (plain text fallback built-in) |
| `pyyaml` | Config file support | Optional |

### System tools

| Tool | Role | Required? |
|------|------|-----------|
| `nmap` | Enhanced port scanning via `--nmap` | Optional |

---

## 🚀 Installation

### Option 1 — Standard install

```bash
git clone https://github.com/yourusername/recon-toolkit.git
cd recon_v2
pip install -r requirements.txt
python3 main.py -t example.com or http://<ip_add> or http://www.website.com
```

---

### Option 2 — Virtual environment (recommended)

Using a venv isolates dependencies and prevents version conflicts. It also fixes most import errors.

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/recon-toolkit.git
cd recon_v2

# 2. Create the virtual environment
python3 -m venv venv

# 3. Activate it
#    Linux / macOS:
source venv/bin/activate

#    Windows Command Prompt:
venv\Scripts\activate.bat

#    Windows PowerShell:
venv\Scripts\Activate.ps1

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run the tool
python3 main.py -t http://example.com

# 6. Deactivate when done
deactivate
```

> **Tip:** Every time you return, just activate the venv (step 3) before running the tool.

---

### Installing nmap (optional)

Only needed with `--nmap`.

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install nmap

# Fedora / RHEL
sudo dnf install nmap

# macOS
brew install nmap

# Windows — installer at https://nmap.org/download.html
```

---

## 🖥️ Usage

```bash
# Full scan — all modules, all 3 report formats
python3 main.py -t http://example.com

# Full scan with custom output path
python3 main.py -t example.com -o ./reports/client_acme

# Scan an IP address
python3 main.py -t 192.168.1.100 --modules ports banners web whois

# Pass a full URL — scheme and path stripped automatically
python3 main.py -t https://example.com/some/path

# DNS and subdomain recon only
python3 main.py -t example.com --modules dns subs

# Full port range with nmap + UDP
python3 main.py -t example.com --ports 1-65535 --nmap --udp

# Stealth scan with random delays
python3 main.py -t example.com --stealth --random-delay

# Passive subdomain recon + large wordlist
python3 main.py -t example.com --passive \
  --wordlist /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Use a config file
python3 main.py --config config.yaml

# Resume an interrupted scan
python3 main.py -t example.com --resume recon_example_com_20240510_state.json

# Write log to file
python3 main.py -t example.com --logfile ./logs/scan.log
```

---

## 🚩 All Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t / --target` | — | Hostname, IP, or URL |
| `--config` | — | Path to YAML config file |
| `--modules` | all | Space-separated: `dns` `ports` `subs` `web` `whois` `banners` |
| `--ports` | top 30 | Range `1-1024` or list `80,443,8080` |
| `--nmap` | off | Use nmap with service detection |
| `--udp` | off | Also scan common UDP ports |
| `--wordlist` | built-in | Path to subdomain wordlist |
| `--passive` | off | Passive recon via crt.sh and Wayback Machine |
| `--stealth` | off | ≤20 threads + randomized jitter |
| `--delay` | `0.0` | Fixed delay in seconds between probes |
| `--random-delay` | off | Random delay 0.1–1.5s per probe |
| `--threads` | `100` | Concurrent threads (max 1000) |
| `--timeout` | `1.5` | Socket timeout in seconds |
| `-o / --output` | auto | Base path for output files |
| `--json-only` | off | Save JSON report only |
| `--logfile` | — | Write log to this file |
| `--no-banner` | off | Suppress ASCII banner |
| `--resume` | — | Resume from a `_state.json` checkpoint |

---

## 🔬 Modules

### `dns` — DNS Enumeration

Queries `A` `AAAA` `MX` `NS` `TXT` `CNAME` `SOA` `SRV` `CAA` `DNSKEY` `DS`, performs PTR reverse lookup, checks DNSSEC, and attempts AXFR zone transfer against each nameserver.

```bash
python3 main.py -t example.com --modules dns
```

---

### `ports` — Port Scanner

Socket-based TCP scanner with optional nmap integration. Includes non-standard port service detection — probes open ports for HTTP, SSH, Redis, FTP regardless of port number. Supports UDP scanning with service-specific probes (DNS, SNMP, NTP).

```bash
python3 main.py -t example.com --modules ports --ports 1-65535 --nmap --udp
```

---

### `subs` — Subdomain Enumeration

Phase 1 (optional, `--passive`): queries crt.sh and Wayback Machine — no direct target contact.
Phase 2: concurrent DNS resolution of wordlist entries. Results merged and deduplicated.
Top discovered subdomains are automatically chained into the web fingerprinter.

```bash
python3 main.py -t example.com --passive --modules subs \
  --wordlist /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

### `web` — Web Fingerprinting

Detects 25+ technologies, audits 8 security headers, checks SSL/TLS (version, cipher, expiry, SANs), reads cookie attributes correctly, fetches and parses robots.txt and sitemap.xml, and flags information-leaking headers.

```bash
python3 main.py -t example.com --modules web
```

---

### `whois` — WHOIS Lookup

Returns registrar, org, dates, emails, ASN. Works on domains and IPs. Two-stage socket fallback (IANA → authoritative server) if python-whois is not installed.

---

### `banners` — Banner Grabbing + CVE Hints

Sends service-specific probes to open ports. Matches response strings against 25+ known vulnerable versions and maps them to CVE IDs including OpenSSH, Apache, Nginx, IIS, vsftpd, MySQL, Redis, OpenSSL (Heartbleed), Drupal, WordPress, and more.

```bash
python3 main.py -t example.com --modules ports banners
```

---

## 🥷 Stealth Mode

```bash
# Auto stealth — ≤20 threads, randomized 0.3–1.0s jitter, randomized port order
python3 main.py -t example.com --stealth

# Manual fixed delay
python3 main.py -t example.com --delay 0.5

# Manual random delay
python3 main.py -t example.com --random-delay

# Combine for maximum stealth
python3 main.py -t example.com --stealth --random-delay --delay 0.3
```

---

## 🕵️ Passive Recon

`--passive` queries external APIs — no direct probes sent to the target.

```bash
python3 main.py -t example.com --passive --modules subs
```

Sources queried:
- **crt.sh** — finds subdomains from TLS certificate transparency logs
- **Wayback Machine CDX API** — finds historical subdomains from archived URLs

---

## ♻️ Resume / Checkpoint

A checkpoint file (`_state.json`) is saved after every module. Resume interrupted scans:

```bash
python3 main.py -t example.com --resume recon_example_com_TIMESTAMP_state.json
```

The checkpoint is automatically deleted after a successful full scan.

---

## ⚙️ Config File

Edit `config.yaml` for persistent defaults:

```yaml
modules: [dns, ports, subs, web, whois, banners]
threads: 150
timeout: 2.0
stealth: false
passive: false
scan_udp: false
wordlist: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
logfile: ./logs/recon.log
```

```bash
python3 main.py --config config.yaml -t example.com
```

CLI flags always override the config file.

---

## 📄 Output & Reports

| File | Use for |
|------|---------|
| `<base>.json` | Scripting, piping into other tools |
| `<base>.txt` | Quick review, archiving |
| `<base>.html` | Client handoff, browser viewing |

```bash
# Custom path
python3 main.py -t example.com -o ./reports/client
# → ./reports/client.json  ./reports/client.txt  ./reports/client.html

# JSON only
python3 main.py -t example.com --json-only
```

---

## 🛠️ Troubleshooting

### `ModuleNotFoundError: No module named 'dns'`
```bash
pip install dnspython
# or: python3 -m pip install dnspython
```

### Packages install but tool still can't find them
Multiple Python environments conflict. Use a **virtual environment** — see [Installation](#-installation).

### `pip: command not found`
```bash
sudo apt install python3-pip        # Debian/Ubuntu
python3 -m ensurepip --upgrade      # any platform
```

### `Permission denied` running the script
```bash
chmod +x main.py
# or always use: python3 main.py
```

### Windows PowerShell blocks venv activation
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
venv\Scripts\Activate.ps1
```

### Scan is too slow
```bash
python3 main.py -t example.com --threads 300 --ports 1-1024
```

### `OSError: [Errno 24] Too many open files`
```bash
python3 main.py -t example.com --threads 50
# or: ulimit -n 4096
```

### `--config` flag does nothing
```bash
pip install pyyaml
```

### SSL errors in web fingerprinting
```bash
pip install --upgrade requests urllib3
```

### Checkpoint file missing after interruption
```bash
ls recon_*_state.json    # find it in current directory
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Commit: `git commit -m "Add HTTP directory brute-force module"`
4. Push: `git push origin feature/my-improvement`
5. Open a Pull Request

**Ideas for future modules:**
- HTTP directory / file brute-force
- Screenshot capture (Playwright)
- asyncio rewrite for higher throughput
- Favicon hashing for tech detection
- SMB / SMTP enumeration
- Full CVE database integration (NVD API)
- Shodan / Censys API integration

---

## 📜 License

MIT License — free to use, modify, and distribute with attribution.

---

*Built for security professionals. Use responsibly and legally.*

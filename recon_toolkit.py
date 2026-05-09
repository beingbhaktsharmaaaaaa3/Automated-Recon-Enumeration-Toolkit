#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║           RECON & ENUMERATION TOOLKIT v1.0                ║
║        Automated Pentesting Recon Framework               ║
║  Usage: python3 recon_toolkit.py -t <target> [options]    ║
╚═══════════════════════════════════════════════════════════╝

Modules:
  [1] DNS Enumeration       - A/MX/NS/TXT/CNAME + zone transfer
  [2] Port Scanner          - Socket-based + nmap wrapper
  [3] Subdomain Brute-Force - Wordlist-based enumeration
  [4] Web Fingerprinting    - Headers, CMS, tech stack
  [5] WHOIS Lookup          - Registrar, org, dates
  [6] Banner Grabbing       - Service identification
  [7] Report Generator      - JSON + text output

Requirements:
  pip install dnspython requests python-whois rich

Optional (recommended):
  apt install nmap  (or brew install nmap)
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

# ── External dependencies (graceful degradation if missing) ──────────────────
try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    class _FallbackConsole:
        def print(self, *args, **kwargs): print(*args)
        def rule(self, title=""): print(f"\n{'─'*60} {title} {'─'*60}\n")
    console = _FallbackConsole()

# ── Embedded Subdomain Wordlist ───────────────────────────────────────────────
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "ns", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
    "test", "ns3", "vpn", "mail2", "new", "mysql", "old", "lists", "support",
    "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure", "demo",
    "cp", "calendar", "wiki", "web", "media", "email", "images", "img", "www2",
    "intranet", "admin", "portal", "video", "sip", "dns", "dns2", "dev",
    "staging", "api", "v1", "v2", "cdn", "assets", "upload", "remote",
    "blog", "forum", "store", "download", "app", "apps", "cloud", "help",
    "status", "monitor", "proxy", "backup", "db", "database", "gateway",
    "internal", "jenkins", "gitlab", "git", "jira", "confluence", "kibana",
    "grafana", "prometheus", "vault", "k8s", "kubernetes", "docker",
    "ci", "cd", "build", "deploy", "prod", "production", "uat", "qa",
    "sandbox", "preprod", "stage", "edge", "origin", "s3", "files",
    "mx1", "mx2", "smtp2", "relay", "exchange", "owa",
]

# ── Common Ports ──────────────────────────────────────────────────────────────
TOP_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 27017: "MongoDB", 6379: "Redis",
    5432: "PostgreSQL", 1433: "MSSQL", 2049: "NFS", 4444: "Metasploit",
    5000: "Flask/UPnP", 8000: "HTTP-Dev", 9200: "Elasticsearch",
    9300: "Elasticsearch-cluster", 2181: "Zookeeper", 6443: "K8s API",
}

# ── Web Technology Fingerprints ───────────────────────────────────────────────
TECH_SIGNATURES = {
    "WordPress":    {"headers": [], "body": ["wp-content", "wp-includes", "wordpress"]},
    "Drupal":       {"headers": ["X-Generator: Drupal"], "body": ["Drupal.settings", "/sites/default/"]},
    "Joomla":       {"headers": [], "body": ["/media/jui/", "Joomla!"]},
    "Laravel":      {"headers": ["laravel_session"], "body": ["laravel", "csrf-token"]},
    "Django":       {"headers": [], "body": ["csrfmiddlewaretoken", "__admin"]},
    "React":        {"headers": [], "body": ["react.development.js", "react.production.min.js", "_react"]},
    "Angular":      {"headers": [], "body": ["ng-version", "angular.min.js"]},
    "Vue.js":       {"headers": [], "body": ["vue.min.js", "vue.js", "__vue__"]},
    "jQuery":       {"headers": [], "body": ["jquery.min.js", "jquery-"]},
    "Bootstrap":    {"headers": [], "body": ["bootstrap.min.css", "bootstrap.css"]},
    "Nginx":        {"headers": ["Server: nginx"], "body": []},
    "Apache":       {"headers": ["Server: Apache"], "body": []},
    "IIS":          {"headers": ["Server: Microsoft-IIS"], "body": []},
    "Cloudflare":   {"headers": ["CF-RAY", "cf-cache-status"], "body": []},
    "AWS ELB":      {"headers": ["x-amzn-requestid", "x-amz-cf-id"], "body": []},
    "PHP":          {"headers": ["X-Powered-By: PHP"], "body": []},
    "ASP.NET":      {"headers": ["X-Powered-By: ASP.NET", "X-AspNet-Version"], "body": ["__VIEWSTATE"]},
    "Tomcat":       {"headers": ["Server: Apache-Coyote"], "body": ["Apache Tomcat"]},
    "Spring Boot":  {"headers": [], "body": ["spring", "Whitelabel Error Page"]},
}

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "bold white",
    "OK":       "bold green",
}


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner():
    if RICH_AVAILABLE:
        banner = Text()
        banner.append("  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗\n", style="bold red")
        banner.append("  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║\n", style="bold red")
        banner.append("  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║\n", style="bold yellow")
        banner.append("  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║\n", style="bold yellow")
        banner.append("  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║\n", style="bold green")
        banner.append("  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝\n", style="bold green")
        banner.append("  Recon & Enumeration Toolkit v1.0  |  Pentesting Edition\n", style="dim white")
        console.print(Panel(banner, border_style="bold blue", padding=(0, 2)))
    else:
        print("\n" + "="*60)
        print("  RECON & ENUMERATION TOOLKIT v1.0")
        print("="*60 + "\n")


def log(level: str, msg: str):
    icons = {"INFO": "[*]", "OK": "[+]", "WARN": "[!]", "ERROR": "[-]", "FIND": "[>>]"}
    icon = icons.get(level, "[?]")
    if RICH_AVAILABLE:
        colors = {"INFO": "cyan", "OK": "green", "WARN": "yellow", "ERROR": "red", "FIND": "bold magenta"}
        console.print(f"  {icon} {msg}", style=colors.get(level, "white"))
    else:
        print(f"  {icon} {msg}")


def section(title: str):
    if RICH_AVAILABLE:
        console.rule(f"[bold blue] {title} [/bold blue]")
    else:
        print(f"\n{'─'*20} {title} {'─'*20}")


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 1 – DNS ENUMERATION 
# ═══════════════════════════════════════════════════════════════════════════════

class DNSEnumerator:
    def __init__(self, target: str):
        self.target = target
        self.results = {}

    def run(self) -> dict:
        section("DNS Enumeration")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        if not DNS_AVAILABLE:
            log("WARN", "dnspython not installed — using socket fallback (A records only)")
            try:
                ip = socket.gethostbyname(self.target)
                self.results["A"] = [ip]
                log("FIND", f"A  →  {ip}")
            except socket.gaierror as e:
                log("ERROR", f"DNS resolution failed: {e}")
            return self.results

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in record_types:
            try:
                answers = resolver.resolve(self.target, rtype)
                records = [str(r) for r in answers]
                self.results[rtype] = records
                for r in records:
                    log("FIND", f"{rtype:<6} →  {r}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout,
                    dns.resolver.NoNameservers):
                pass
            except Exception as e:
                log("WARN", f"{rtype} lookup error: {e}")

        # Zone transfer attempt
        self._zone_transfer()
        return self.results

    def _zone_transfer(self):
        if not DNS_AVAILABLE:
            return
        log("INFO", "Attempting zone transfer (AXFR)…")
        try:
            ns_records = self.results.get("NS", [])
            for ns in ns_records:
                ns_host = str(ns).rstrip(".")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_host, self.target, timeout=5))
                    log("FIND", f"[CRITICAL] Zone transfer SUCCESS on {ns_host}!")
                    self.results["ZONE_TRANSFER"] = {
                        "ns": ns_host,
                        "records": [str(n) for n in zone.nodes.keys()]
                    }
                    for name in zone.nodes.keys():
                        log("FIND", f"  ZT Record: {name}.{self.target}")
                except Exception:
                    log("OK", f"Zone transfer refused by {ns_host} (expected)")
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 2 – PORT SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

class PortScanner:
    def __init__(self, target: str, ports: Optional[list] = None,
                 threads: int = 100, timeout: float = 1.0, use_nmap: bool = False):
        self.target = target
        self.ports = ports or list(TOP_PORTS.keys())
        self.threads = threads
        self.timeout = timeout
        self.use_nmap = use_nmap
        self.results = {"open": {}, "nmap": None}

    def run(self) -> dict:
        section("Port Scanning")
        try:
            self.ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            self.ip = self.target
        log("INFO", f"Scanning {self.target} ({self.ip}) — {len(self.ports)} ports | threads={self.threads}")

        if self.use_nmap and self._nmap_available():
            self._run_nmap()
        else:
            self._run_socket_scan()

        return self.results

    def _scan_port(self, port: int) -> Optional[tuple]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))
            sock.close()
            if result == 0:
                return port
        except Exception:
            pass
        return None

    def _run_socket_scan(self):
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in self.ports}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    open_ports.append(res)

        for port in sorted(open_ports):
            svc = TOP_PORTS.get(port, "unknown")
            banner = self._grab_banner(port)
            self.results["open"][port] = {"service": svc, "banner": banner}
            banner_str = f"  [{banner}]" if banner else ""
            log("FIND", f"Port {port:<6} OPEN  ({svc}){banner_str}")

        if not open_ports:
            log("INFO", "No open ports found in scanned range")

    def _grab_banner(self, port: int, timeout: float = 2.0) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.ip, port))
            if port in (80, 8080, 8000, 8888):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass
            else:
                sock.sendall(b"\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner[:120].replace("\n", " ").replace("\r", "")
        except Exception:
            return ""

    def _nmap_available(self) -> bool:
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            log("WARN", "nmap not found — falling back to socket scanner")
            return False

    def _run_nmap(self):
        port_str = ",".join(str(p) for p in self.ports)
        cmd = ["nmap", "-sV", "-sC", "--open", "-T4", "-p", port_str, self.ip]
        log("INFO", f"Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout
            self.results["nmap"] = output
            # Parse open ports from nmap output
            for line in output.splitlines():
                m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
                if m:
                    port, svc, version = int(m.group(1)), m.group(2), m.group(3).strip()
                    self.results["open"][port] = {"service": svc, "banner": version}
                    log("FIND", f"Port {port:<6} OPEN  ({svc}) {version}")
        except subprocess.TimeoutExpired:
            log("ERROR", "nmap timed out")
        except Exception as e:
            log("ERROR", f"nmap error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 3 – SUBDOMAIN ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════

class SubdomainEnumerator:
    def __init__(self, target: str, wordlist: Optional[str] = None,
                 threads: int = 50, timeout: float = 3.0):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.results = []

        if wordlist and os.path.isfile(wordlist):
            with open(wordlist) as f:
                self.wordlist = [w.strip() for w in f if w.strip()]
            log("INFO", f"Loaded wordlist: {wordlist} ({len(self.wordlist)} words)")
        else:
            self.wordlist = SUBDOMAIN_WORDLIST
            if wordlist:
                log("WARN", f"Wordlist '{wordlist}' not found — using built-in ({len(self.wordlist)} words)")

    def run(self) -> list:
        section("Subdomain Enumeration")
        log("INFO", f"Brute-forcing {len(self.wordlist)} subdomains against {self.target}")

        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check, sub): sub for sub in self.wordlist}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    found.append(res)
                    log("FIND", f"Found: {res['subdomain']:<40} → {', '.join(res['ips'])}")

        self.results = sorted(found, key=lambda x: x["subdomain"])
        if not found:
            log("INFO", "No subdomains found with built-in wordlist")
        return self.results

    def _check(self, sub: str) -> Optional[dict]:
        fqdn = f"{sub}.{self.target}"
        try:
            ips = list({r[4][0] for r in socket.getaddrinfo(fqdn, None)})
            return {"subdomain": fqdn, "ips": ips}
        except socket.gaierror:
            return None


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 4 – WEB FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════════

class WebFingerprinter:
    def __init__(self, target: str, ports: Optional[list] = None):
        self.target = target
        self.ports = ports or [80, 443, 8080, 8443]
        self.results = {}

    def run(self) -> dict:
        section("Web Fingerprinting")
        if not REQUESTS_AVAILABLE:
            log("WARN", "requests not installed — skipping web fingerprinting")
            return self.results

        for port in self.ports:
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{self.target}:{port}"
            self._fingerprint(url)

        return self.results

    def _fingerprint(self, url: str):
        try:
            r = requests.get(url, timeout=8, verify=False, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 (Recon-Toolkit/1.0)"})
            log("OK", f"{url}  →  HTTP {r.status_code}  ({len(r.content)} bytes)")

            info = {
                "url": url,
                "status_code": r.status_code,
                "final_url": r.url,
                "headers": dict(r.headers),
                "technologies": [],
                "interesting_headers": {},
                "cookies": {},
                "title": "",
            }

            # Page title
            title_m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
            if title_m:
                info["title"] = title_m.group(1).strip()[:100]
                log("INFO", f"  Title: {info['title']}")

            # Technology detection
            detected = self._detect_tech(r)
            info["technologies"] = detected
            if detected:
                log("FIND", f"  Technologies: {', '.join(detected)}")

            # Security headers audit
            sec_headers = {
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy": "CSP",
                "X-Frame-Options": "Clickjacking protection",
                "X-Content-Type-Options": "MIME sniffing protection",
                "Referrer-Policy": "Referrer policy",
                "Permissions-Policy": "Permissions policy",
            }
            missing = []
            for hdr, label in sec_headers.items():
                if hdr in r.headers:
                    info["interesting_headers"][hdr] = r.headers[hdr]
                    log("OK", f"  {label}: {r.headers[hdr][:60]}")
                else:
                    missing.append(label)

            if missing:
                log("WARN", f"  Missing security headers: {', '.join(missing)}")
                info["missing_security_headers"] = missing

            # Interesting headers (info leak)
            leak_headers = ["X-Powered-By", "Server", "X-AspNet-Version",
                            "X-Generator", "X-Drupal-Cache", "X-Varnish"]
            for hdr in leak_headers:
                if hdr in r.headers:
                    log("FIND", f"  [Info-Leak] {hdr}: {r.headers[hdr]}")
                    info["interesting_headers"][hdr] = r.headers[hdr]

            # Cookies
            for name, val in r.cookies.items():
                flags = []
                if "secure" not in str(val).lower():
                    flags.append("no-Secure")
                if "httponly" not in str(val).lower():
                    flags.append("no-HttpOnly")
                info["cookies"][name] = {"value": str(val)[:40], "flags": flags}
                if flags:
                    log("WARN", f"  Cookie '{name}' missing: {', '.join(flags)}")

            self.results[url] = info

        except requests.exceptions.SSLError:
            log("WARN", f"{url}  →  SSL certificate error (self-signed?)")
        except requests.exceptions.ConnectionError:
            log("INFO", f"{url}  →  Connection refused / port closed")
        except requests.exceptions.Timeout:
            log("WARN", f"{url}  →  Request timed out")
        except Exception as e:
            log("ERROR", f"{url}  →  {e}")

    def _detect_tech(self, response) -> list:
        detected = []
        headers_str = " ".join(f"{k}: {v}" for k, v in response.headers.items())
        body = response.text[:50000]

        for tech, sigs in TECH_SIGNATURES.items():
            for hdr_sig in sigs["headers"]:
                if hdr_sig.lower() in headers_str.lower():
                    detected.append(tech)
                    break
            else:
                for body_sig in sigs["body"]:
                    if body_sig.lower() in body.lower():
                        detected.append(tech)
                        break

        return list(dict.fromkeys(detected))  # preserve order, deduplicate


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 5 – WHOIS LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

class WHOISLookup:
    def __init__(self, target: str):
        self.target = target
        self.results = {}

    def run(self) -> dict:
        section("WHOIS Lookup")
        if not WHOIS_AVAILABLE:
            log("WARN", "python-whois not installed — skipping WHOIS")
            self._socket_whois()
            return self.results

        try:
            w = whois.whois(self.target)
            fields = {
                "registrar":      w.registrar,
                "creation_date":  w.creation_date,
                "expiration_date":w.expiration_date,
                "updated_date":   w.updated_date,
                "name_servers":   w.name_servers,
                "org":            w.org,
                "country":        w.country,
                "emails":         w.emails,
                "dnssec":         w.dnssec,
            }
            for k, v in fields.items():
                if v:
                    val = str(v[0] if isinstance(v, list) else v)[:100]
                    self.results[k] = str(v)
                    log("INFO", f"  {k:<20} {val}")
        except Exception as e:
            log("WARN", f"WHOIS lookup failed: {e}")
            self._socket_whois()

        return self.results

    def _socket_whois(self):
        """Fallback raw WHOIS via socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(("whois.iana.org", 43))
            sock.sendall((self.target + "\r\n").encode())
            raw = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
            sock.close()
            text = raw.decode("utf-8", errors="ignore")
            self.results["raw"] = text[:2000]
            # Extract refer line to find the proper WHOIS server
            for line in text.splitlines():
                log("INFO", f"  {line}")
                if len(self.results.get("raw_lines", [])) < 30:
                    pass
        except Exception as e:
            log("ERROR", f"Socket WHOIS failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 6 – BANNER GRABBING (explicit service probes)
# ═══════════════════════════════════════════════════════════════════════════════

class BannerGrabber:
    PROBES = {
        21:  b"",
        22:  b"",
        25:  b"EHLO recon.test\r\n",
        80:  b"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n",
        110: b"",
        143: b"",
        443: None,  # skip raw TLS
        3306: b"",
        5432: b"",
        6379: b"PING\r\n",
        27017: None,
    }

    def __init__(self, target: str, open_ports: dict):
        self.target = target
        self.ip = socket.gethostbyname(target) if not self._is_ip(target) else target
        self.open_ports = open_ports
        self.results = {}

    def run(self) -> dict:
        section("Banner Grabbing")
        if not self.open_ports:
            log("INFO", "No open ports to grab banners from")
            return self.results

        for port in sorted(self.open_ports.keys()):
            probe = self.PROBES.get(port, b"\r\n")
            if probe is None:
                continue
            banner = self._grab(port, probe)
            if banner:
                self.results[port] = banner
                log("FIND", f"Port {port:<6}  →  {banner[:100]}")

        return self.results

    def _grab(self, port: int, probe: bytes, timeout: float = 3.0) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.ip, port))
            if probe:
                p = probe.replace(b"{target}", self.target.encode())
                sock.sendall(p)
            time.sleep(0.3)
            data = sock.recv(2048).decode("utf-8", errors="ignore").strip()
            sock.close()
            return data.replace("\n", " ").replace("\r", "")[:200]
        except Exception:
            return ""

    @staticmethod
    def _is_ip(s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 7 – REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    def __init__(self, target: str, scan_time: str, findings: dict):
        self.target = target
        self.scan_time = scan_time
        self.findings = findings

    def save_json(self, output_path: str):
        report = {
            "meta": {
                "toolkit": "Recon & Enumeration Toolkit v1.0",
                "target": self.target,
                "scan_time": self.scan_time,
                "generated": datetime.utcnow().isoformat() + "Z",
            },
            "findings": self.findings,
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        log("OK", f"JSON report saved → {output_path}")

    def save_text(self, output_path: str):
        lines = [
            "=" * 70,
            "  RECON & ENUMERATION TOOLKIT — ENGAGEMENT REPORT",
            "=" * 70,
            f"  Target     : {self.target}",
            f"  Scan Time  : {self.scan_time}",
            f"  Generated  : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            "=" * 70,
            "",
        ]

        for module, data in self.findings.items():
            lines.append(f"\n{'─'*70}")
            lines.append(f"  {module.upper()}")
            lines.append(f"{'─'*70}")
            lines.append(json.dumps(data, indent=2, default=str))

        lines.append("\n" + "=" * 70)
        lines.append("  END OF REPORT")
        lines.append("=" * 70)

        with open(output_path, "w") as f:
            f.write("\n".join(lines))
        log("OK", f"Text report saved → {output_path}")

    def print_summary(self):
        section("Engagement Summary")
        if RICH_AVAILABLE:
            table = Table(
                title=f"Recon Summary — {self.target}",
                box=box.ROUNDED,
                border_style="blue",
                header_style="bold cyan",
                show_lines=True,
            )
            table.add_column("Module", style="bold white", width=22)
            table.add_column("Findings", style="green", width=50)

            dns_data = self.findings.get("dns", {})
            table.add_row("DNS Records",
                ", ".join(dns_data.keys()) if dns_data else "None")

            ports_data = self.findings.get("ports", {}).get("open", {})
            port_list = ", ".join(f"{p}({v['service']})" for p, v in sorted(ports_data.items()))
            table.add_row("Open Ports", port_list[:80] or "None")

            subs = self.findings.get("subdomains", [])
            table.add_row("Subdomains", f"{len(subs)} found" + (
                f": {', '.join(s['subdomain'] for s in subs[:3])}" if subs else ""))

            web = self.findings.get("web", {})
            techs = []
            for url_data in web.values():
                techs.extend(url_data.get("technologies", []))
            table.add_row("Web Technologies", ", ".join(set(techs)) or "None detected")

            whois_d = self.findings.get("whois", {})
            table.add_row("WHOIS Registrar", str(whois_d.get("registrar", "N/A"))[:60])

            console.print(table)
        else:
            for module, data in self.findings.items():
                print(f"  {module}: {str(data)[:80]}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN CLI
# ═══════════════════════════════════════════════════════════════════════════════

def validate_target(target: str) -> str:
    """Strip scheme and path from target if a full URL was given."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.rstrip("/")


def parse_args():
    parser = argparse.ArgumentParser(
        prog="recon_toolkit.py",
        description="Automated Recon & Enumeration Toolkit for Pentesting Engagements",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon_toolkit.py -t example.com
  python3 recon_toolkit.py -t example.com --modules dns ports web
  python3 recon_toolkit.py -t example.com --ports 1-1024 --nmap --wordlist /path/to/subs.txt
  python3 recon_toolkit.py -t 192.168.1.1 --modules ports banners --threads 200
  python3 recon_toolkit.py -t example.com -o /tmp/report --all

Modules:
  dns        DNS record enumeration + zone transfer
  ports      Port scanning (socket or nmap)
  subs       Subdomain brute-force
  web        HTTP fingerprinting & header audit
  whois      WHOIS lookup
  banners    Service banner grabbing
        """
    )

    parser.add_argument("-t", "--target", required=True,
                        help="Target hostname or IP (e.g. example.com or 10.0.0.1)")
    parser.add_argument("--modules", nargs="+",
                        choices=["dns", "ports", "subs", "web", "whois", "banners"],
                        default=["dns", "ports", "subs", "web", "whois", "banners"],
                        help="Modules to run (default: all)")
    parser.add_argument("--all", action="store_true",
                        help="Run all modules (equivalent to not specifying --modules)")
    parser.add_argument("--ports", default=None,
                        help="Port range or comma-separated list (e.g. 1-1024 or 80,443,8080)")
    parser.add_argument("--nmap", action="store_true",
                        help="Use nmap instead of socket scanner (requires nmap installed)")
    parser.add_argument("--wordlist", default=None,
                        help="Path to subdomain wordlist file")
    parser.add_argument("--threads", type=int, default=100,
                        help="Thread count for scanning (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.5,
                        help="Socket timeout in seconds (default: 1.5)")
    parser.add_argument("-o", "--output", default=None,
                        help="Output file base path (e.g. /tmp/report → report.json + report.txt)")
    parser.add_argument("--json-only", action="store_true",
                        help="Only save JSON report")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress ASCII banner")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    return parser.parse_args()


def parse_ports(port_str: str) -> list:
    """Parse '80,443' or '1-1024' into a list of ints."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def check_dependencies():
    deps = {
        "dnspython":   DNS_AVAILABLE,
        "requests":    REQUESTS_AVAILABLE,
        "python-whois":WHOIS_AVAILABLE,
        "rich":        RICH_AVAILABLE,
    }
    missing = [d for d, ok in deps.items() if not ok]
    if missing:
        log("WARN", f"Optional packages not installed (degraded mode): {', '.join(missing)}")
        log("INFO", f"Install with: pip install {' '.join(missing)}")


def main():
    args = parse_args()

    if not args.no_banner:
        print_banner()

    # Warnings
    log("WARN", "⚠  For authorized use only. Ensure you have written permission.")
    check_dependencies()

    target = validate_target(args.target)
    modules = args.modules
    scan_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    findings = {}

    log("INFO", f"Target    : {target}")
    log("INFO", f"Modules   : {', '.join(modules)}")
    log("INFO", f"Scan start: {scan_time}")

    # ── Run modules ─────────────────────────────────────────────────────────

    if "dns" in modules:
        dns_enum = DNSEnumerator(target)
        findings["dns"] = dns_enum.run()

    if "whois" in modules:
        whois_lkp = WHOISLookup(target)
        findings["whois"] = whois_lkp.run()

    if "ports" in modules:
        port_list = parse_ports(args.ports) if args.ports else list(TOP_PORTS.keys())
        scanner = PortScanner(
            target, port_list,
            threads=args.threads,
            timeout=args.timeout,
            use_nmap=args.nmap,
        )
        findings["ports"] = scanner.run()

    if "banners" in modules:
        open_ports = findings.get("ports", {}).get("open", {})
        grabber = BannerGrabber(target, open_ports)
        findings["banners"] = grabber.run()

    if "subs" in modules:
        sub_enum = SubdomainEnumerator(
            target, wordlist=args.wordlist, threads=args.threads, timeout=args.timeout
        )
        findings["subdomains"] = sub_enum.run()

    if "web" in modules:
        # Derive candidate HTTP ports from open ports
        open_ports = findings.get("ports", {}).get("open", {})
        web_ports = [p for p in open_ports if p in (80, 443, 8080, 8443, 8000, 8888)] \
                    or [80, 443]
        fingerprinter = WebFingerprinter(target, web_ports)
        findings["web"] = fingerprinter.run()

    # ── Summary & Report ─────────────────────────────────────────────────────

    reporter = ReportGenerator(target, scan_time, findings)
    reporter.print_summary()

    if args.output:
        base = args.output
        reporter.save_json(base + ".json")
        if not args.json_only:
            reporter.save_text(base + ".txt")
    else:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(".", "_").replace("/", "_")
        default_base = f"recon_{safe_target}_{ts}"
        reporter.save_json(default_base + ".json")
        if not args.json_only:
            reporter.save_text(default_base + ".txt")

    log("OK", "Scan complete.")


if __name__ == "__main__":
    main()

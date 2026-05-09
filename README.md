a single self-contained recon_toolkit.py with 6 modules that chain cleanly together, plus the interactive reference panel above.
What the toolkit covers:
ModuleWhat it doesdnsA/MX/NS/TXT/SOA + AXFR zone transfer attempt against each NSportsMulti-threaded socket scanner + nmap wrapper (--nmap)subsConcurrent subdomain brute-force, wordlist-swappablewebHTTP fingerprinting: tech stack, security header audit, cookie flagswhoisRegistrar, org, dates, emails via python-whois or socket fallbackbannersService-specific probes (FTP, SSH, SMTP, Redis, HTTP, etc.)
Quick start:
bashpip install dnspython requests python-whois rich
python3 recon_toolkit.py -t target.com -o ./reports/engagement1
A few things worth knowing:

Every module degrades gracefully — if a pip package is missing, it falls back rather than crashing
Open ports discovered by the port scanner are automatically fed into the banner grabber and web fingerprinter
Reports are always written — JSON (machine-parseable) and plain text (for client handoff)
Pass --wordlist a SecLists file for serious subdomain coverage

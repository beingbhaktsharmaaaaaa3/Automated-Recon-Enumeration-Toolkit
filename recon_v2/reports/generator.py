import json
from datetime import datetime
from core.logger import log, section


class ReportGenerator:
    def __init__(self, target: str, scan_time: str, findings: dict):
        self.target = target
        self.scan_time = scan_time
        self.findings = findings
        self.generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── JSON ──────────────────────────────────────────────────────────────────

    def save_json(self, path: str):
        report = {
            "meta": {
                "toolkit": "Recon & Enumeration Toolkit v2.0",
                "target": self.target,
                "scan_time": self.scan_time,
                "generated": self.generated,
            },
            "findings": self.findings,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        log("OK", f"JSON report → {path}")

    # ── Plain text ────────────────────────────────────────────────────────────

    def save_text(self, path: str):
        lines = [
            "=" * 72,
            "  RECON & ENUMERATION TOOLKIT v2.0 — ENGAGEMENT REPORT",
            "=" * 72,
            f"  Target    : {self.target}",
            f"  Scan Time : {self.scan_time}",
            f"  Generated : {self.generated}",
            "=" * 72,
        ]
        for module, data in self.findings.items():
            lines += ["", f"{'─'*72}", f"  {module.upper()}", f"{'─'*72}"]
            lines.append(json.dumps(data, indent=2, default=str))
        lines += ["", "=" * 72, "  END OF REPORT", "=" * 72]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        log("OK", f"Text report → {path}")

    # ── HTML ─────────────────────────────────────────────────────────────────

    def save_html(self, path: str):
        dns     = self.findings.get("dns", {})
        ports   = self.findings.get("ports", {})
        subs    = self.findings.get("subdomains", [])
        web     = self.findings.get("web", {})
        whois_d = self.findings.get("whois", {})
        banners = self.findings.get("banners", {})

        open_tcp = ports.get("open_tcp", {})
        open_udp = ports.get("open_udp", {})

        all_techs = []
        missing_headers = []
        cve_hits = []
        for url_data in web.values():
            all_techs.extend(url_data.get("technologies", []))
            missing_headers.extend(url_data.get("missing_security_headers", []))
        for port, bdata in banners.items():
            for cve in bdata.get("cves", []):
                cve_hits.append((port, cve["id"], cve["description"]))

        def _rows(items: list, cols: list) -> str:
            if not items:
                return f'<tr><td colspan="{len(cols)}" class="empty">No data</td></tr>'
            rows = ""
            for item in items:
                rows += "<tr>" + "".join(f"<td>{item.get(c,'')}</td>" for c in cols) + "</tr>"
            return rows

        def _kv_rows(d: dict) -> str:
            if not d:
                return '<tr><td colspan="2" class="empty">No data</td></tr>'
            return "".join(
                f"<tr><td class='key'>{k}</td><td>{str(v)[:200]}</td></tr>"
                for k, v in d.items() if v
            )

        def _port_rows(d: dict, proto: str) -> str:
            if not d:
                return f'<tr><td colspan="3" class="empty">No open {proto.upper()} ports</td></tr>'
            return "".join(
                f"<tr><td>{port}</td><td>{proto.upper()}</td><td>{info.get('service','')}</td></tr>"
                for port, info in sorted(d.items())
            )

        def _cve_rows() -> str:
            if not cve_hits:
                return '<tr><td colspan="3" class="empty">No CVE hints matched</td></tr>'
            return "".join(
                f"<tr><td>{port}</td>"
                f'<td><span class="badge-warn">{cve_id}</span></td>'
                f"<td>{desc}</td></tr>"
                for port, cve_id, desc in cve_hits
            )

        def _sub_rows() -> str:
            if not subs:
                return '<tr><td colspan="3" class="empty">No subdomains found</td></tr>'
            return "".join(
                f"<tr><td>{s['subdomain']}</td>"
                f"<td>{', '.join(s.get('ips', []))}</td>"
                f"<td>{s.get('source','')}</td></tr>"
                for s in subs
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report — {self.target}</title>
<style>
  :root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #c9d1d9; --text2: #8b949e;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
    --blue: #388bfd; --purple: #bc8cff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont,
    'Segoe UI', monospace; font-size: 14px; line-height: 1.6; }}
  .wrapper {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }}
  header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  header h1 {{ font-size: 1.6rem; color: var(--blue); }}
  header .meta {{ color: var(--text2); font-size: 13px; margin-top: .4rem; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem; margin-bottom: 2rem; }}
  .stat {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px;
    padding: 1rem 1.25rem; }}
  .stat .num {{ font-size: 2rem; font-weight: 700; color: var(--blue); line-height: 1; }}
  .stat .label {{ color: var(--text2); font-size: 12px; margin-top: .3rem; }}
  section {{ margin-bottom: 2.5rem; }}
  section h2 {{ font-size: 1rem; font-weight: 600; color: var(--purple);
    border-left: 3px solid var(--purple); padding-left: .75rem; margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--bg2);
    border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th {{ background: var(--bg3); color: var(--text2); font-size: 11px; text-transform: uppercase;
    letter-spacing: .05em; padding: .5rem .75rem; text-align: left; border-bottom: 1px solid var(--border); }}
  td {{ padding: .45rem .75rem; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-all; }}
  tr:last-child td {{ border-bottom: none; }}
  td.key {{ color: var(--text2); min-width: 160px; font-family: monospace; }}
  td.empty {{ color: var(--text2); font-style: italic; text-align: center; padding: 1rem; }}
  .badge-warn {{ background: rgba(210,153,34,.15); color: var(--yellow);
    padding: 1px 8px; border-radius: 4px; font-size: 12px; font-family: monospace; }}
  .badge-ok {{ background: rgba(63,185,80,.15); color: var(--green);
    padding: 1px 8px; border-radius: 4px; font-size: 12px; }}
  .badge-crit {{ background: rgba(248,81,73,.15); color: var(--red);
    padding: 1px 8px; border-radius: 4px; font-size: 12px; }}
  .tag {{ display: inline-block; background: var(--bg3); border: 1px solid var(--border);
    border-radius: 4px; font-size: 12px; padding: 1px 8px; margin: 2px; color: var(--text); }}
  footer {{ color: var(--text2); font-size: 12px; text-align: center;
    border-top: 1px solid var(--border); padding-top: 1.5rem; margin-top: 2rem; }}
</style>
</head>
<body>
<div class="wrapper">

<header>
  <h1>🔍 Recon Report</h1>
  <div class="meta">
    <strong>Target:</strong> {self.target} &nbsp;|&nbsp;
    <strong>Scan started:</strong> {self.scan_time} &nbsp;|&nbsp;
    <strong>Generated:</strong> {self.generated}
  </div>
</header>

<div class="stat-grid">
  <div class="stat"><div class="num">{len(open_tcp)}</div><div class="label">Open TCP Ports</div></div>
  <div class="stat"><div class="num">{len(open_udp)}</div><div class="label">Open UDP Ports</div></div>
  <div class="stat"><div class="num">{len(subs)}</div><div class="label">Subdomains Found</div></div>
  <div class="stat"><div class="num">{len(set(all_techs))}</div><div class="label">Technologies Detected</div></div>
  <div class="stat"><div class="num">{len(cve_hits)}</div><div class="label">CVE Hints Matched</div></div>
  <div class="stat"><div class="num">{len(set(missing_headers))}</div><div class="label">Missing Sec Headers</div></div>
</div>

<section>
  <h2>DNS Records</h2>
  <table>
    <tr><th>Type</th><th>Value(s)</th></tr>
    {"".join(f"<tr><td class='key'>{rtype}</td><td>{'<br>'.join(str(v) for v in (vals if isinstance(vals, list) else [vals]))}</td></tr>" for rtype, vals in dns.items()) or '<tr><td colspan="2" class="empty">No DNS data</td></tr>'}
  </table>
</section>

<section>
  <h2>Open Ports</h2>
  <table>
    <tr><th>Port</th><th>Protocol</th><th>Service</th></tr>
    {_port_rows(open_tcp, "tcp")}
    {_port_rows(open_udp, "udp")}
  </table>
</section>

<section>
  <h2>Banner Grabbing & CVE Hints</h2>
  <table>
    <tr><th>Port</th><th>CVE</th><th>Description</th></tr>
    {_cve_rows()}
  </table>
</section>

<section>
  <h2>Subdomains</h2>
  <table>
    <tr><th>Subdomain</th><th>IP(s)</th><th>Source</th></tr>
    {_sub_rows()}
  </table>
</section>

<section>
  <h2>Web Technologies Detected</h2>
  <div style="padding:.75rem 1rem;background:var(--bg2);border:1px solid var(--border);border-radius:8px;">
    {"".join(f'<span class="tag">{t}</span>' for t in sorted(set(all_techs))) or '<span style="color:var(--text2);font-style:italic">None detected</span>'}
  </div>
</section>

<section>
  <h2>Web Endpoints</h2>
  {"".join(self._render_endpoint(url, data) for url, data in web.items()) or '<p style="color:var(--text2)">No web data</p>'}
</section>

<section>
  <h2>WHOIS</h2>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    {_kv_rows(whois_d)}
  </table>
</section>

<footer>Generated by Recon &amp; Enumeration Toolkit v2.0 — Authorized use only.</footer>
</div>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        log("OK", f"HTML report → {path}")

    def _render_endpoint(self, url: str, data: dict) -> str:
        ssl = data.get("ssl") or {}
        missing = data.get("missing_security_headers", [])
        cookies = data.get("cookies", {})
        return f"""
<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;
  padding:1rem 1.25rem;margin-bottom:1rem;">
  <div style="font-weight:600;margin-bottom:.5rem;">
    <span style="color:var(--blue)">{url}</span>
    <span style="color:var(--text2);font-size:13px;margin-left:.75rem;">
      HTTP {data.get('status_code','')} — {data.get('title','')[:80]}
    </span>
  </div>
  {"<div style='color:var(--yellow);font-size:13px;margin-bottom:.4rem;'>⚠ Missing: " + ", ".join(missing) + "</div>" if missing else ""}
  {"<div style='color:var(--text2);font-size:13px;'>TLS: " + ssl.get('tls_version','') + " | " + ssl.get('cipher','') + " | expires in " + str(ssl.get('days_until_expiry','?')) + " days</div>" if ssl else ""}
  {"<div style='font-size:13px;margin-top:.4rem;'>🍪 Cookies: " + ", ".join(f"{n} ({', '.join(v.get('flags',[])) or 'OK'})" for n, v in cookies.items()) + "</div>" if cookies else ""}
</div>"""

    # ── Summary table (terminal) ──────────────────────────────────────────────

    def print_summary(self):
        section("Engagement Summary")
        try:
            from rich.console import Console
            from rich.table import Table
            from rich import box
            console = Console()
            t = Table(title=f"Summary — {self.target}", box=box.ROUNDED,
                      border_style="blue", header_style="bold cyan", show_lines=True)
            t.add_column("Module", style="bold white", width=20)
            t.add_column("Result", width=55)

            dns = self.findings.get("dns", {})
            t.add_row("DNS Records", ", ".join(dns.keys()) or "None")

            ports = self.findings.get("ports", {})
            tcp = ports.get("open_tcp", {})
            udp = ports.get("open_udp", {})
            t.add_row("Open TCP Ports", ", ".join(f"{p}({v['service']})" for p, v in sorted(tcp.items()))[:60] or "None")
            t.add_row("Open UDP Ports", ", ".join(f"{p}({v['service']})" for p, v in sorted(udp.items()))[:60] or "None")

            subs = self.findings.get("subdomains", [])
            t.add_row("Subdomains", f"{len(subs)} found" + (
                f": {', '.join(s['subdomain'] for s in subs[:3])}" if subs else ""))

            web = self.findings.get("web", {})
            techs = list({t_ for d in web.values() for t_ in d.get("technologies", [])})
            t.add_row("Technologies", ", ".join(techs[:8]) or "None")

            banners = self.findings.get("banners", {})
            cves = [c["id"] for b in banners.values() for c in b.get("cves", [])]
            t.add_row("CVE Hints", ", ".join(cves) or "None")

            whois_d = self.findings.get("whois", {})
            t.add_row("WHOIS Registrar", str(whois_d.get("registrar", "N/A"))[:55])
            console.print(t)
        except ImportError:
            for module, data in self.findings.items():
                print(f"  {module}: {str(data)[:80]}")

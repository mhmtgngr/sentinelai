"""Report generation — JSON and HTML output for DNS pentest results."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from .models import ScanResult

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#ca8a04",
    "Low": "#2563eb",
    "Info": "#6b7280",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DNS Pentest Report — {target}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 2rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ color: #f8fafc; font-size: 1.8rem; margin-bottom: 0.5rem; }}
  h2 {{ color: #94a3b8; font-size: 1.3rem; margin: 2rem 0 1rem; border-bottom: 1px solid #334155;
        padding-bottom: 0.5rem; }}
  h3 {{ color: #cbd5e1; font-size: 1.1rem; margin: 1rem 0 0.5rem; }}
  .header {{ background: #1e293b; padding: 2rem; border-radius: 12px; margin-bottom: 2rem;
             border: 1px solid #334155; }}
  .header .subtitle {{ color: #64748b; font-size: 0.9rem; }}
  .meta {{ display: flex; gap: 2rem; margin-top: 1rem; flex-wrap: wrap; }}
  .meta-item {{ background: #0f172a; padding: 0.5rem 1rem; border-radius: 8px; font-size: 0.85rem; }}
  .meta-item span {{ color: #94a3b8; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                    gap: 1rem; margin: 1rem 0; }}
  .summary-card {{ background: #1e293b; padding: 1.2rem; border-radius: 10px; text-align: center;
                   border: 1px solid #334155; }}
  .summary-card .count {{ font-size: 2rem; font-weight: 700; }}
  .summary-card .label {{ font-size: 0.8rem; color: #94a3b8; text-transform: uppercase;
                          letter-spacing: 0.05em; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.7rem; border-radius: 9999px; font-size: 0.75rem;
            font-weight: 600; color: #fff; }}
  .finding-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px;
                   padding: 1.5rem; margin-bottom: 1rem; border-left: 4px solid; }}
  .finding-card .title {{ font-size: 1rem; font-weight: 600; color: #f1f5f9; margin-bottom: 0.5rem; }}
  .finding-card .desc {{ color: #94a3b8; font-size: 0.9rem; margin: 0.5rem 0; }}
  .finding-card .section-label {{ color: #64748b; font-size: 0.75rem; text-transform: uppercase;
                                  letter-spacing: 0.05em; margin-top: 0.8rem; }}
  .evidence {{ background: #0f172a; padding: 0.8rem; border-radius: 6px; font-family: 'Fira Code',
               monospace; font-size: 0.8rem; color: #e2e8f0; white-space: pre-wrap;
               margin-top: 0.3rem; overflow-x: auto; }}
  .remediation {{ color: #86efac; font-size: 0.85rem; margin-top: 0.3rem; }}
  .mitre {{ display: inline-block; background: #312e81; color: #a5b4fc; padding: 0.15rem 0.5rem;
            border-radius: 4px; font-size: 0.75rem; margin-top: 0.5rem; text-decoration: none; }}
  .mitre:hover {{ background: #3730a3; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th {{ background: #1e293b; color: #94a3b8; text-align: left; padding: 0.8rem; font-size: 0.8rem;
       text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 0.6rem 0.8rem; border-bottom: 1px solid #1e293b; font-size: 0.85rem; }}
  tr:hover {{ background: #1e293b; }}
  .subdomain-list {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
  .subdomain-tag {{ background: #1e293b; padding: 0.3rem 0.8rem; border-radius: 6px;
                    font-size: 0.8rem; font-family: monospace; }}
  .footer {{ text-align: center; color: #475569; font-size: 0.8rem; margin-top: 3rem;
             padding-top: 1rem; border-top: 1px solid #1e293b; }}
  .azure-section {{ background: #172554; border: 1px solid #1e3a5f; border-radius: 10px;
                    padding: 1.5rem; margin: 1rem 0; }}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>Sentinel-AI DNS Pentest Report</h1>
  <div class="subtitle">Automated DNS Penetration Testing & Security Assessment</div>
  <div class="meta">
    <div class="meta-item"><span>Target:</span> <strong>{target}</strong></div>
    <div class="meta-item"><span>Start:</span> {scan_start}</div>
    <div class="meta-item"><span>End:</span> {scan_end}</div>
    <div class="meta-item"><span>Nameservers:</span> {nameservers}</div>
  </div>
</div>

<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="summary-card">
    <div class="count" style="color: #dc2626">{critical_count}</div>
    <div class="label">Critical</div>
  </div>
  <div class="summary-card">
    <div class="count" style="color: #ea580c">{high_count}</div>
    <div class="label">High</div>
  </div>
  <div class="summary-card">
    <div class="count" style="color: #ca8a04">{medium_count}</div>
    <div class="label">Medium</div>
  </div>
  <div class="summary-card">
    <div class="count" style="color: #2563eb">{low_count}</div>
    <div class="label">Low</div>
  </div>
  <div class="summary-card">
    <div class="count" style="color: #6b7280">{info_count}</div>
    <div class="label">Info</div>
  </div>
  <div class="summary-card">
    <div class="count" style="color: #22d3ee">{records_count}</div>
    <div class="label">DNS Records</div>
  </div>
  <div class="summary-card">
    <div class="count" style="color: #a78bfa">{subdomains_count}</div>
    <div class="label">Subdomains</div>
  </div>
</div>

{azure_section}

<h2>Security Findings</h2>
{findings_html}

<h2>DNS Records</h2>
<table>
  <thead><tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th><th>Source</th></tr></thead>
  <tbody>{records_html}</tbody>
</table>

{subdomains_section}

{reverse_dns_section}

<div class="footer">
  Generated by Sentinel-AI DNS Pentest Scanner v1.0.0 | Report generated {generated_at}
</div>

</div>
</body>
</html>"""


class ReportGenerator:
    """Generate JSON and HTML reports from scan results."""

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_json(self, result: ScanResult) -> str:
        """Generate JSON report and return the file path."""
        filename = self._make_filename(result.target_domain, "json")
        filepath = self.output_dir / filename

        with open(filepath, "w") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)

        logger.info("JSON report saved: %s", filepath)
        return str(filepath)

    def generate_html(self, result: ScanResult) -> str:
        """Generate HTML report and return the file path."""
        filename = self._make_filename(result.target_domain, "html")
        filepath = self.output_dir / filename

        html = self._render_html(result)
        with open(filepath, "w") as f:
            f.write(html)

        logger.info("HTML report saved: %s", filepath)
        return str(filepath)

    def generate(self, result: ScanResult, fmt: str = "both") -> list[str]:
        """Generate reports in the specified format(s)."""
        paths: list[str] = []
        if fmt in ("json", "both"):
            paths.append(self.generate_json(result))
        if fmt in ("html", "both"):
            paths.append(self.generate_html(result))
        return paths

    def _render_html(self, result: ScanResult) -> str:
        """Render the HTML report from scan result."""
        data = result.to_dict()
        summary = data["summary"]["by_severity"]

        # Azure section
        azure_html = ""
        if result.azure_zones:
            azure_rows = ""
            for z in result.azure_zones:
                azure_rows += (
                    f"<tr><td>{z.zone_name}</td><td>{z.resource_group}</td>"
                    f"<td>{z.record_count}</td>"
                    f"<td>{', '.join(z.nameservers[:3])}</td></tr>"
                )
            azure_html = f"""
<h2>Azure DNS Zones</h2>
<div class="azure-section">
  <table>
    <thead><tr><th>Zone</th><th>Resource Group</th><th>Records</th><th>Nameservers</th></tr></thead>
    <tbody>{azure_rows}</tbody>
  </table>
</div>"""

        # Findings
        findings_html = ""
        if not result.findings:
            findings_html = '<p style="color: #86efac;">No security issues found.</p>'
        else:
            sorted_findings = sorted(
                result.findings, key=lambda f: f.severity.sort_key
            )
            for f in sorted_findings:
                color = SEVERITY_COLORS.get(f.severity.value, "#6b7280")
                mitre_html = ""
                if f.mitre_technique:
                    mitre_url = f"https://attack.mitre.org/techniques/{f.mitre_technique.replace('.', '/')}/"
                    mitre_html = (
                        f'<a class="mitre" href="{mitre_url}" target="_blank">'
                        f"MITRE {f.mitre_technique}: {f.mitre_name or ''}</a>"
                    )

                findings_html += f"""
<div class="finding-card" style="border-left-color: {color}">
  <div>
    <span class="badge" style="background: {color}">{f.severity.value}</span>
    {f'<span class="badge" style="background: #334155; color: #94a3b8; margin-left: 0.3rem">{f.category}</span>' if f.category else ''}
  </div>
  <div class="title">{_escape(f.title)}</div>
  <div class="desc">{_escape(f.description)}</div>
  <div class="section-label">Evidence</div>
  <div class="evidence">{_escape(f.evidence)}</div>
  <div class="section-label">Remediation</div>
  <div class="remediation">{_escape(f.remediation)}</div>
  {mitre_html}
</div>"""

        # DNS Records table rows
        records_html = ""
        for r in result.dns_records:
            source_badge = (
                '<span style="color: #60a5fa">Azure</span>'
                if r.source == "azure_api"
                else '<span style="color: #94a3b8">External</span>'
            )
            records_html += (
                f"<tr><td><strong>{r.record_type}</strong></td>"
                f"<td>{_escape(r.name)}</td>"
                f"<td style='font-family:monospace;font-size:0.8rem'>{_escape(r.value)}</td>"
                f"<td>{r.ttl}</td><td>{source_badge}</td></tr>"
            )

        # Subdomains
        subdomains_section = ""
        if result.subdomains:
            tags = "".join(
                f'<span class="subdomain-tag">{_escape(s)}</span>'
                for s in sorted(result.subdomains)
            )
            subdomains_section = f"""
<h2>Discovered Subdomains ({len(result.subdomains)})</h2>
<div class="subdomain-list">{tags}</div>"""

        # Reverse DNS
        reverse_dns_section = ""
        if result.reverse_dns:
            rows = "".join(
                f"<tr><td style='font-family:monospace'>{ip}</td>"
                f"<td>{_escape(hostname)}</td></tr>"
                for ip, hostname in sorted(result.reverse_dns.items())
            )
            reverse_dns_section = f"""
<h2>Reverse DNS</h2>
<table>
  <thead><tr><th>IP Address</th><th>Hostname (PTR)</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"""

        return HTML_TEMPLATE.format(
            target=_escape(result.target_domain),
            scan_start=result.scan_start.strftime("%Y-%m-%d %H:%M:%S UTC"),
            scan_end=(
                result.scan_end.strftime("%Y-%m-%d %H:%M:%S UTC")
                if result.scan_end
                else "In progress"
            ),
            nameservers=", ".join(result.nameservers) if result.nameservers else "N/A",
            critical_count=summary.get("Critical", 0),
            high_count=summary.get("High", 0),
            medium_count=summary.get("Medium", 0),
            low_count=summary.get("Low", 0),
            info_count=summary.get("Info", 0),
            records_count=len(result.dns_records),
            subdomains_count=len(result.subdomains),
            azure_section=azure_html,
            findings_html=findings_html,
            records_html=records_html,
            subdomains_section=subdomains_section,
            reverse_dns_section=reverse_dns_section,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

    @staticmethod
    def _make_filename(domain: str, ext: str) -> str:
        safe_domain = domain.replace(".", "_")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"{safe_domain}_dns_pentest_{timestamp}.{ext}"


def _escape(text: str) -> str:
    """Basic HTML escaping."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

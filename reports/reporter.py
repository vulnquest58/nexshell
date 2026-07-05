#!/usr/bin/env python3
"""
NexShell — Reporting Engine  (reports/reporter.py)
Generates professional pentest reports from DB data.

Outputs:
    • Markdown (default)
    • JSON (structured export)
    • HTML (self-contained, print-ready)

CLI (from nexshell.py):
    report generate                    — Generate markdown report
    report generate --format html      — Generate HTML report
    report generate --format json      — Generate JSON export
"""

import os
import json
import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# ══════════════════════════════════════════════════════════════════════════════
#  REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Compiles data from all DB tables into a structured pentest report."""

    SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']
    SEVERITY_ICONS = {
        'critical': '🔴', 'high': '🟠', 'medium': '🟡',
        'low': '🟢', 'info': '⚪',
    }

    def __init__(self):
        pass

    def _get_db(self):
        try:
            from db import get_db
            return get_db()
        except Exception:
            return None

    def _get_operation(self):
        try:
            from operations import ops
            return ops.active
        except Exception:
            return None

    # ── Data Collection ───────────────────────────────────────────────────────

    def collect_data(self) -> Dict[str, Any]:
        """Gather all report data from DB."""
        db   = self._get_db()
        op   = self._get_operation()
        data = {
            'generated_at': datetime.datetime.utcnow().isoformat(),
            'operation':    op.to_dict() if op else {},
            'sessions':     [],
            'hosts':        [],
            'findings':     [],
            'loot_summary': {},
            'evidence':     [],
            'statistics':   {},
        }
        if not db:
            return data

        # Sessions
        try:
            data['sessions'] = db.list_sessions()
        except Exception:
            pass

        # Hosts
        try:
            data['hosts'] = db.list_hosts()
        except Exception:
            pass

        # Findings (severity-sorted)
        try:
            findings = db.list_findings()
            order    = {s: i for i, s in enumerate(self.SEVERITY_ORDER)}
            data['findings'] = sorted(findings, key=lambda f: order.get(f.get('severity','info'), 99))
        except Exception:
            pass

        # Loot summary
        try:
            data['loot_summary'] = db.get_loot_summary()
        except Exception:
            pass

        # Evidence
        try:
            data['evidence'] = db.list_evidence()
        except Exception:
            pass

        # Statistics
        try:
            data['statistics'] = db.stats()
        except Exception:
            pass

        return data

    # ── Markdown Report ───────────────────────────────────────────────────────

    def generate_markdown(self, output_path: str = None) -> str:
        """Generate a full markdown pentest report."""
        data = self.collect_data()
        op   = data['operation']
        now  = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

        lines = [
            f"# Penetration Test Report",
            f"",
            f"> **Generated:** {now}  ",
            f"> **Tool:** NexShell v2  ",
            f"> **Classification:** CONFIDENTIAL",
            f"",
        ]

        # Operation details
        if op:
            lines += [
                "## Engagement Overview",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| Operation | {op.get('name', '—')} |",
                f"| Client | {op.get('client', '—')} |",
                f"| Operator | {op.get('operator', '—')} |",
                f"| Status | {op.get('status', '—')} |",
                f"| Start Date | {op.get('start_date', '—')[:10]} |",
                f"| End Date | {op.get('end_date', 'Ongoing')[:10] or 'Ongoing'} |",
                f"",
            ]
            # Objectives
            objs = op.get('objectives', [])
            if objs:
                lines.append("### Objectives")
                lines.append("")
                for obj in objs:
                    lines.append(f"- {obj}")
                lines.append("")
            # Scope
            scope_ips = op.get('scope_ips', [])
            scope_dom = op.get('scope_domains', [])
            if scope_ips or scope_dom:
                lines.append("### Scope")
                lines.append("")
                if scope_ips:
                    lines.append(f"**IP Ranges:** {', '.join(scope_ips)}")
                if scope_dom:
                    lines.append(f"**Domains:** {', '.join(scope_dom)}")
                lines.append("")

        # Executive Summary
        stats    = data['statistics']
        findings = data['findings']
        by_sev   = {s: [f for f in findings if f.get('severity') == s]
                    for s in self.SEVERITY_ORDER}

        lines += [
            "## Executive Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Sessions | {stats.get('sessions_total', len(data['sessions']))} |",
            f"| Hosts Discovered | {len(data['hosts'])} |",
            f"| Total Findings | {len(findings)} |",
            f"| Critical Findings | {len(by_sev.get('critical', []))} |",
            f"| High Findings | {len(by_sev.get('high', []))} |",
            f"| Loot Items | {stats.get('loot_total', 0)} |",
            f"| Credentials Found | {stats.get('loot_creds', 0)} |",
            f"",
        ]

        # Findings
        if findings:
            lines += ["## Findings", ""]
            for i, f in enumerate(findings, 1):
                sev_icon = self.SEVERITY_ICONS.get(f.get('severity', 'info'), '⚫')
                lines += [
                    f"### {i}. {sev_icon} {f.get('title', 'Unnamed Finding')}",
                    "",
                    f"| Field | Value |",
                    f"|-------|-------|",
                    f"| Severity | **{f.get('severity', '').upper()}** |",
                    f"| CVSS | {f.get('cvss', 0.0):.1f} |",
                    f"| Host | `{f.get('host', '—')}` |",
                    f"| MITRE | {f.get('mitre_id', '—')} |",
                    f"| Status | {f.get('status', 'open')} |",
                    f"| Source | {f.get('source', 'manual')} |",
                    f"",
                ]
                if f.get('description'):
                    lines += ["**Description:**", "", f.get('description', ''), ""]
                if f.get('recommendation'):
                    lines += ["**Recommendation:**", "", f.get('recommendation', ''), ""]
                lines.append("---")
                lines.append("")

        # Hosts
        if data['hosts']:
            lines += ["## Asset Inventory", "", "| IP | Hostname | OS | Risk | Tags |",
                      "|----|----------|----|------|------|"]
            for h in data['hosts']:
                tags = ', '.join(h.get('tags', [])) if h.get('tags') else '—'
                lines.append(
                    f"| `{h.get('ip', '')}` | {h.get('hostname','—')} | "
                    f"{h.get('os','?')} | {h.get('risk','?')} | {tags} |"
                )
            lines.append("")

        # Sessions
        if data['sessions']:
            lines += ["## Sessions", "", "| ID | Host | OS | User | Status |",
                      "|----|------|----|------|--------|"]
            for s in data['sessions']:
                root = " (root)" if s.get('is_root') else ""
                lines.append(
                    f"| {s.get('id','')} | `{s.get('host','')}` | "
                    f"{s.get('os','?')} | {s.get('user','?')}{root} | {s.get('status','?')} |"
                )
            lines.append("")

        # Evidence
        if data['evidence']:
            lines += ["## Evidence", "",
                      "| ID | Type | Host | SHA256 | Note |",
                      "|----|------|------|--------|------|"]
            for e in data['evidence'][:30]:
                sha = e.get('sha256', '')[:16] + '…'
                lines.append(
                    f"| `{e.get('id','')[:8]}` | {e.get('type','')} | "
                    f"`{e.get('host','—')}` | `{sha}` | {e.get('note','')[:40]} |"
                )
            lines.append("")

        lines += [
            "---",
            f"*Report generated by NexShell v2 — {now}*",
            "",
        ]

        report_text = '\n'.join(lines)

        if output_path:
            Path(output_path).write_text(report_text, encoding='utf-8')

        return report_text

    # ── JSON Export ───────────────────────────────────────────────────────────

    def generate_json(self, output_path: str = None) -> str:
        """Export all data as structured JSON."""
        data = self.collect_data()
        result = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        if output_path:
            Path(output_path).write_text(result, encoding='utf-8')
        return result

    # ── HTML Report ───────────────────────────────────────────────────────────

    def generate_html(self, output_path: str = None) -> str:
        """Generate a self-contained HTML report with embedded CSS."""
        data     = self.collect_data()
        op       = data['operation']
        findings = data['findings']
        stats    = data['statistics']
        now      = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
        op_name  = op.get('name', 'Engagement Report') if op else 'Engagement Report'

        by_sev = {s: len([f for f in findings if f.get('severity') == s])
                  for s in self.SEVERITY_ORDER}

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{op_name} — NexShell Report</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --accent: #58a6ff; --green: #3fb950;
    --red: #f85149; --orange: #d29922; --purple: #bc8cff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
           font-size: 14px; line-height: 1.6; padding: 2rem; }}
  h1 {{ color: var(--accent); font-size: 2rem; margin-bottom: .5rem; }}
  h2 {{ color: var(--purple); font-size: 1.3rem; margin: 2rem 0 1rem;
        border-bottom: 1px solid var(--border); padding-bottom: .4rem; }}
  h3 {{ color: var(--text); font-size: 1.1rem; margin: 1.5rem 0 .5rem; }}
  .meta {{ color: #8b949e; font-size: 12px; margin-bottom: 2rem; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 1rem; margin: 1rem 0; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
                padding: 1rem; text-align: center; }}
  .stat-card .num {{ font-size: 2rem; font-weight: bold; color: var(--accent); }}
  .stat-card .lbl {{ color: #8b949e; font-size: 12px; }}
  .finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
              padding: 1.2rem; margin: 1rem 0; }}
  .finding.critical {{ border-left: 4px solid #f85149; }}
  .finding.high     {{ border-left: 4px solid #d29922; }}
  .finding.medium   {{ border-left: 4px solid #e3b341; }}
  .finding.low      {{ border-left: 4px solid #3fb950; }}
  .finding.info     {{ border-left: 4px solid #58a6ff; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px;
            font-size: 11px; font-weight: bold; margin-right: 4px; }}
  .badge.critical {{ background: #f8514933; color: #f85149; }}
  .badge.high {{ background: #d2992233; color: #d29922; }}
  .badge.medium {{ background: #e3b34133; color: #e3b341; }}
  .badge.low {{ background: #3fb95033; color: #3fb950; }}
  .badge.info {{ background: #58a6ff33; color: #58a6ff; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th {{ background: var(--surface); color: var(--accent); padding: 8px 12px;
        text-align: left; border-bottom: 1px solid var(--border); font-size: 12px; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); }}
  code {{ background: var(--surface); padding: 1px 6px; border-radius: 4px;
          font-family: 'Consolas', monospace; font-size: 12px; color: var(--green); }}
  .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
             color: #8b949e; font-size: 12px; }}
</style>
</head>
<body>
<h1>{'🔐 ' + op_name}</h1>
<p class="meta">Generated: {now} | NexShell v2</p>

<h2>📊 Executive Summary</h2>
<div class="stat-grid">
  <div class="stat-card"><div class="num">{stats.get('sessions_total', len(data['sessions']))}</div><div class="lbl">Sessions</div></div>
  <div class="stat-card"><div class="num">{len(data['hosts'])}</div><div class="lbl">Hosts</div></div>
  <div class="stat-card"><div class="num">{len(findings)}</div><div class="lbl">Findings</div></div>
  <div class="stat-card"><div class="num" style="color:#f85149">{by_sev.get('critical', 0)}</div><div class="lbl">Critical</div></div>
  <div class="stat-card"><div class="num" style="color:#d29922">{by_sev.get('high', 0)}</div><div class="lbl">High</div></div>
  <div class="stat-card"><div class="num">{stats.get('loot_creds', 0)}</div><div class="lbl">Credentials</div></div>
</div>
"""

        # Findings section
        if findings:
            html += "<h2>🎯 Findings</h2>\n"
            for i, f in enumerate(findings, 1):
                sev  = f.get('severity', 'info')
                icon = self.SEVERITY_ICONS.get(sev, '⚫')
                html += f"""
<div class="finding {sev}">
  <h3>{icon} {i}. {f.get('title','')}</h3>
  <p style="margin:.5rem 0">
    <span class="badge {sev}">{sev.upper()}</span>
    CVSS: <strong>{f.get('cvss',0.0):.1f}</strong> &nbsp;|&nbsp;
    Host: <code>{f.get('host','—')}</code> &nbsp;|&nbsp;
    MITRE: <code>{f.get('mitre_id','—')}</code>
  </p>"""
                if f.get('description'):
                    html += f"<p style='margin:.5rem 0'>{f['description']}</p>"
                if f.get('recommendation'):
                    html += f"<p style='color:#3fb950;margin:.5rem 0'>💡 {f['recommendation']}</p>"
                html += "</div>\n"

        # Hosts table
        if data['hosts']:
            html += "<h2>🖥️ Asset Inventory</h2>\n<table><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Risk</th><th>Tags</th></tr>\n"
            for h in data['hosts']:
                tags = ', '.join(h.get('tags', [])) if h.get('tags') else '—'
                html += f"<tr><td><code>{h.get('ip','')}</code></td><td>{h.get('hostname','—')}</td><td>{h.get('os','?')}</td><td>{h.get('risk','?')}</td><td>{tags}</td></tr>\n"
            html += "</table>\n"

        # Sessions table
        if data['sessions']:
            html += "<h2>💀 Sessions</h2>\n<table><tr><th>ID</th><th>Host</th><th>OS</th><th>User</th><th>Status</th></tr>\n"
            for s in data['sessions']:
                root = " <strong style='color:#f85149'>[ROOT]</strong>" if s.get('is_root') else ""
                html += f"<tr><td>{s.get('id','')}</td><td><code>{s.get('host','')}</code></td><td>{s.get('os','?')}</td><td>{s.get('user','?')}{root}</td><td>{s.get('status','?')}</td></tr>\n"
            html += "</table>\n"

        html += f'<div class="footer">NexShell v2 — {now}</div>\n</body>\n</html>'

        if output_path:
            Path(output_path).write_text(html, encoding='utf-8')
        return html

    # ── Auto-name ─────────────────────────────────────────────────────────────

    def auto_filename(self, fmt: str = 'md') -> str:
        """Generate timestamped output filename."""
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M')
        try:
            from operations import ops
            op_name = ops.active.name if ops.active else 'report'
        except Exception:
            op_name = 'report'
        safe = op_name.replace(' ', '_')
        return f"nexshell_{safe}_{ts}.{fmt}"


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

reporter = ReportGenerator()

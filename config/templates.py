#!/usr/bin/env python3
"""
NexShell — Configuration Templates  (config/templates.py)
Predefined engagement configurations and report templates.

Usage:
    from config.templates import get_template, REPORT_TEMPLATES
    tpl = get_template("internal_pentest")
    print(tpl["scope_template"])
"""

from typing import Dict, Any


# ── Engagement Templates ───────────────────────────────────────────────────────

ENGAGEMENT_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "internal_pentest": {
        "name":         "Internal Network Penetration Test",
        "type":         "pentest",
        "checklist":    "pentest",
        "opsec_profile":"normal",
        "auto_loot":    True,
        "auto_findings":True,
        "workflows":    ["quick-recon", "cred-hunt"],
        "mitre_focus":  ["T1078", "T1110", "T1021", "T1003"],
        "scope_template":"192.168.0.0/16",
        "report_sections": [
            "executive_summary", "scope", "findings",
            "asset_inventory", "credentials", "evidence", "recommendations"
        ],
        "objectives_template": [
            "Identify all network-accessible systems",
            "Attempt privilege escalation on compromised hosts",
            "Demonstrate lateral movement within the network",
            "Harvest credentials and assess password policy",
            "Identify critical data at risk",
        ],
    },
    "external_pentest": {
        "name":         "External Penetration Test",
        "type":         "pentest",
        "checklist":    "pentest",
        "opsec_profile":"ghost",
        "auto_loot":    True,
        "auto_findings":True,
        "workflows":    ["quick-recon"],
        "mitre_focus":  ["T1190", "T1133", "T1566", "T1078"],
        "report_sections": [
            "executive_summary", "scope", "attack_narrative",
            "findings", "credentials", "recommendations"
        ],
        "objectives_template": [
            "Enumerate externally accessible services",
            "Identify publicly exposed vulnerabilities",
            "Attempt to gain initial access",
            "Assess perimeter security controls",
        ],
    },
    "red_team": {
        "name":         "Red Team Operation",
        "type":         "red_team",
        "checklist":    "pentest",
        "opsec_profile":"paranoid",
        "auto_loot":    True,
        "auto_findings":True,
        "workflows":    ["quick-recon", "cred-hunt", "linux-privesc"],
        "mitre_focus":  ["T1566", "T1078", "T1021", "T1055", "T1003", "T1059"],
        "report_sections": [
            "executive_summary", "attack_path", "findings",
            "mitre_coverage", "detection_opportunities", "recommendations"
        ],
        "objectives_template": [
            "Simulate a realistic threat actor",
            "Test detection and response capabilities",
            "Achieve defined objectives without detection",
            "Document the full attack chain",
        ],
    },
    "ctf": {
        "name":         "CTF / HackTheBox / HackMyVM",
        "type":         "ctf",
        "checklist":    "quick",
        "opsec_profile":"normal",
        "auto_loot":    True,
        "auto_findings":False,
        "workflows":    ["quick-recon"],
        "mitre_focus":  [],
        "report_sections": ["overview", "enumeration", "exploitation", "flags"],
        "objectives_template": [
            "Obtain user flag",
            "Escalate to root",
            "Write a technical writeup",
        ],
    },
}


# ── Report Section Templates ───────────────────────────────────────────────────

REPORT_TEMPLATES: Dict[str, str] = {
    "executive_summary": """## Executive Summary

{operation_name} was conducted between {start_date} and {end_date}.

During this assessment, **{finding_count} findings** were identified across the tested scope,
including **{critical_count} critical** and **{high_count} high** severity vulnerabilities.

Key risk areas identified:
{risk_summary}

### Risk Rating

| Severity | Count |
|----------|:-----:|
| Critical | {critical_count} |
| High     | {high_count} |
| Medium   | {medium_count} |
| Low      | {low_count} |
| Info     | {info_count} |
""",

    "attack_narrative": """## Attack Narrative

### Phase 1: Initial Reconnaissance
{recon_summary}

### Phase 2: Initial Access
{access_summary}

### Phase 3: Post-Exploitation
{postex_summary}

### Phase 4: Lateral Movement
{lateral_summary}

### Phase 5: Impact
{impact_summary}
""",

    "recommendations": """## Remediation Recommendations

### Immediate Priority (Critical/High)
{critical_recs}

### Short-term (Medium)
{medium_recs}

### Long-term (Low/Info)
{low_recs}

### General Hardening Guidance

1. **Patch Management** — Establish a regular patching cycle (≤30 days for critical)
2. **Credential Hygiene** — Enforce MFA, password complexity, and regular rotation
3. **Network Segmentation** — Limit lateral movement with VLANs and firewall rules
4. **Monitoring & Alerting** — Deploy SIEM with detection rules for identified TTPs
5. **Least Privilege** — Remove unnecessary administrative rights
6. **Audit Logging** — Enable and centralize authentication and process execution logs
""",

    "mitre_coverage": """## MITRE ATT&CK Coverage

Techniques observed during the assessment:

| ID | Name | Tactic | Detected |
|----|------|--------|:--------:|
{technique_rows}

### Coverage Heatmap
{heatmap_note}
""",
}


def get_template(name: str) -> Dict[str, Any]:
    """Get an engagement template by name."""
    return ENGAGEMENT_TEMPLATES.get(name, ENGAGEMENT_TEMPLATES['ctf'])


def list_templates() -> list:
    return [
        {'name': k, 'description': v['name'], 'type': v['type']}
        for k, v in ENGAGEMENT_TEMPLATES.items()
    ]


def apply_template(template_name: str):
    """Apply an engagement template to the active operation and config."""
    tpl = get_template(template_name)
    results = []

    # Apply OPSEC profile
    try:
        from config import config
        config.set('opsec_profile', tpl.get('opsec_profile', 'normal'))
        results.append(f"OPSEC profile → {tpl['opsec_profile']}")
    except Exception:
        pass

    # Apply objectives
    try:
        from operations import ops
        if ops.active:
            for obj in tpl.get('objectives_template', []):
                ops.add_objective(obj)
            results.append(f"Applied {len(tpl['objectives_template'])} objectives")
    except Exception:
        pass

    # Initialize checklist
    try:
        from operations.checklist import Checklist
        cl = Checklist.from_template(tpl.get('checklist', 'pentest'))
        results.append(f"Checklist: {cl.name} ({tpl['checklist']})")
    except Exception:
        pass

    return results

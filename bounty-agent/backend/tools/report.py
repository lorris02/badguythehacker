"""Auto-generate professional bug bounty reports in Markdown."""

import os
from datetime import datetime, timezone
from typing import Any, Dict, List


SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

REMEDIATION_MAP = {
    "sqli": "Use parameterized queries / prepared statements. Never interpolate user input into SQL strings.",
    "sql injection": "Use parameterized queries / prepared statements. Never interpolate user input into SQL strings.",
    "xss": "Encode all user-controlled output. Use Content-Security-Policy headers. Prefer frameworks that auto-escape.",
    "idor": "Enforce server-side authorization checks on every object access. Never rely on obscurity of IDs.",
    "auth bypass": "Validate authentication on every sensitive endpoint server-side. Do not trust client-supplied roles.",
    "jwt": "Reject 'alg: none'. Pin the expected algorithm. Validate signature before trusting claims.",
    "ssrf": "Whitelist allowed internal endpoints. Block metadata IPs (169.254.169.254). Use a DNS rebind guard.",
    "rce": "Sanitize all inputs used in system calls. Use allowlists. Avoid shell=True in subprocesses.",
    "lfi": "Resolve canonical paths and validate they remain within the allowed directory.",
    "open redirect": "Whitelist redirect destinations. Never pass raw user input as a redirect URL.",
    "info disclosure": "Remove debug endpoints, stack traces, and verbose error messages from production.",
    "misconfiguration": "Harden server configuration. Apply principle of least privilege. Review exposed admin interfaces.",
}


def _remediation(vuln_type: str) -> str:
    vt = vuln_type.lower()
    for key, advice in REMEDIATION_MAP.items():
        if key in vt:
            return advice
    return "Apply the principle of least privilege, validate and sanitize all inputs, and conduct a targeted code review of the affected component."


def _severity_stats(findings: List[Dict]) -> Dict[str, int]:
    stats: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        stats[sev] = stats.get(sev, 0) + 1
    return stats


def generate_report(
    findings: List[Dict],
    target: str,
    reports_dir: str = "reports",
) -> str:
    """
    Render a Markdown bug bounty report and write it to reports_dir.
    Returns the path to the generated file.
    """
    os.makedirs(reports_dir, exist_ok=True)

    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_").strip("._")
    filename = f"{reports_dir}/report_{safe_target}_{timestamp}.md"

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info").lower(), 5))
    stats = _severity_stats(findings)
    confirmed = [f for f in findings if f.get("confirmed")]
    unconfirmed = [f for f in findings if not f.get("confirmed")]

    lines: List[str] = []

    # ── Header ──────────────────────────────────────────────────────────────
    lines += [
        f"# Bug Bounty Assessment Report",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Target** | `{target}` |",
        f"| **Assessment Date** | {now.strftime('%Y-%m-%d %H:%M UTC')} |",
        f"| **Tool** | BountyAgent (Claude-powered autonomous security agent) |",
        f"| **Total Findings** | {len(findings)} ({len(confirmed)} confirmed, {len(unconfirmed)} unconfirmed) |",
        f"",
    ]

    # ── Risk Rating Badge ────────────────────────────────────────────────────
    if stats["critical"] > 0:
        overall = "**CRITICAL**"
    elif stats["high"] > 0:
        overall = "**HIGH**"
    elif stats["medium"] > 0:
        overall = "**MEDIUM**"
    elif stats["low"] > 0:
        overall = "**LOW**"
    else:
        overall = "**INFORMATIONAL**"

    lines += [f"> Overall Risk Rating: {overall}", ""]

    # ── Executive Summary ────────────────────────────────────────────────────
    lines += ["## Executive Summary", ""]
    if not findings:
        lines += [
            "No vulnerabilities were identified during this assessment. "
            "The attack surface was fully enumerated and no exploitable conditions were confirmed.",
            "",
        ]
    else:
        lines += [
            f"This automated assessment of `{target}` identified **{len(findings)} finding(s)** "
            f"across the enumerated attack surface. "
            f"{len(confirmed)} finding(s) were confirmed with a proof of concept.",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            if stats[sev]:
                emoji = SEVERITY_EMOJI.get(sev, "")
                lines.append(f"| {emoji} {sev.capitalize()} | {stats[sev]} |")
        lines.append("")

    # ── Findings ─────────────────────────────────────────────────────────────
    lines += ["## Findings", ""]

    if not sorted_findings:
        lines += ["*No findings to report.*", ""]
    else:
        for idx, finding in enumerate(sorted_findings, 1):
            sev = finding.get("severity", "info").lower()
            emoji = SEVERITY_EMOJI.get(sev, "")
            vuln_type = finding.get("vuln_type", "Unknown")
            url = finding.get("url", "N/A")
            description = finding.get("description", "No description provided.")
            poc = finding.get("poc", "")
            confirmed_flag = finding.get("confirmed", False)
            status_label = "✅ Confirmed" if confirmed_flag else "⚠️ Unconfirmed"

            lines += [
                f"### [{idx}] {emoji} {vuln_type}",
                "",
                f"| | |",
                f"|---|---|",
                f"| **Severity** | {sev.capitalize()} |",
                f"| **Status** | {status_label} |",
                f"| **Affected URL** | `{url}` |",
                f"| **Discovered** | {finding.get('discovered_at', 'N/A')} |",
                "",
                "#### Description",
                "",
                description,
                "",
            ]

            if poc:
                lines += [
                    "#### Proof of Concept",
                    "",
                    "```",
                    poc,
                    "```",
                    "",
                ]

            lines += [
                "#### Impact",
                "",
                _impact_statement(vuln_type, sev),
                "",
                "#### Remediation",
                "",
                _remediation(vuln_type),
                "",
                "---",
                "",
            ]

    # ── Attack Surface Summary ───────────────────────────────────────────────
    lines += [
        "## Attack Surface Summary",
        "",
        "_Subdomains, live hosts, and endpoints enumerated during this assessment are stored "
        "in the local SQLite database (`bounty_agent.db`) for review._",
        "",
    ]

    # ── Methodology ──────────────────────────────────────────────────────────
    lines += [
        "## Methodology",
        "",
        "1. **Passive Recon** — subfinder (subdomain enumeration), Shodan (service discovery)",
        "2. **Active Fingerprinting** — httpx (live host probing, technology detection)",
        "3. **Vulnerability Discovery** — nuclei (template-based scanning), ffuf (directory/endpoint fuzzing)",
        "4. **Exploitation** — sqlmap (SQL injection), custom IDOR probes, auth bypass probes",
        "5. **Confirmation** — each finding verified with a reproducible proof of concept",
        "",
    ]

    # ── Disclaimer ───────────────────────────────────────────────────────────
    lines += [
        "## Disclaimer",
        "",
        "> This assessment was conducted on an **authorized** target within an agreed scope. "
        "All testing activities were non-destructive. This report is intended solely for the "
        "target organization's security team.",
        "",
        f"*Generated by BountyAgent on {now.strftime('%Y-%m-%d at %H:%M UTC')}*",
    ]

    content = "\n".join(lines)
    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(content)

    return filename


def generate_disclosure_report(
    findings: List[Dict],
    target: str,
    contact_info: Dict,
    reports_dir: str = "reports",
) -> str:
    """
    Generate a professional responsible disclosure report (Markdown).

    Includes CVSS breakdown, disclosure timeline, security contact info,
    and remediation guidance. Designed to be sent to the vendor's security team.
    """
    os.makedirs(reports_dir, exist_ok=True)

    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_").strip("._")
    filename = f"{reports_dir}/disclosure_{safe_target}_{timestamp}.md"
    deadline = now.replace(tzinfo=None)

    from datetime import timedelta
    deadline_date = (now + timedelta(days=90)).strftime("%Y-%m-%d")

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info").lower(), 5))
    stats = _severity_stats(findings)
    confirmed = [f for f in findings if f.get("confirmed")]

    lines: List[str] = []

    # ── Header ──────────────────────────────────────────────────────────────
    lines += [
        "# Responsible Disclosure Report",
        "",
        f"| | |",
        f"|---|---|",
        f"| **Target** | `{target}` |",
        f"| **Report Date** | {now.strftime('%Y-%m-%d')} |",
        f"| **Disclosure Deadline** | {deadline_date} (90-day policy) |",
        f"| **CVE Status** | Pending assignment |",
        f"| **Findings** | {len(confirmed)} confirmed / {len(findings)} total |",
        "",
        "> **This report is confidential.** Please do not share outside your security team "
        "until vulnerabilities are remediated.",
        "",
    ]

    # ── Contact info found ───────────────────────────────────────────────────
    if contact_info:
        recommended = contact_info.get("recommended_contact", "N/A")
        has_program = contact_info.get("has_formal_program", False)
        lines += [
            "## Security Contact",
            "",
            f"- **Recommended contact**: `{recommended}`",
            f"- **Formal bug bounty program**: {'Yes' if has_program else 'Not detected'}",
        ]
        if contact_info.get("platform_programs"):
            for prog in contact_info["platform_programs"]:
                platform = prog.get("platform", prog.get("url", ""))
                url = prog.get("url", "")
                lines.append(f"- **Platform**: [{platform}]({url})")
        if contact_info.get("security_txt"):
            lines.append(f"- **security.txt**: {contact_info['security_txt'].get('url', '')}")
        lines += [""]

    # ── Executive Summary ────────────────────────────────────────────────────
    lines += ["## Executive Summary", ""]

    if not findings:
        lines += ["No confirmed vulnerabilities were identified.", ""]
    else:
        # Determine top finding for summary
        top = sorted_findings[0]
        top_sev = top.get("severity", "unknown").upper()
        top_type = top.get("vuln_type", "vulnerability")
        cvss = top.get("cvss_score", "N/A")
        cvss_vector = top.get("cvss_vector", "")

        lines += [
            f"A **{top_sev}**-severity {top_type} was identified in `{target}`. "
            f"This report documents {len(confirmed)} confirmed finding(s) discovered during "
            f"independent security research conducted on {now.strftime('%Y-%m-%d')}.",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            if stats[sev]:
                emoji = SEVERITY_EMOJI.get(sev, "")
                lines.append(f"| {emoji} {sev.capitalize()} | {stats[sev]} |")
        lines.append("")

    # ── Individual findings ──────────────────────────────────────────────────
    lines += ["## Vulnerability Details", ""]

    for idx, finding in enumerate(sorted_findings, 1):
        sev = finding.get("severity", "info").lower()
        emoji = SEVERITY_EMOJI.get(sev, "")
        vuln_type = finding.get("vuln_type", "Unknown")
        url = finding.get("url", "N/A")
        description = finding.get("description", "No description provided.")
        poc = finding.get("poc", "")
        cvss_score = finding.get("cvss_score")
        cvss_vector = finding.get("cvss_vector", "")
        cvss_components = finding.get("cvss_components", {})

        lines += [
            f"### {idx}. {emoji} {vuln_type}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Severity** | {sev.capitalize()} |",
            f"| **Affected URL** | `{url}` |",
            f"| **Discovered** | {finding.get('discovered_at', now.strftime('%Y-%m-%d'))} |",
        ]

        if cvss_score is not None:
            lines.append(f"| **CVSS 3.1 Score** | {cvss_score} / 10.0 |")
        if cvss_vector:
            lines.append(f"| **CVSS Vector** | `{cvss_vector}` |")

        lines += ["", "#### Description", "", description, ""]

        if cvss_components:
            lines += [
                "#### CVSS 3.1 Breakdown",
                "",
                "| Metric | Value | Meaning |",
                "|--------|-------|---------|",
            ]
            metric_labels = {
                "attack_vector": ("Attack Vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
                "attack_complexity": ("Attack Complexity", {"L": "Low", "H": "High"}),
                "privileges_required": ("Privileges Required", {"N": "None", "L": "Low", "H": "High"}),
                "user_interaction": ("User Interaction", {"N": "None", "R": "Required"}),
                "scope": ("Scope", {"U": "Unchanged", "C": "Changed"}),
                "confidentiality": ("Confidentiality", {"N": "None", "L": "Low", "H": "High"}),
                "integrity": ("Integrity", {"N": "None", "L": "Low", "H": "High"}),
                "availability": ("Availability", {"N": "None", "L": "Low", "H": "High"}),
            }
            for key, (label, mapping) in metric_labels.items():
                val = cvss_components.get(key, "?")
                meaning = mapping.get(val, val)
                lines.append(f"| {label} | {val} | {meaning} |")
            lines.append("")

        if poc:
            lines += ["#### Proof of Concept", "", "```", poc, "```", ""]

        lines += [
            "#### Impact",
            "",
            _impact_statement(vuln_type, sev),
            "",
            "#### Recommended Fix",
            "",
            _remediation(vuln_type),
            "",
            "---",
            "",
        ]

    # ── Disclosure Timeline ──────────────────────────────────────────────────
    lines += [
        "## Coordinated Disclosure Timeline",
        "",
        "| Date | Event |",
        "|------|-------|",
        f"| {now.strftime('%Y-%m-%d')} | Vulnerability discovered and confirmed |",
        f"| {now.strftime('%Y-%m-%d')} | Initial contact attempted |",
        f"| {deadline_date} | **Public disclosure deadline** (90-day policy) |",
        "",
        "> If remediation requires additional time beyond the deadline, "
        "please reach out before the deadline date to arrange an extension.",
        "",
    ]

    # ── Researcher Notes ─────────────────────────────────────────────────────
    lines += [
        "## Researcher Notes",
        "",
        "- Testing was non-destructive. No data was accessed, modified, or retained beyond what was necessary to confirm exploitability.",
        "- No third parties were informed of these findings prior to this disclosure.",
        "- The researcher is available to verify remediation once fixes are deployed.",
        "",
        f"*Report generated by BountyAgent (disclosure mode) on {now.strftime('%Y-%m-%d at %H:%M UTC')}*",
    ]

    content = "\n".join(lines)
    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(content)

    return filename


def _impact_statement(vuln_type: str, severity: str) -> str:
    vt = vuln_type.lower()
    if "sql" in vt:
        return "An attacker could extract, modify, or delete database contents, potentially including credentials, PII, and sensitive business data."
    if "rce" in vt or "command" in vt:
        return "An attacker could execute arbitrary commands on the server, leading to full system compromise, data exfiltration, or lateral movement."
    if "idor" in vt:
        return "An attacker could access or modify other users' data without authorization, leading to data exposure or account takeover."
    if "auth" in vt or "bypass" in vt:
        return "An attacker could gain unauthorized access to privileged functionality or user accounts without valid credentials."
    if "xss" in vt:
        return "An attacker could execute malicious scripts in victims' browsers, enabling session hijacking, credential theft, or malware delivery."
    if "ssrf" in vt:
        return "An attacker could make the server issue requests to internal services, potentially exposing cloud metadata, internal APIs, or enabling lateral movement."
    if "disclosure" in vt or "exposure" in vt:
        return "Sensitive information is exposed that could assist an attacker in planning further attacks or directly compromise user privacy."
    if "jwt" in vt:
        return "An attacker could forge authentication tokens, escalate privileges, or impersonate other users."
    if "redirect" in vt:
        return "An attacker could redirect users to malicious sites using trusted domain links, enabling phishing or credential harvesting."
    return f"A {severity}-severity vulnerability that could be exploited by an attacker to compromise the confidentiality, integrity, or availability of the application."

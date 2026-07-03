"""
Responsible disclosure utilities:
  - CVSS v3.1 base score calculator
  - Security contact discovery (security.txt, common emails, HackerOne/Bugcrowd)
  - Professional outreach email drafter
"""

import math
import re
import subprocess
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests


# ── CVSS v3.1 ────────────────────────────────────────────────────────────────

_AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC  = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # Scope Changed
_UI  = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}


def _roundup(x: float) -> float:
    """CVSS v3.1 round-up to nearest 0.1."""
    return math.ceil(x * 10) / 10


def calculate_cvss(
    attack_vector: str = "N",
    attack_complexity: str = "L",
    privileges_required: str = "N",
    user_interaction: str = "N",
    scope: str = "U",
    confidentiality: str = "N",
    integrity: str = "N",
    availability: str = "N",
) -> Dict[str, Any]:
    """
    Calculate CVSS v3.1 Base Score.

    Metric abbreviations:
      attack_vector        : N (Network) | A (Adjacent) | L (Local) | P (Physical)
      attack_complexity    : L (Low) | H (High)
      privileges_required  : N (None) | L (Low) | H (High)
      user_interaction     : N (None) | R (Required)
      scope                : U (Unchanged) | C (Changed)
      confidentiality      : N (None) | L (Low) | H (High)
      integrity            : N (None) | L (Low) | H (High)
      availability         : N (None) | L (Low) | H (High)
    """
    av = attack_vector.upper()
    ac = attack_complexity.upper()
    pr = privileges_required.upper()
    ui = user_interaction.upper()
    s  = scope.upper()
    c  = confidentiality.upper()
    i  = integrity.upper()
    a  = availability.upper()

    av_v  = _AV.get(av, 0.85)
    ac_v  = _AC.get(ac, 0.77)
    pr_v  = (_PR_C if s == "C" else _PR_U).get(pr, 0.85)
    ui_v  = _UI.get(ui, 0.85)
    c_v   = _CIA.get(c, 0.0)
    i_v   = _CIA.get(i, 0.0)
    a_v   = _CIA.get(a, 0.0)

    iss = 1 - (1 - c_v) * (1 - i_v) * (1 - a_v)

    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av_v * ac_v * pr_v * ui_v

    if impact <= 0:
        base_score = 0.0
    elif s == "U":
        base_score = _roundup(min(impact + exploitability, 10))
    else:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10))

    if base_score == 0.0:
        rating = "None"
    elif base_score < 4.0:
        rating = "Low"
    elif base_score < 7.0:
        rating = "Medium"
    elif base_score < 9.0:
        rating = "High"
    else:
        rating = "Critical"

    vector = (
        f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}"
        f"/S:{s}/C:{c}/I:{i}/A:{a}"
    )

    return {
        "base_score": round(base_score, 1),
        "rating": rating,
        "vector": vector,
        "components": {
            "attack_vector": av,
            "attack_complexity": ac,
            "privileges_required": pr,
            "user_interaction": ui,
            "scope": s,
            "confidentiality": c,
            "integrity": i,
            "availability": a,
        },
    }


# ── Security contact discovery ────────────────────────────────────────────────

_COMMON_EMAIL_PATTERNS = [
    "security@{root}",
    "psirt@{root}",
    "infosec@{root}",
    "abuse@{root}",
    "bugbounty@{root}",
    "responsible-disclosure@{root}",
    "vulnerabilities@{root}",
    "disclosure@{root}",
    "security@{domain}",
]

_PLATFORM_CHECKS = [
    ("HackerOne",  "https://hackerone.com/{slug}"),
    ("Bugcrowd",   "https://bugcrowd.com/{slug}"),
    ("Intigriti",  "https://www.intigriti.com/programs/{slug}"),
    ("YesWeHack",  "https://yeswehack.com/programs/{slug}"),
]


def find_security_contact(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Discover security contact info for a domain.

    Checks (in order):
      1. /.well-known/security.txt  (RFC 9116)
      2. /security.txt
      3. Common security email patterns
      4. Public bug bounty platform profiles
      5. DNS TXT records for hints
    """
    root = _root_domain(domain)
    slug = root.split(".")[0]

    result: Dict[str, Any] = {
        "domain": domain,
        "root_domain": root,
        "security_txt": None,
        "emails": [],
        "platform_programs": [],
        "dns_hints": [],
        "recommended_contact": None,
        "has_formal_program": False,
    }

    # 1 & 2 — security.txt
    sec_txt = _fetch_security_txt(domain, timeout)
    if sec_txt:
        result["security_txt"] = sec_txt
        for match in re.findall(r"(?i)^Contact:\s*(.+)", sec_txt["content"], re.MULTILINE):
            val = match.strip()
            if val.startswith("mailto:"):
                result["emails"].insert(0, val[7:])
            elif val.startswith("http"):
                result["platform_programs"].append({"url": val, "source": "security.txt"})
            elif "@" in val:
                result["emails"].insert(0, val)

    # 3 — Common emails
    for pattern in _COMMON_EMAIL_PATTERNS:
        email = pattern.format(domain=domain, root=root)
        if email not in result["emails"]:
            result["emails"].append(email)

    # 4 — Platform lookups (HEAD request only, no auth needed)
    session = requests.Session()
    session.headers["User-Agent"] = "security-researcher-contact-lookup/1.0"
    for platform, url_tpl in _PLATFORM_CHECKS:
        url = url_tpl.format(slug=slug)
        try:
            r = session.head(url, timeout=timeout, allow_redirects=True)
            if r.status_code == 200:
                result["platform_programs"].append({"platform": platform, "url": url})
                result["has_formal_program"] = True
        except requests.RequestException:
            continue

    # 5 — DNS TXT records
    try:
        proc = subprocess.run(
            ["dig", "+short", "TXT", root],
            capture_output=True, text=True, timeout=10,
        )
        for line in proc.stdout.splitlines():
            clean = line.strip().strip('"')
            if any(kw in clean.lower() for kw in ("security", "abuse", "contact", "vuln", "report")):
                result["dns_hints"].append(clean)
    except Exception:
        pass

    # Recommend best contact
    if result["platform_programs"] and result["has_formal_program"]:
        result["recommended_contact"] = result["platform_programs"][0]["url"]
    elif result["emails"]:
        result["recommended_contact"] = result["emails"][0]

    return result


# ── Outreach email ────────────────────────────────────────────────────────────

def draft_outreach_email(
    target: str,
    vuln_summary: str,
    severity: str,
    cvss_score: float,
    contact: str,
    researcher_name: str = "Security Researcher",
    deadline_days: int = 90,
) -> Dict[str, str]:
    """
    Draft a professional responsible disclosure outreach email.

    Returns {"to", "subject", "body"} — does NOT send.
    The researcher reviews and sends manually.
    """
    root = _root_domain(target)
    company = root.split(".")[0].capitalize()
    subject = f"[Responsible Disclosure] Security Vulnerability in {target}"

    body = f"""\
To: {contact}
Subject: {subject}

Dear {company} Security Team,

I'm writing to report a security vulnerability I identified in {target} during
independent security research. I follow responsible disclosure practices and have
not shared this information with any third party.

─── Finding Summary ───────────────────────────────────────────

{vuln_summary}

Severity : {severity.upper()}
CVSS 3.1 : {cvss_score} / 10.0

───────────────────────────────────────────────────────────────

I have a full technical report with proof-of-concept steps ready to share through
a secure channel of your choice. I have not exploited this beyond confirming its
existence and have not accessed, retained, or exfiltrated any user data.

My commitments under this disclosure:
  • No public disclosure for {deadline_days} days from this email
  • Full cooperation with your remediation timeline
  • Re-test and confirm the fix once deployed

Requested from your team:
  1. Acknowledgement of this report within 5 business days
  2. Estimated remediation timeline
  3. Notification when the fix is live

If you operate a bug bounty program on HackerOne, Bugcrowd, or a similar platform,
please share the link and I will re-submit through the official channel.

I look forward to resolving this together.

Regards,
{researcher_name}

─── Disclosure Policy ─────────────────────────────────────────
This disclosure follows the industry-standard {deadline_days}-day coordinated
disclosure policy. If additional time is needed, please reach out before the
deadline to arrange an extension.
"""

    return {
        "to": contact,
        "subject": subject,
        "body": body.strip(),
        "deadline_days": deadline_days,
        "note": (
            "REVIEW BEFORE SENDING — verify contact address, fill in researcher_name, "
            "attach the disclosure report PDF/Markdown."
        ),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _root_domain(domain: str) -> str:
    parsed = urlparse(domain if "://" in domain else f"https://{domain}")
    host = (parsed.netloc or parsed.path).split(":")[0]
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _fetch_security_txt(domain: str, timeout: int) -> Optional[Dict]:
    candidates = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt",
        f"http://{domain}/.well-known/security.txt",
    ]
    for url in candidates:
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code == 200 and len(r.text) > 15:
                return {"url": url, "content": r.text[:3000], "found": True}
        except requests.RequestException:
            continue
    return None

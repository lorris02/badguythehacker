"""
OSINT tools: GitHub dorking, Google dorking, cert transparency, Wayback Machine,
leaked credential search, WHOIS, paste search.
"""

import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

import requests

TIMEOUT = 15
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def _get(url: str, headers: Optional[Dict] = None, params: Optional[Dict] = None) -> Optional[requests.Response]:
    try:
        h = {"User-Agent": UA}
        if headers:
            h.update(headers)
        r = requests.get(url, headers=h, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        return r
    except Exception:
        return None


# ── Certificate Transparency ──────────────────────────────────────────────────

def certsh_search(domain: str) -> Dict[str, Any]:
    """
    Query crt.sh for certificate transparency logs.
    Finds subdomains the target has ever had a TLS cert for — often reveals
    staging, internal, and forgotten assets.
    """
    r = _get(f"https://crt.sh/?q=%.{domain}&output=json")
    if not r:
        return {"error": "crt.sh unreachable", "domain": domain}

    try:
        entries = r.json()
    except Exception:
        return {"error": "Invalid JSON from crt.sh", "domain": domain}

    subdomains = set()
    wildcards = set()
    interesting = []

    for entry in entries:
        name = entry.get("name_value", "")
        for sub in name.splitlines():
            sub = sub.strip().lower()
            if sub.startswith("*."):
                wildcards.add(sub)
                sub = sub[2:]
            if domain in sub and sub != domain:
                subdomains.add(sub)
                for kw in ["dev", "stage", "staging", "internal", "admin", "api",
                            "test", "uat", "qa", "vpn", "jenkins", "jira", "git",
                            "confluence", "old", "legacy", "beta", "corp"]:
                    if kw in sub:
                        interesting.append(sub)
                        break

    return {
        "domain": domain,
        "subdomains": sorted(subdomains),
        "count": len(subdomains),
        "wildcards": sorted(wildcards),
        "interesting": list(set(interesting)),
        "note": "These are historical — not all may be live. Feed to httpx_probe.",
    }


# ── Wayback Machine ───────────────────────────────────────────────────────────

def wayback_urls(domain: str, limit: int = 500) -> Dict[str, Any]:
    """
    Pull historical URLs from the Wayback Machine CDX API.
    Finds forgotten endpoints, old API versions, backup files, and deleted pages.
    """
    r = _get(
        "http://web.archive.org/cdx/search/cdx",
        params={
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": limit,
            "filter": "statuscode:200",
        },
    )
    if not r:
        return {"error": "Wayback CDX API unreachable", "domain": domain}

    try:
        data = r.json()
    except Exception:
        return {"error": "Invalid response from Wayback", "domain": domain}

    urls = [row[0] for row in data[1:] if row]  # skip header row

    # Categorize URLs
    juicy = []
    for url in urls:
        url_lower = url.lower()
        for pattern in [".env", ".git", ".bak", ".sql", ".tar", ".zip", ".config",
                        "backup", "admin", "api/v1", "api/v2", "internal", "debug",
                        "phpinfo", "swagger", ".json", "token=", "key=", "password="]:
            if pattern in url_lower:
                juicy.append(url)
                break

    return {
        "domain": domain,
        "total_urls": len(urls),
        "sample": urls[:100],
        "juicy_endpoints": list(set(juicy))[:50],
        "note": "Juicy endpoints are historical — test for live access.",
    }


# ── GitHub Dorking ────────────────────────────────────────────────────────────

def github_dork(domain: str, dork_type: str = "all") -> Dict[str, Any]:
    """
    Search GitHub for accidentally committed secrets related to the target domain.
    Finds API keys, passwords, tokens, internal hostnames, config files.
    """
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    dorks = {
        "secrets": [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
            f'"{domain}" credentials',
        ],
        "config": [
            f'"{domain}" filename:.env',
            f'"{domain}" filename:config.yml',
            f'"{domain}" filename:settings.py',
            f'"{domain}" filename:database.yml',
            f'"{domain}" filename:.htpasswd',
        ],
        "code": [
            f'"{domain}" extension:sql',
            f'"{domain}" extension:pem',
            f'"{domain}" extension:key',
        ],
    }

    if dork_type != "all":
        dorks = {dork_type: dorks.get(dork_type, [])}

    all_results = []
    queries_run = 0

    for category, queries in dorks.items():
        for query in queries[:3]:  # limit to avoid rate limiting
            time.sleep(0.5)
            r = _get(
                "https://api.github.com/search/code",
                headers=headers,
                params={"q": query, "per_page": 5},
            )
            queries_run += 1
            if not r:
                continue
            try:
                data = r.json()
                for item in data.get("items", []):
                    all_results.append({
                        "category": category,
                        "query": query,
                        "repo": item.get("repository", {}).get("full_name", ""),
                        "file": item.get("path", ""),
                        "url": item.get("html_url", ""),
                        "last_modified": item.get("repository", {}).get("updated_at", ""),
                    })
            except Exception:
                continue

    return {
        "domain": domain,
        "results": all_results,
        "count": len(all_results),
        "queries_run": queries_run,
        "note": "Review each URL manually — false positives possible.",
        "auth": bool(token),
    }


# ── Google Dorking ────────────────────────────────────────────────────────────

def google_dork(domain: str, dork: str = "all") -> Dict[str, Any]:
    """
    Run Google dork queries via DuckDuckGo to find exposed files,
    admin panels, login pages, and sensitive information indexed by search engines.
    """
    base_dorks = {
        "files": [
            f"site:{domain} ext:sql OR ext:bak OR ext:log OR ext:env",
            f"site:{domain} ext:xml OR ext:json OR ext:yaml intitle:index",
            f"site:{domain} inurl:backup OR inurl:bak OR inurl:.old",
        ],
        "admin": [
            f"site:{domain} inurl:admin OR inurl:administrator OR inurl:wp-admin",
            f"site:{domain} inurl:login OR inurl:signin OR inurl:dashboard",
            f"site:{domain} intitle:\"index of\" OR intitle:\"directory listing\"",
        ],
        "sensitive": [
            f"site:{domain} \"api_key\" OR \"api key\" OR \"apikey\"",
            f"site:{domain} \"password\" filetype:log OR filetype:txt",
            f"site:{domain} inurl:phpinfo OR inurl:test.php OR inurl:info.php",
        ],
    }

    if dork != "all" and dork in base_dorks:
        queries = base_dorks[dork]
    else:
        queries = [q for qs in base_dorks.values() for q in qs]

    results = []
    for query in queries[:6]:
        time.sleep(1)
        r = _get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            headers={"User-Agent": UA},
        )
        if not r:
            continue

        # Extract results from DDG HTML
        urls = re.findall(r'class="result__url[^"]*"[^>]*>([^<]+)<', r.text)
        snippets = re.findall(r'class="result__snippet[^"]*"[^>]*>([^<]+)<', r.text)

        for url, snippet in zip(urls[:5], snippets[:5]):
            results.append({
                "query": query,
                "url": url.strip(),
                "snippet": snippet.strip()[:200],
            })

    return {
        "domain": domain,
        "results": results,
        "count": len(results),
        "note": "Manual verification needed — search engines may not index everything.",
    }


# ── WHOIS / IP Recon ─────────────────────────────────────────────────────────

def whois_lookup(domain: str) -> Dict[str, Any]:
    """
    WHOIS lookup to find registrant info, name servers, creation date.
    Useful for finding related domains, org names, and contact emails.
    """
    import subprocess
    stdout, _, rc = _run_cmd(["whois", domain], timeout=15)

    info = {
        "domain": domain,
        "registrar": "",
        "registrant_org": "",
        "registrant_email": "",
        "nameservers": [],
        "created": "",
        "expires": "",
        "related_domains_hint": [],
        "raw": stdout[:1500],
    }

    for line in stdout.splitlines():
        ll = line.lower()
        if "registrar:" in ll and not info["registrar"]:
            info["registrar"] = line.split(":", 1)[-1].strip()
        if "registrant organization:" in ll or "org:" in ll:
            info["registrant_org"] = line.split(":", 1)[-1].strip()
        if "registrant email:" in ll and "@" in line:
            info["registrant_email"] = line.split(":", 1)[-1].strip()
        if "name server:" in ll or "nserver:" in ll:
            ns = line.split(":", 1)[-1].strip().lower()
            if ns:
                info["nameservers"].append(ns)
        if "creation date:" in ll or "created:" in ll:
            info["created"] = line.split(":", 1)[-1].strip()[:30]
        if "expir" in ll and "date" in ll:
            info["expires"] = line.split(":", 1)[-1].strip()[:30]

    return info


def _run_cmd(cmd, timeout=30):
    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except Exception as e:
        return "", str(e), -1


# ── Paste / Leak Search ───────────────────────────────────────────────────────

def paste_search(domain: str) -> Dict[str, Any]:
    """
    Search paste sites and public leak indexes for the domain name.
    May surface leaked credentials, internal URLs, API keys.
    """
    results = []

    # IntelligenceX (free tier)
    r = _get(f"https://2.intelx.io/phonebook/search?term={domain}&maxresults=20&media=0&target=1")
    if r:
        try:
            data = r.json()
            for item in data.get("selectors", [])[:10]:
                results.append({
                    "source": "IntelligenceX",
                    "value": item.get("selectorvalue", ""),
                    "type": item.get("selectortype", ""),
                })
        except Exception:
            pass

    # GreyNoise (community API — no key needed)
    r = _get(f"https://api.greynoise.io/v3/community/{domain}")
    greynoise = {}
    if r:
        try:
            greynoise = r.json()
        except Exception:
            pass

    # HaveIBeenPwned domain search
    hibp_token = os.environ.get("HIBP_API_KEY", "")
    breaches = []
    if hibp_token:
        r = _get(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
            headers={"hibp-api-key": hibp_token},
        )
        if r:
            try:
                breaches = r.json()
            except Exception:
                pass

    return {
        "domain": domain,
        "paste_results": results,
        "greynoise": greynoise,
        "breached_accounts": breaches[:20] if breaches else [],
        "breach_count": len(breaches),
        "note": "Add HIBP_API_KEY to .env for full breach data.",
    }

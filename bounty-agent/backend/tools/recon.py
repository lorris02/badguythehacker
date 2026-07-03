"""Passive and semi-passive reconnaissance tools: subfinder, httpx, shodan."""

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# Prefer binaries from tools/bin/ over system PATH
_BIN_DIR = Path(__file__).parent / "bin"


def _bin(name: str) -> str:
    """Return full path to a tool binary, preferring tools/bin/."""
    local = _BIN_DIR / (name + (".exe" if os.name == "nt" else ""))
    if local.exists():
        return str(local)
    found = shutil.which(name)
    return found or name


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(cmd: List[str], timeout: int = 180) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]} — install it or update tool_paths in config.yaml", -1
    except Exception as e:
        return "", str(e), -1


def _parse_ndjson(text: str) -> List[Dict]:
    """Parse newline-delimited JSON, skipping bad lines."""
    results = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def _is_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------

def run_subfinder(domain: str, binary: str = None) -> Dict[str, Any]:
    """Enumerate subdomains using subfinder. Returns list of discovered hosts."""
    cmd = [_bin(binary or "subfinder"), "-d", domain, "-oJ", "-silent", "-all"]
    stdout, stderr, rc = _run(cmd, timeout=300)

    if rc == -1:
        return {"error": stderr, "domain": domain, "subdomains": [], "count": 0}

    subdomains: List[str] = []
    for record in _parse_ndjson(stdout):
        host = record.get("host", "").strip()
        if host:
            subdomains.append(host)

    # Fallback: some versions output plain text
    if not subdomains:
        for line in stdout.strip().splitlines():
            line = line.strip()
            if line and "." in line:
                subdomains.append(line)

    unique = sorted(set(subdomains))
    return {
        "domain": domain,
        "subdomains": unique,
        "count": len(unique),
    }


# ---------------------------------------------------------------------------
# httpx
# ---------------------------------------------------------------------------

def run_httpx(hosts: List[str], binary: str = None) -> Dict[str, Any]:
    """Probe a list of hosts/URLs with httpx. Returns alive host details."""
    if not hosts:
        return {"error": "No hosts provided", "alive_hosts": [], "alive_count": 0}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts))
        tmp = f.name

    try:
        cmd = [
            _bin(binary or "httpx"), "-l", tmp,
            "-json", "-silent",
            "-title",
            "-tech-detect",
            "-status-code",
            "-follow-redirects",
            "-content-length",
            "-web-server",
            "-ip",
            "-timeout", "10",
            "-threads", "50",
        ]
        stdout, stderr, rc = _run(cmd, timeout=600)
    finally:
        os.unlink(tmp)

    if rc == -1:
        return {"error": stderr, "alive_hosts": [], "alive_count": 0}

    alive: List[Dict] = []
    for record in _parse_ndjson(stdout):
        alive.append({
            "url": record.get("url", ""),
            "status_code": record.get("status-code", 0),
            "title": record.get("title", ""),
            "technologies": record.get("tech", []),
            "content_length": record.get("content-length", 0),
            "webserver": record.get("webserver", ""),
            "ip": record.get("host", ""),
            "port": str(record.get("port", "")),
            "scheme": record.get("scheme", ""),
            "location": record.get("location", ""),
        })

    return {
        "total_probed": len(hosts),
        "alive_count": len(alive),
        "alive_hosts": alive,
    }


# ---------------------------------------------------------------------------
# shodan
# ---------------------------------------------------------------------------

def run_shodan(query: str, api_key: str) -> Dict[str, Any]:
    """Query Shodan for passive intel on a domain, IP, or search string."""
    if not api_key or api_key.startswith("YOUR_"):
        return {
            "error": "Shodan API key not configured. Set api_keys.shodan in config.yaml.",
            "results": [],
        }

    try:
        import shodan as shodan_lib
    except ImportError:
        return {"error": "shodan library not installed. Run: pip install shodan", "results": []}

    try:
        api = shodan_lib.Shodan(api_key)

        if _is_ip(query):
            host = api.host(query)
            return _format_shodan_host(host)

        # Domain or keyword search
        search_query = f"hostname:{query}" if "." in query and " " not in query else query
        results = api.search(search_query, limit=20)
        matches = []
        for m in results.get("matches", []):
            matches.append({
                "ip": m.get("ip_str", ""),
                "port": m.get("port", 0),
                "hostnames": m.get("hostnames", []),
                "org": m.get("org", ""),
                "os": m.get("os", ""),
                "service": m.get("_shodan", {}).get("module", ""),
                "banner": (m.get("data", "")[:400]).strip(),
                "vulns": list(m.get("vulns", {}).keys()),
                "tags": m.get("tags", []),
            })

        return {
            "query": query,
            "total_results": results.get("total", 0),
            "returned": len(matches),
            "results": matches,
        }

    except Exception as e:
        return {"error": str(e), "results": []}


def _format_shodan_host(host: Dict) -> Dict[str, Any]:
    services = []
    for svc in host.get("data", []):
        services.append({
            "port": svc.get("port", 0),
            "transport": svc.get("transport", "tcp"),
            "service": svc.get("_shodan", {}).get("module", ""),
            "banner": (svc.get("data", "")[:300]).strip(),
            "vulns": list(svc.get("vulns", {}).keys()),
            "cpe": svc.get("cpe", []),
        })

    return {
        "ip": host.get("ip_str", ""),
        "hostnames": host.get("hostnames", []),
        "org": host.get("org", ""),
        "country": host.get("country_name", ""),
        "os": host.get("os", ""),
        "ports": host.get("ports", []),
        "tags": host.get("tags", []),
        "vulns": list(host.get("vulns", {}).keys()),
        "last_update": host.get("last_update", ""),
        "services": services,
    }

"""
Network-layer attack tools: nmap, credential brute force, SMB enumeration, exploit search.
All designed for authorized penetration testing only.
"""

import json
import re
import subprocess
import tempfile
import os
from typing import Any, Dict, List, Optional


DEFAULT_CREDS = {
    "ssh":   [("root","root"),("admin","admin"),("root","toor"),("admin","password"),
               ("ubuntu","ubuntu"),("pi","raspberry"),("root",""),("admin","1234")],
    "ftp":   [("anonymous",""),("ftp","ftp"),("admin","admin"),("root","root"),("guest","guest")],
    "telnet":[("admin","admin"),("root","root"),("root",""),("admin","1234")],
    "mysql": [("root",""),("root","root"),("admin","admin"),("mysql","mysql")],
    "mssql": [("sa",""),("sa","sa"),("sa","password"),("admin","admin")],
    "rdp":   [("administrator",""),("administrator","admin"),("admin","admin"),("guest","")],
    "smb":   [("administrator",""),("admin","admin"),("guest",""),("root","root")],
    "http":  [("admin","admin"),("admin","password"),("admin","1234"),("root","root"),
               ("administrator","administrator"),("user","user"),("guest","guest")],
    "snmp":  [("public",""),("private",""),("community","")],
    "vnc":   [("",""),("admin",""),("root","")],
    "postgres":[("postgres",""),("postgres","postgres"),("admin","admin")],
    "redis": [("",""),("default",""),("admin","")],
}


def _run(cmd: List[str], timeout: int = 300) -> tuple:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", -1
    except Exception as e:
        return "", str(e), -1


def nmap_scan(
    target: str,
    ports: str = "top1000",
    scan_type: str = "full",
    timeout: int = 300,
) -> Dict[str, Any]:
    """
    Full nmap scan: port discovery, service version detection, OS guessing, vuln scripts.
    scan_type: 'fast' | 'full' | 'vuln' | 'stealth'
    ports: 'top1000' | 'all' | '22,80,443,8080,...'
    """
    cmd = ["nmap", "-sV", "--open", "-T4", "-n"]

    if scan_type == "stealth":
        cmd = ["nmap", "-sS", "-sV", "--open", "-T3", "-n"]
    elif scan_type == "vuln":
        cmd += ["--script", "vuln,exploit,auth,default"]
    elif scan_type == "full":
        cmd += ["--script", "default,banner,http-title,ssl-cert,http-headers,ssh-hostkey"]
    elif scan_type == "fast":
        cmd = ["nmap", "-sV", "--open", "-T5", "-n", "-F"]

    if ports == "top1000":
        cmd += ["--top-ports", "1000"]
    elif ports == "all":
        cmd += ["-p-"]
    else:
        cmd += ["-p", ports]

    # OS detection
    cmd += ["-O", "--osscan-guess"]
    cmd += ["-oX", "-"]  # XML output for parsing
    cmd.append(target)

    stdout, stderr, rc = _run(cmd, timeout=timeout)

    # Parse XML output
    open_ports = []
    services = []
    os_guess = ""

    # Extract ports
    for m in re.finditer(r'<port protocol="(\w+)" portid="(\d+)".*?<state state="open".*?<service name="([^"]*)"[^>]*(?:product="([^"]*)")?[^>]*(?:version="([^"]*)")?', stdout, re.DOTALL):
        port_info = {
            "protocol": m.group(1),
            "port": int(m.group(2)),
            "service": m.group(3),
            "product": m.group(4) or "",
            "version": m.group(5) or "",
        }
        open_ports.append(port_info)
        services.append(f"{m.group(3)} {m.group(4) or ''} {m.group(5) or ''}".strip())

    # Extract OS
    os_match = re.search(r'<osmatch name="([^"]+)"', stdout)
    if os_match:
        os_guess = os_match.group(1)

    # Extract script output (vuln findings)
    script_findings = []
    for m in re.finditer(r'<script id="([^"]+)" output="([^"]+)"', stdout):
        script_id = m.group(1)
        output = m.group(2)
        if any(kw in output.lower() for kw in ["vulnerable", "cvss", "exploit", "cve-"]):
            script_findings.append({"script": script_id, "output": output[:500]})

    if not open_ports and not stdout:
        return {"error": stderr or "No output from nmap", "target": target}

    return {
        "target": target,
        "open_ports": open_ports,
        "port_count": len(open_ports),
        "services": list(set(services)),
        "os_guess": os_guess,
        "script_findings": script_findings,
        "attack_surface": _assess_attack_surface(open_ports),
        "raw_summary": _extract_nmap_summary(stdout),
    }


def _assess_attack_surface(ports: List[Dict]) -> List[str]:
    """Map open ports to potential attack vectors."""
    surface = []
    port_map = {p["port"]: p["service"] for p in ports}

    interesting = {
        21: "FTP - try anonymous login + credential brute force",
        22: "SSH - credential brute force + key-based auth check",
        23: "Telnet - plaintext protocol, credential brute force",
        25: "SMTP - open relay check, user enumeration",
        53: "DNS - zone transfer, subdomain brute force",
        80: "HTTP - full web attack surface",
        110: "POP3 - credential brute force",
        111: "RPC - nmap RPC scan, NFS mounts",
        135: "MS-RPC - Windows attack surface",
        139: "NetBIOS - SMB enumeration",
        143: "IMAP - credential brute force",
        443: "HTTPS - full web attack surface + SSL cert recon",
        445: "SMB - EternalBlue check, enum shares, credential attacks",
        1433: "MSSQL - SA blank password, xp_cmdshell",
        1521: "Oracle DB - default credentials",
        2049: "NFS - check for world-readable exports",
        3306: "MySQL - root blank password, credential brute force",
        3389: "RDP - credential brute force, BlueKeep check",
        5432: "PostgreSQL - credential brute force",
        5900: "VNC - no-auth check, credential brute force",
        6379: "Redis - no-auth check, config write exploit",
        8080: "HTTP-alt - web attack surface, admin panels",
        8443: "HTTPS-alt - web attack surface",
        9200: "Elasticsearch - unauthenticated access check",
        27017: "MongoDB - no-auth check",
    }

    for port, service in port_map.items():
        if port in interesting:
            surface.append(f"Port {port} ({service}): {interesting[port]}")

    return surface


def _extract_nmap_summary(xml_output: str) -> str:
    """Pull readable summary from nmap XML."""
    lines = []
    for m in re.finditer(r'<port protocol="\w+" portid="(\d+)".*?state="open".*?<service name="([^"]*)"[^>]*(?:product="([^"]*)")?[^>]*(?:version="([^"]*)")?', xml_output, re.DOTALL):
        svc = f"{m.group(2)} {m.group(3) or ''} {m.group(4) or ''}".strip()
        lines.append(f"{m.group(1)}/open/{svc}")
    return "\n".join(lines[:50])


def credential_bruteforce(
    target: str,
    service: str,
    port: int,
    userlist: Optional[str] = None,
    passlist: Optional[str] = None,
    timeout: int = 300,
) -> Dict[str, Any]:
    """
    Brute force credentials on SSH, FTP, RDP, SMB, HTTP-form, MySQL, etc. using hydra.
    Falls back to built-in default credential list if no wordlists provided.
    """
    service = service.lower().strip()

    # If no wordlists, try default creds first (fast and often works)
    if not userlist or not passlist:
        return default_creds_check(target, service, port)

    cmd = ["hydra", "-L", userlist, "-P", passlist, "-t", "4", "-f", "-q",
           f"{service}://{target}:{port}"]

    if service in ("http", "https", "http-form"):
        cmd = ["hydra", "-L", userlist, "-P", passlist, "-t", "4", "-f", "-q",
               f"{target}", "http-get", "/"]

    stdout, stderr, rc = _run(cmd, timeout=timeout)

    found = []
    for line in stdout.splitlines():
        if "login:" in line.lower() and "password:" in line.lower():
            found.append(line.strip())

    return {
        "target": target,
        "service": service,
        "port": port,
        "credentials_found": found,
        "vulnerable": len(found) > 0,
        "raw": stdout[:1000],
    }


def default_creds_check(
    target: str,
    service: str,
    port: int,
) -> Dict[str, Any]:
    """
    Try known default credentials for common services without external wordlists.
    Uses direct protocol connections where possible.
    """
    import socket
    import requests

    service = service.lower().strip()
    creds = DEFAULT_CREDS.get(service, DEFAULT_CREDS.get("http", []))
    found = []

    if service in ("http", "https", "http-form"):
        proto = "https" if service == "https" or port == 443 else "http"
        for user, pwd in creds:
            try:
                r = requests.get(
                    f"{proto}://{target}:{port}/",
                    auth=(user, pwd),
                    timeout=5,
                    verify=False,
                    allow_redirects=True,
                )
                if r.status_code not in (401, 403):
                    found.append({"user": user, "password": pwd, "status": r.status_code})
                    break
            except Exception:
                continue

    elif service == "redis":
        for user, pwd in creds:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((target, port))
                if pwd:
                    s.send(f"AUTH {pwd}\r\n".encode())
                else:
                    s.send(b"PING\r\n")
                resp = s.recv(64).decode(errors="ignore")
                s.close()
                if "+PONG" in resp or "+OK" in resp:
                    found.append({"user": user, "password": pwd, "note": "Redis accessible"})
                    break
            except Exception:
                continue

    elif service in ("ftp",):
        import ftplib
        for user, pwd in creds:
            try:
                ftp = ftplib.FTP()
                ftp.connect(target, port, timeout=5)
                ftp.login(user, pwd)
                found.append({"user": user, "password": pwd})
                ftp.quit()
                break
            except Exception:
                continue

    return {
        "target": target,
        "service": service,
        "port": port,
        "credentials_found": found,
        "vulnerable": len(found) > 0,
        "creds_tried": len(creds),
    }


def smb_enumerate(target: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Enumerate SMB: null session, shares, users, OS, domain info.
    Uses smbclient and nmap SMB scripts.
    """
    results = {"target": target, "shares": [], "users": [], "os_info": "", "null_session": False, "findings": []}

    # Try null session share listing
    stdout, _, rc = _run(["smbclient", "-L", target, "-N", "--option=client min protocol=NT1"], timeout=30)
    if rc == 0 and "Sharename" in stdout:
        results["null_session"] = True
        results["findings"].append("NULL SESSION: SMB null session allowed — unauthenticated enumeration possible")
        for line in stdout.splitlines():
            if re.match(r"\s+\w+\s+Disk", line) or re.match(r"\s+\w+\s+IPC", line):
                share = line.strip().split()[0]
                results["shares"].append(share)

    # nmap SMB scripts
    nmap_out, _, _ = _run([
        "nmap", "-p", "445,139", "--script",
        "smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln-ms17-010,smb-security-mode",
        "-T4", "-n", target
    ], timeout=60)

    if "VULNERABLE" in nmap_out or "vulnerable" in nmap_out:
        results["findings"].append("CRITICAL: SMB vulnerability detected (possibly MS17-010/EternalBlue)")

    os_match = re.search(r"OS: (.+)", nmap_out)
    if os_match:
        results["os_info"] = os_match.group(1).strip()

    for line in nmap_out.splitlines():
        if "\\\\$" in line or "ADMIN$" in line or "C$" in line or "IPC$" in line:
            results["shares"].append(line.strip())

    results["raw_nmap"] = nmap_out[:1000]
    return results


def exploit_search(query: str, limit: int = 10) -> Dict[str, Any]:
    """
    Search exploit-db via searchsploit for known exploits matching service/version.
    Also checks for Metasploit modules.
    """
    stdout, stderr, rc = _run(["searchsploit", "--json", query], timeout=30)

    if rc != 0 or not stdout:
        # Try without --json flag (older versions)
        stdout, stderr, rc = _run(["searchsploit", query], timeout=30)
        exploits = []
        for line in stdout.splitlines():
            if "|" in line and "EDB-ID" not in line and "---" not in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    exploits.append({
                        "title": parts[0].strip(),
                        "path": parts[1].strip() if len(parts) > 1 else "",
                        "type": "unknown",
                    })
        return {
            "query": query,
            "exploits": exploits[:limit],
            "count": len(exploits),
            "has_metasploit": any("Metasploit" in e.get("title","") for e in exploits),
        }

    try:
        data = json.loads(stdout)
        exploits = []
        for item in data.get("RESULTS_EXPLOIT", [])[:limit]:
            exploits.append({
                "title": item.get("Title", ""),
                "edb_id": item.get("EDB-ID", ""),
                "type": item.get("Type", ""),
                "platform": item.get("Platform", ""),
                "date": item.get("Date_Published", ""),
                "path": item.get("Path", ""),
            })
        msf = data.get("RESULTS_SHELLCODE", []) + [e for e in exploits if "Metasploit" in e.get("title","")]
        return {
            "query": query,
            "exploits": exploits,
            "count": len(exploits),
            "has_metasploit": len(msf) > 0,
            "metasploit_modules": [e["title"] for e in exploits if "Metasploit" in e.get("title","")],
        }
    except json.JSONDecodeError:
        return {"query": query, "error": "Could not parse searchsploit output", "raw": stdout[:500]}


def ssh_audit(target: str, port: int = 22) -> Dict[str, Any]:
    """
    Audit SSH configuration: weak algorithms, version, host key issues.
    """
    stdout, stderr, rc = _run(
        ["nmap", "-p", str(port), "--script", "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods",
         "-sV", "-n", target],
        timeout=60,
    )

    findings = []
    weak_algos = ["arcfour", "blowfish", "3des", "rc4", "md5", "sha1-96"]
    for algo in weak_algos:
        if algo in stdout.lower():
            findings.append(f"Weak algorithm detected: {algo}")

    version_match = re.search(r"SSH-[\d.]+-(\S+)", stdout)
    version = version_match.group(1) if version_match else "unknown"

    if "OpenSSH_7" in stdout or "OpenSSH_6" in stdout or "OpenSSH_5" in stdout:
        findings.append(f"Potentially outdated OpenSSH version — check for known CVEs")

    return {
        "target": target,
        "port": port,
        "version": version,
        "weak_algorithms": [a for a in weak_algos if a in stdout.lower()],
        "auth_methods": re.findall(r"Supported methods: (.+)", stdout),
        "findings": findings,
        "raw": stdout[:800],
    }

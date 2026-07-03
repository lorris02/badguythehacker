"""Active scanning tools: nuclei and ffuf."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

_BIN_DIR = Path(__file__).parent / "bin"

def _bin(name: str) -> str:
    local = _BIN_DIR / (name + (".exe" if os.name == "nt" else ""))
    if local.exists():
        return str(local)
    return shutil.which(name) or name


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(cmd: List[str], timeout: int = 300) -> tuple[str, str, int]:
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
        return "", f"Tool not found: {cmd[0]} — install or update tool_paths in config.yaml", -1
    except Exception as e:
        return "", str(e), -1


def _parse_ndjson(text: str) -> List[Dict]:
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


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------

def run_nuclei(
    targets: List[str],
    binary: str = None,
    templates: str = "",
    severity: str = "low",
    template_dir: str = "",
) -> Dict[str, Any]:
    """
    Run nuclei against targets. Returns structured vulnerability findings.

    templates: comma-separated nuclei tags (e.g. 'cves,exposures,misconfigs')
               or a path to a specific template/directory.
    severity:  minimum severity — info|low|medium|high|critical
    """
    if not targets:
        return {"error": "No targets provided", "findings": []}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp = f.name

    try:
        cmd = [
            _bin(binary or "nuclei"),
            "-l", tmp,
            "-json",
            "-silent",
            "-severity", severity,
            "-retries", "2",
            "-timeout", "10",
            "-rate-limit", "150",
        ]

        if templates:
            # Detect if it's a file path or a tag list
            if os.path.exists(templates):
                cmd += ["-t", templates]
            else:
                cmd += ["-tags", templates]
        elif template_dir and os.path.isdir(template_dir):
            cmd += ["-t", template_dir]
        # Otherwise nuclei uses its default template directory

        stdout, stderr, rc = _run(cmd, timeout=900)
    finally:
        os.unlink(tmp)

    if rc == -1:
        return {"error": stderr, "findings": []}

    findings = []
    for record in _parse_ndjson(stdout):
        info = record.get("info", {})
        finding = {
            "template_id": record.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": info.get("severity", ""),
            "description": info.get("description", ""),
            "tags": info.get("tags", []),
            "matched_at": record.get("matched-at", ""),
            "url": record.get("host", ""),
            "type": record.get("type", ""),
            "extracted_results": record.get("extracted-results", []),
            "curl_command": record.get("curl-command", ""),
        }
        findings.append(finding)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

    return {
        "targets_scanned": len(targets),
        "findings_count": len(findings),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# ffuf
# ---------------------------------------------------------------------------

def run_ffuf(
    url: str,
    wordlist: str,
    binary: str = None,
    mode: str = "dirs",
    extensions: str = "",
    threads: int = 40,
) -> Dict[str, Any]:
    """
    Fuzz directories, parameters, or virtual hosts with ffuf.

    url:        Must contain FUZZ placeholder, e.g. https://example.com/FUZZ
    wordlist:   Path to wordlist file
    mode:       dirs | params | vhosts
    extensions: Comma-separated list, e.g. 'php,asp,html'
    """
    if not url or "FUZZ" not in url:
        return {
            "error": "URL must contain FUZZ placeholder. Example: https://example.com/FUZZ",
            "results": [],
        }

    if not wordlist or not os.path.exists(wordlist):
        return {
            "error": f"Wordlist not found: {wordlist}. Update settings.ffuf_wordlist in config.yaml.",
            "results": [],
        }

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_file = f.name

    try:
        cmd = [
            _bin(binary or "ffuf"),
            "-u", url,
            "-w", wordlist,
            "-o", out_file,
            "-of", "json",
            "-t", str(threads),
            "-timeout", "10",
            "-mc", "200,201,204,301,302,307,401,403,405,500",
            "-s",  # silent
        ]

        if extensions:
            cmd += ["-e", f".{extensions.replace(',', ',.')}"]

        if mode == "vhosts":
            # Replace FUZZ in Host header instead
            base_url = url.replace("FUZZ.", "").replace("FUZZ", "")
            cmd = [
                binary,
                "-u", base_url,
                "-w", wordlist,
                "-H", f"Host: FUZZ.{_extract_domain(url)}",
                "-o", out_file,
                "-of", "json",
                "-t", str(threads),
                "-timeout", "10",
                "-mc", "200,201,204,301,302,307,401,403",
                "-s",
            ]

        stdout, stderr, rc = _run(cmd, timeout=600)
    finally:
        pass  # we'll clean up after reading

    results = []
    try:
        if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
            with open(out_file) as fh:
                data = json.load(fh)
            for r in data.get("results", []):
                results.append({
                    "url": r.get("url", ""),
                    "status": r.get("status", 0),
                    "length": r.get("length", 0),
                    "words": r.get("words", 0),
                    "lines": r.get("lines", 0),
                    "input": r.get("input", {}).get("FUZZ", ""),
                    "redirect_location": r.get("redirectlocation", ""),
                })
    except (json.JSONDecodeError, IOError):
        pass
    finally:
        if os.path.exists(out_file):
            os.unlink(out_file)

    if rc == -1 and not results:
        return {"error": stderr, "results": []}

    # Sort: 200s first, then 30xs, then 40xs
    results.sort(key=lambda x: (x["status"] // 100 != 2, x["status"]))

    return {
        "url_pattern": url,
        "mode": mode,
        "total_found": len(results),
        "results": results,
    }


def _extract_domain(url: str) -> str:
    import re
    m = re.search(r"https?://([^/]+)", url)
    return m.group(1) if m else url

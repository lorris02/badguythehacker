"""
Auto-downloads security scanning tools into tools/bin/.
Runs automatically on backend startup if tools are missing.
Safe to re-run — skips already-installed tools.
"""

import os
import platform
import stat
import sys
import zipfile
import tarfile
import io
from pathlib import Path

import requests

BIN_DIR = Path(__file__).parent / "bin"
BIN_DIR.mkdir(exist_ok=True)

IS_WINDOWS = platform.system() == "Windows"
ARCH = "amd64" if platform.machine().lower() in ("x86_64", "amd64") else "arm64"
EXT = ".exe" if IS_WINDOWS else ""

_OS = "windows" if IS_WINDOWS else "linux"
_ZIP = "zip" if IS_WINDOWS else "tar.gz"

TOOLS = {
    "subfinder": {
        "repo": "projectdiscovery/subfinder",
        "asset_pattern": f"subfinder_{_OS}_{ARCH}.zip",
        "binary_in_zip": f"subfinder{EXT}",
    },
    "nuclei": {
        "repo": "projectdiscovery/nuclei",
        # actual asset: nuclei_3.x.x_windows_amd64.zip
        "asset_pattern": f"nuclei_*_{_OS}_{ARCH}.zip",
        "binary_in_zip": f"nuclei{EXT}",
    },
    "ffuf": {
        "repo": "ffuf/ffuf",
        # actual asset: ffuf_2.x.x_windows_amd64.zip
        "asset_pattern": f"ffuf_*_{_OS}_{ARCH}.{_ZIP}",
        "binary_in_zip": f"ffuf{EXT}",
    },
    "httpx": {
        "repo": "projectdiscovery/httpx",
        "asset_pattern": f"httpx_{_OS}_{ARCH}.zip",
        "binary_in_zip": f"httpx{EXT}",
    },
}

WORDLIST_PATH = BIN_DIR / "common.txt"
WORDLIST_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    "/Discovery/Web-Content/common.txt"
)


def _get_latest_release(repo: str) -> dict:
    r = requests.get(
        f"https://api.github.com/repos/{repo}/releases/latest",
        headers={"Accept": "application/vnd.github+json"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def _find_asset(assets: list, pattern: str, alt_pattern: str = None) -> dict | None:
    import fnmatch
    for asset in assets:
        name = asset["name"].lower()
        if fnmatch.fnmatch(name, pattern.lower()):
            return asset
    if alt_pattern:
        for asset in assets:
            name = asset["name"].lower()
            if fnmatch.fnmatch(name, alt_pattern.lower()):
                return asset
    # fallback: substring match
    pat_parts = pattern.lower().replace("*", "").split("_")
    for asset in assets:
        name = asset["name"].lower()
        if all(p in name for p in pat_parts if p):
            return asset
    return None


def _extract_binary(data: bytes, archive_name: str, binary_name: str) -> bytes | None:
    try:
        if archive_name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for member in zf.namelist():
                    if Path(member).name.lower() == binary_name.lower():
                        return zf.read(member)
        elif archive_name.endswith((".tar.gz", ".tgz")):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
                for member in tf.getmembers():
                    if Path(member.name).name.lower() == binary_name.lower():
                        f = tf.extractfile(member)
                        if f:
                            return f.read()
    except Exception as e:
        print(f"  extract error: {e}")
    return None


def install_tool(name: str, config: dict) -> bool:
    dest = BIN_DIR / f"{name}{EXT}"
    if dest.exists():
        print(f"  {name}: already installed OK")
        return True

    print(f"  {name}: downloading...", end="", flush=True)
    try:
        release = _get_latest_release(config["repo"])
        assets  = release.get("assets", [])
        asset   = _find_asset(assets, config["asset_pattern"], config.get("alt_pattern"))

        if not asset:
            print(f" FAIL — no matching release asset found (looked for: {config['asset_pattern']})")
            return False

        r = requests.get(asset["browser_download_url"], timeout=120, stream=True)
        r.raise_for_status()
        data = b"".join(r.iter_content(8192))

        binary_data = _extract_binary(data, asset["name"], config["binary_in_zip"])
        if not binary_data:
            print(f" FAIL — could not find {config['binary_in_zip']} inside {asset['name']}")
            return False

        dest.write_bytes(binary_data)
        if not IS_WINDOWS:
            dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

        print(f" OK ({len(binary_data) // 1024}KB)")
        return True

    except Exception as e:
        print(f" FAIL — {e}")
        return False


def install_sqlmap() -> bool:
    dest = BIN_DIR / "sqlmap"
    sqlmap_py = BIN_DIR / "sqlmap" / "sqlmap.py"
    if sqlmap_py.exists():
        print("  sqlmap: already installed OK")
        return True

    print("  sqlmap: cloning...", end="", flush=True)
    try:
        import subprocess
        result = subprocess.run(
            ["git", "clone", "--depth=1", "https://github.com/sqlmapproject/sqlmap.git",
             str(BIN_DIR / "sqlmap")],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            print(" OK")
            return True
        else:
            print(f" FAIL — {result.stderr[:100]}")
            return False
    except Exception as e:
        print(f" FAIL — {e}")
        return False


def install_wordlist() -> bool:
    if WORDLIST_PATH.exists() and WORDLIST_PATH.stat().st_size > 10_000:
        print("  wordlist: already installed OK")
        return True
    print("  wordlist: downloading common.txt...", end="", flush=True)
    try:
        r = requests.get(WORDLIST_URL, timeout=30)
        r.raise_for_status()
        WORDLIST_PATH.write_bytes(r.content)
        print(f" OK ({len(r.content) // 1024}KB)")
        return True
    except Exception as e:
        print(f" FAIL -- {e}")
        return False


def setup_all(quiet: bool = False) -> dict:
    results = {}
    if not quiet:
        print(f"Setting up scanning tools -> {BIN_DIR}")

    for name, config in TOOLS.items():
        results[name] = install_tool(name, config)

    results["sqlmap"] = install_sqlmap()
    results["wordlist"] = install_wordlist()

    installed = [k for k, v in results.items() if v]
    failed    = [k for k, v in results.items() if not v]

    if not quiet:
        print(f"\nInstalled: {', '.join(installed) or 'none'}")
        if failed:
            print(f"Failed:    {', '.join(failed)} (agents will work without them)")

    return results


def get_tool_path(name: str) -> str | None:
    """Return path to a tool binary, or None if not installed."""
    candidates = [
        BIN_DIR / f"{name}{EXT}",
        BIN_DIR / "sqlmap" / "sqlmap.py",  # sqlmap special case
    ]
    for c in candidates:
        if c.exists():
            return str(c)

    # Also check system PATH
    import shutil
    found = shutil.which(name)
    return found


def tools_status() -> dict:
    """Return install status of all tools — used by agents to self-report."""
    all_tools = list(TOOLS.keys()) + ["sqlmap"]
    return {t: get_tool_path(t) is not None for t in all_tools}


if __name__ == "__main__":
    setup_all()

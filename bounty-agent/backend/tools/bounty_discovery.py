"""
Bounty program discovery — queries every major source:
  Platforms  : HackerOne, Bugcrowd, Intigriti, Immunefi, YesWeHack,
               HackenProof, Open Bug Bounty
  Social     : Twitter/X (bearer token optional), DuckDuckGo news search
  Web3       : Immunefi (crypto/DeFi — often $100k-$1M+ rewards)
"""

import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

import requests

TIMEOUT = 15
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def _get(url, **kwargs) -> Optional[requests.Response]:
    try:
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA}, **kwargs)
        r.raise_for_status()
        return r
    except Exception:
        return None


# ── HackerOne ─────────────────────────────────────────────────────────────────

def discover_hackerone(limit: int = 30) -> List[Dict] | Dict:
    username  = os.environ.get("HACKERONE_USERNAME")
    api_token = os.environ.get("HACKERONE_API_TOKEN")

    if not (username and api_token):
        return {"error": "missing_keys", "platform": "hackerone",
                "message": "Add HACKERONE_USERNAME and HACKERONE_API_TOKEN to .env"}

    try:
        r = requests.get(
            "https://api.hackerone.com/v1/hackers/programs",
            auth=(username, api_token),
            params={"page[size]": min(limit, 100)},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        programs = []
        for prog in r.json().get("data", []):
            a = prog.get("attributes", {})
            slug = a.get("handle", "")
            if a.get("submission_state") != "open":
                continue
            scope = [s.get("asset_identifier","") for s in a.get("structured_scope",{}).get("in_scope",[])
                     if s.get("asset_type") in ("URL","DOMAIN","WILDCARD")]
            programs.append({
                "platform": "hackerone", "name": a.get("name", slug), "slug": slug,
                "url": f"https://hackerone.com/{slug}",
                "submit_url": f"https://hackerone.com/{slug}/reports/new",
                "min_bounty": a.get("min_bounty",{}).get("value"),
                "max_bounty": a.get("max_bounty",{}).get("value"),
                "currency": "USD", "scope": scope[:10],
            })
        return programs
    except Exception as e:
        return {"error": str(e), "platform": "hackerone"}


# ── Bugcrowd ──────────────────────────────────────────────────────────────────

def discover_bugcrowd(limit: int = 30) -> List[Dict] | Dict:
    try:
        r = _get("https://bugcrowd.com/programs")
        if not r:
            return {"error": "request_failed", "platform": "bugcrowd"}
        programs = []
        for eng in r.json().get("engagements", [])[:limit]:
            if eng.get("isPrivate") or eng.get("isDemo"):
                continue
            brief = eng.get("briefUrl", "")
            slug  = brief.lstrip("/engagements/") if brief else ""
            reward = eng.get("rewardSummary", {})
            def _parse_reward(s):
                if not s:
                    return None
                s = str(s).replace("$","").replace(",","").strip()
                try: return int(s.split("-")[0].strip())
                except: return None
            programs.append({
                "platform":   "bugcrowd",
                "name":       eng.get("name", slug),
                "slug":       slug,
                "url":        f"https://bugcrowd.com/engagements/{slug}",
                "submit_url": f"https://bugcrowd.com/engagements/{slug}/reports/new",
                "min_bounty": _parse_reward(reward.get("minReward")),
                "max_bounty": _parse_reward(reward.get("maxReward")),
                "currency":   "USD",
                "scope":      [],
            })
        return programs
    except Exception as e:
        return {"error": str(e), "platform": "bugcrowd"}


# ── Intigriti ─────────────────────────────────────────────────────────────────

def discover_intigriti(limit: int = 30) -> List[Dict] | Dict:
    try:
        # Try multiple known Intigriti API endpoints
        r = (_get("https://api.intigriti.com/core/public/programs") or
             _get("https://api.intigriti.com/api/core/public/programs") or
             _get("https://app.intigriti.com/api/core/public/programs"))
        if not r:
            return {"error": "request_failed", "platform": "intigriti"}
        data = r.json()
        records = data if isinstance(data, list) else data.get("records", [])
        programs = []
        for prog in records[:limit]:
            company = prog.get("companyHandle", "")
            handle  = prog.get("handle", "")
            scope   = [d.get("endpoint","") for d in prog.get("domains",[]) if d.get("type")=="url"]
            programs.append({
                "platform": "intigriti", "name": prog.get("name", handle), "slug": handle,
                "url": f"https://app.intigriti.com/programs/{company}/{handle}/detail",
                "submit_url": f"https://app.intigriti.com/researcher/submissions/{company}/{handle}/create",
                "min_bounty": prog.get("minBounty"),
                "max_bounty": prog.get("maxBounty"),
                "currency": "EUR", "scope": scope[:10],
            })
        return programs
    except Exception as e:
        return {"error": str(e), "platform": "intigriti"}


# ── Immunefi (Web3 / DeFi — huge rewards) ────────────────────────────────────

def discover_immunefi(limit: int = 30) -> List[Dict] | Dict:
    """
    Immunefi hosts crypto/DeFi bounties. Critical bugs often pay $100k-$1M+.
    No API key needed.
    """
    try:
        r = _get("https://immunefi.com/explore/", headers={"Accept": "application/json, text/html"})
        if not r:
            return {"error": "request_failed", "platform": "immunefi"}

        # Immunefi embeds JSON in a <script id="__NEXT_DATA__"> tag
        match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', r.text, re.DOTALL)
        if not match:
            return {"error": "parse_failed", "platform": "immunefi"}

        import json
        data = json.loads(match.group(1))
        bounties = (data.get("props",{}).get("pageProps",{}).get("bounties") or
                    data.get("props",{}).get("initialState",{}).get("bounties") or [])

        programs = []
        for b in bounties[:limit]:
            assets = b.get("assets", [])
            scope  = [a.get("url","") or a.get("target","") for a in assets[:10] if a.get("type") in ("smart_contract","websites_and_applications","")]
            max_b  = b.get("maxBounty") or b.get("maximumBountyUsd") or 0
            try:
                max_b = int(str(max_b).replace(",","").replace("$","").strip() or 0)
            except Exception:
                max_b = 0

            slug = b.get("slug","") or b.get("id","")
            programs.append({
                "platform":   "immunefi",
                "name":       b.get("project","") or b.get("name",""),
                "slug":       slug,
                "url":        f"https://immunefi.com/bounty/{slug}/",
                "submit_url": f"https://immunefi.com/bounty/{slug}/#top",
                "min_bounty": b.get("minBounty") or 0,
                "max_bounty": max_b,
                "currency":   "USD",
                "scope":      [s for s in scope if s],
                "category":   "web3",
            })
        # Sort by max reward
        programs.sort(key=lambda p: p.get("max_bounty") or 0, reverse=True)
        return programs
    except Exception as e:
        return {"error": str(e), "platform": "immunefi"}


# ── YesWeHack ─────────────────────────────────────────────────────────────────

def discover_yeswehack(limit: int = 30) -> List[Dict] | Dict:
    try:
        r = _get("https://api.yeswehack.com/programs", params={"page": 1, "nb_items_per_page": limit})
        if not r:
            return {"error": "request_failed", "platform": "yeswehack"}
        programs = []
        for prog in r.json().get("items", []):
            slug = prog.get("slug","")
            scope = [s.get("scope","") for s in prog.get("scopes",[])[:10] if s.get("scope_type") in ("web-application","ip-address","other")]
            programs.append({
                "platform":   "yeswehack",
                "name":       prog.get("title", slug),
                "slug":       slug,
                "url":        f"https://yeswehack.com/programs/{slug}",
                "submit_url": f"https://yeswehack.com/programs/{slug}/reports/new",
                "min_bounty": prog.get("bounty_reward_range","").split("-")[0].replace("$","").strip() if prog.get("bounty_reward_range") else None,
                "max_bounty": None,
                "currency":   "USD",
                "scope":      [s for s in scope if s],
            })
        return programs
    except Exception as e:
        return {"error": str(e), "platform": "yeswehack"}


# ── HackenProof ───────────────────────────────────────────────────────────────

def discover_hackenproof(limit: int = 30) -> List[Dict] | Dict:
    try:
        r = _get("https://hackenproof.com/api/public/programs", params={"perPage": limit})
        if not r:
            # Try alternate endpoint
            r = _get("https://hackenproof.com/programs.json")
        if not r:
            return {"error": "request_failed", "platform": "hackenproof"}
        data = r.json()
        items = data if isinstance(data, list) else data.get("data", data.get("programs", []))
        programs = []
        for prog in items[:limit]:
            slug = prog.get("slug","") or prog.get("code","")
            programs.append({
                "platform":   "hackenproof",
                "name":       prog.get("name","") or prog.get("title",""),
                "slug":       slug,
                "url":        f"https://hackenproof.com/programs/{slug}",
                "submit_url": f"https://hackenproof.com/programs/{slug}/reports/new",
                "min_bounty": prog.get("minReward") or prog.get("min_reward"),
                "max_bounty": prog.get("maxReward") or prog.get("max_reward"),
                "currency":   "USD",
                "scope":      [],
            })
        return programs
    except Exception as e:
        return {"error": str(e), "platform": "hackenproof"}


# ── Open Bug Bounty ───────────────────────────────────────────────────────────

def discover_openbugbounty(limit: int = 20) -> List[Dict] | Dict:
    """Open Bug Bounty — free/coordinated disclosure programs, no reward required."""
    try:
        r = _get("https://www.openbugbounty.org/api/1/programs/", params={"format": "json"})
        if not r:
            return {"error": "request_failed", "platform": "openbugbounty"}
        programs = []
        for prog in r.json()[:limit]:
            domain = prog.get("host","")
            programs.append({
                "platform":   "openbugbounty",
                "name":       domain,
                "slug":       domain,
                "url":        f"https://www.openbugbounty.org/bugbounty/{domain}/",
                "submit_url": f"https://www.openbugbounty.org/report/",
                "min_bounty": 0,
                "max_bounty": 0,
                "currency":   "USD",
                "scope":      [domain],
                "note":       "Coordinated disclosure, no cash reward",
            })
        return programs
    except Exception as e:
        return {"error": str(e), "platform": "openbugbounty"}


# ── Twitter/X ─────────────────────────────────────────────────────────────────

def discover_twitter(query: str = "bug bounty program launch OR new OR announcing", limit: int = 20) -> List[Dict] | Dict:
    """
    Search Twitter/X for bug bounty announcements.
    Requires TWITTER_BEARER_TOKEN in .env.
    """
    token = os.environ.get("TWITTER_BEARER_TOKEN")
    if not token:
        return {"error": "missing_keys", "platform": "twitter",
                "message": "Add TWITTER_BEARER_TOKEN to .env to enable Twitter discovery"}

    try:
        r = requests.get(
            "https://api.twitter.com/2/tweets/search/recent",
            headers={"Authorization": f"Bearer {token}"},
            params={
                "query": f"({query}) lang:en -is:retweet",
                "max_results": min(limit, 100),
                "tweet.fields": "created_at,author_id,text,entities",
                "expansions": "author_id",
                "user.fields": "name,username",
            },
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()

        users = {u["id"]: u for u in data.get("includes", {}).get("users", [])}
        results = []
        for tweet in data.get("data", []):
            author = users.get(tweet.get("author_id",""), {})
            urls = [u.get("expanded_url","") for u in tweet.get("entities",{}).get("urls",[])]
            results.append({
                "platform":   "twitter",
                "name":       f"Tweet by @{author.get('username','')}",
                "slug":       tweet["id"],
                "url":        f"https://twitter.com/{author.get('username','')}/status/{tweet['id']}",
                "submit_url": urls[0] if urls else "",
                "min_bounty": None,
                "max_bounty": None,
                "currency":   "USD",
                "scope":      urls[:5],
                "description": tweet.get("text","")[:280],
                "author":     author.get("name",""),
                "handle":     author.get("username",""),
            })
        return results
    except Exception as e:
        return {"error": str(e), "platform": "twitter"}


# ── DuckDuckGo web search (no API key needed) ─────────────────────────────────

def discover_web_search(queries: List[str] = None, limit: int = 15) -> List[Dict] | Dict:
    """
    Search DuckDuckGo for bug bounty programs not on any platform.
    No API key needed.
    """
    if queries is None:
        queries = [
            "new bug bounty program 2024 responsible disclosure",
            "security vulnerability reward program launch",
            "bug bounty program site:security.txt",
        ]

    results = []
    seen = set()

    for q in queries:
        try:
            # DuckDuckGo instant answer API
            r = _get(
                "https://api.duckduckgo.com/",
                params={"q": q, "format": "json", "no_redirect": 1, "no_html": 1},
            )
            if not r:
                continue
            data = r.json()
            for item in data.get("Results", []) + data.get("RelatedTopics", []):
                url  = item.get("FirstURL","")
                text = item.get("Text","")
                if not url or url in seen:
                    continue
                seen.add(url)
                results.append({
                    "platform":   "web",
                    "name":       text[:80] if text else url,
                    "slug":       url,
                    "url":        url,
                    "submit_url": url,
                    "min_bounty": None,
                    "max_bounty": None,
                    "currency":   "USD",
                    "scope":      [url],
                    "description": text[:200],
                })
                if len(results) >= limit:
                    break
            time.sleep(0.5)
        except Exception:
            continue

    return results if results else {"error": "no_results", "platform": "web"}


# ── Unified discovery ─────────────────────────────────────────────────────────

PLATFORM_MAP = {
    "hackerone":     discover_hackerone,
    "bugcrowd":      discover_bugcrowd,
    "intigriti":     discover_intigriti,
    "immunefi":      discover_immunefi,
    "yeswehack":     discover_yeswehack,
    "hackenproof":   discover_hackenproof,
    "openbugbounty": discover_openbugbounty,
    "twitter":       discover_twitter,
    "web":           discover_web_search,
}

ALL_PLATFORMS = list(PLATFORM_MAP.keys())


def discover_all_programs(
    platforms: List[str] = None,
    min_bounty: int = 0,
    limit_per_platform: int = 20,
) -> Dict[str, Any]:
    """
    Query all (or specified) platforms and return a ranked list of programs.
    Immunefi and web3 programs are included by default for high-reward potential.
    """
    if platforms is None:
        platforms = ALL_PLATFORMS

    all_programs = []
    errors       = []
    needs_keys   = []

    for platform in platforms:
        fn = PLATFORM_MAP.get(platform)
        if not fn:
            continue

        result = fn(limit=limit_per_platform)

        if isinstance(result, dict) and "error" in result:
            if result["error"] == "missing_keys":
                needs_keys.append(result)
            else:
                errors.append(result)
        elif isinstance(result, list):
            all_programs.extend(result)

    # Filter by min_bounty (skip filter for coordinated/web/twitter entries)
    filtered = []
    for p in all_programs:
        max_b = p.get("max_bounty") or 0
        try:
            max_b = float(max_b)
        except (TypeError, ValueError):
            max_b = 0
        if max_b >= min_bounty or p.get("platform") in ("web", "twitter", "openbugbounty"):
            if p.get("scope") or p.get("description") or p.get("url"):
                filtered.append(p)

    # Sort: highest paying first, web/twitter at end
    def sort_key(p):
        if p.get("platform") in ("web", "twitter"):
            return -1
        try:
            return float(p.get("max_bounty") or 0)
        except (TypeError, ValueError):
            return 0

    filtered.sort(key=sort_key, reverse=True)

    return {
        "programs":   filtered,
        "total":      len(filtered),
        "by_platform": {
            pl: len([p for p in filtered if p.get("platform") == pl])
            for pl in platforms
        },
        "errors":    errors,
        "needs_keys": needs_keys,
    }

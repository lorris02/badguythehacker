"""
Browser automation tool using Playwright.
Lets agents see what a real browser sees — bypasses many WAF fingerprints,
catches DOM XSS, discovers forms/auth flows, and navigates multi-step UIs.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional


def browser_probe(
    url: str,
    actions: Optional[List[Dict]] = None,
    extract: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Synchronous wrapper. Runs in the thread pool via asyncio.to_thread.

    actions: list of steps to perform after page load, e.g.:
      [{"type": "fill", "selector": "#email", "value": "test@test.com"},
       {"type": "click", "selector": "button[type=submit]"},
       {"type": "wait", "ms": 1000}]

    extract: list of things to pull out — ["forms", "cookies", "links",
             "inputs", "text", "headers", "dom_xss_sinks"]
    """
    try:
        return asyncio.run(_probe_async(url, actions or [], extract or ["forms", "inputs", "links", "text"]))
    except Exception as e:
        return {"error": str(e), "url": url}


async def _probe_async(url: str, actions: List[Dict], extract: List[str]) -> Dict[str, Any]:
    try:
        from playwright.async_api import async_playwright, TimeoutError as PWTimeout
    except ImportError:
        return {
            "error": "Playwright not installed. Run: pip install playwright && playwright install chromium",
            "url": url,
        }

    result: Dict[str, Any] = {"url": url, "status": None, "title": None}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            ignore_https_errors=True,
        )
        page = await context.new_page()

        # Capture response headers from main navigation
        nav_headers: Dict = {}
        def on_response(resp):
            if resp.url == url or resp.url.rstrip("/") == url.rstrip("/"):
                nav_headers.update(dict(resp.headers))
        page.on("response", on_response)

        try:
            resp = await page.goto(url, timeout=15000, wait_until="domcontentloaded")
            result["status"] = resp.status if resp else None
        except PWTimeout:
            result["error"] = "Page load timed out"
            await browser.close()
            return result
        except Exception as e:
            result["error"] = f"Navigation failed: {e}"
            await browser.close()
            return result

        result["title"] = await page.title()
        result["final_url"] = page.url

        # Run any requested actions
        action_log = []
        for action in actions:
            try:
                atype = action.get("type")
                if atype == "fill":
                    await page.fill(action["selector"], action.get("value", ""), timeout=5000)
                    action_log.append(f"filled {action['selector']}")
                elif atype == "click":
                    await page.click(action["selector"], timeout=5000)
                    action_log.append(f"clicked {action['selector']}")
                elif atype == "wait":
                    await asyncio.sleep(action.get("ms", 500) / 1000)
                    action_log.append(f"waited {action.get('ms',500)}ms")
                elif atype == "screenshot":
                    pass  # skip for now, too large to pass in tool result
            except Exception as e:
                action_log.append(f"FAILED {action.get('type')}: {e}")
        if action_log:
            result["actions_performed"] = action_log

        # Extraction
        if "forms" in extract:
            result["forms"] = await page.evaluate("""() => {
                return Array.from(document.forms).map(f => ({
                    id: f.id, name: f.name, action: f.action, method: f.method,
                    fields: Array.from(f.elements).map(el => ({
                        tag: el.tagName, type: el.type, name: el.name,
                        id: el.id, placeholder: el.placeholder, required: el.required
                    }))
                }));
            }""")

        if "inputs" in extract:
            result["inputs"] = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('input,textarea,select')).map(el => ({
                    type: el.type, name: el.name, id: el.id,
                    placeholder: el.placeholder, value: el.value?.substring(0,100)
                }));
            }""")

        if "links" in extract:
            links = await page.evaluate("""() => {
                return Array.from(document.links).map(a => ({href: a.href, text: a.innerText?.substring(0,80)}));
            }""")
            # Deduplicate and filter same-domain
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            result["links"] = [l for l in links if domain in l.get("href", "")][:40]

        if "text" in extract:
            body_text = await page.evaluate("() => document.body?.innerText || ''")
            result["page_text_preview"] = body_text[:1500]

        if "cookies" in extract:
            cookies = await context.cookies()
            result["cookies"] = [{"name": c["name"], "httponly": c.get("httpOnly"), "secure": c.get("secure"), "samesite": c.get("sameSite")} for c in cookies]

        if "headers" in extract:
            result["response_headers"] = nav_headers

        if "dom_xss_sinks" in extract:
            # Look for common DOM XSS sinks in inline scripts
            sinks = await page.evaluate("""() => {
                const scripts = Array.from(document.scripts).map(s => s.textContent || '');
                const sinkPatterns = ['innerHTML', 'outerHTML', 'document.write', 'eval(', 'setTimeout(', 'location.href', 'location.hash', 'window.location'];
                const found = [];
                scripts.forEach((src, i) => {
                    sinkPatterns.forEach(sink => {
                        if (src.includes(sink)) found.push({script_index: i, sink, context: src.substring(Math.max(0,src.indexOf(sink)-60), src.indexOf(sink)+80)});
                    });
                });
                return found.slice(0, 20);
            }""")
            result["dom_xss_sinks"] = sinks

        # Always include meta security headers check
        result["security_headers"] = {
            "csp": nav_headers.get("content-security-policy", "MISSING"),
            "x_frame_options": nav_headers.get("x-frame-options", "MISSING"),
            "hsts": nav_headers.get("strict-transport-security", "MISSING"),
            "x_content_type": nav_headers.get("x-content-type-options", "MISSING"),
        }

        await browser.close()

    return result

"""
BountyAgent — async Claude-powered agent that runs a full assessment loop.

Each instance is a single asyncio Task. Multiple instances run in parallel
per user, coordinated by the Orchestrator.
"""

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import anthropic
from dotenv import load_dotenv

# Load .env so the agent has API keys even if spawned outside main.py
load_dotenv(Path(__file__).parent / ".env")
load_dotenv(Path(__file__).parent.parent / ".env")

from brain.global_brain import GlobalBrain
from brain.private_brain import PrivateBrain
from prompts.system import get_system_prompt
from tools.bounty_discovery import discover_all_programs
from tools.browser import browser_probe
from tools.disclosure import calculate_cvss, draft_outreach_email, find_security_contact
from tools.exploit import probe_auth_bypass, probe_idor, run_sqlmap
from tools.recon import run_httpx, run_shodan, run_subfinder
from tools.report import generate_disclosure_report, generate_report
from tools.scan import run_ffuf, run_nuclei
from tools.network import nmap_scan, credential_bruteforce, default_creds_check, smb_enumerate, exploit_search, ssh_audit
from tools.osint import certsh_search, wayback_urls, github_dork, google_dork, whois_lookup, paste_search

VALID_MODES = ("bounty", "disclosure")

TIER_LIMITS = {
    "free":       {"max_agents": 1,    "max_targets": 5,    "can_contribute": False},
    "pro":        {"max_agents": 5,    "max_targets": None, "can_contribute": True},
    "enterprise": {"max_agents": None, "max_targets": None, "can_contribute": True},
    "admin":      {"max_agents": None, "max_targets": None, "can_contribute": True},
}


class BountyAgent:
    def __init__(
        self,
        user_id: str,
        tier: str,
        mode: str,
        private_brain: PrivateBrain,
        global_brain: GlobalBrain,
        push: Callable[[Dict], Any],  # async callback → ws_manager.send
        reports_dir: str = "/app/reports",
    ):
        self.agent_id = f"agent-{uuid.uuid4().hex[:8]}"
        self.user_id = user_id
        self.tier = tier
        self.mode = mode
        self.private = private_brain
        self.global_brain = global_brain
        self.push = push
        self.reports_dir = reports_dir

        self.client = anthropic.AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
        self.target: Optional[str] = None
        self.session_id: Optional[str] = None
        self.history: List[Dict] = []
        self.running = True
        self.status = "idle"
        self._task: Optional[asyncio.Task] = None

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self) -> asyncio.Task:
        self._event_loop = asyncio.get_running_loop()
        self._task = asyncio.create_task(self._loop(), name=self.agent_id)
        return self._task

    def stop(self) -> None:
        self.running = False
        if self._task:
            self._task.cancel()

    def state(self) -> Dict:
        return {
            "agent_id": self.agent_id,
            "status": self.status,
            "target": self.target,
            "mode": self.mode,
            "session_id": self.session_id,
        }

    # ── Main loop ─────────────────────────────────────────────────────────────

    async def _loop(self) -> None:
        await self._emit("agent_status", {"status": "idle", "message": "Agent ready, looking for targets..."})
        asyncio.create_task(self._hive_listener(), name=f"{self.agent_id}_hive")

        while self.running:
            claimed = await self.private.claim_target(self.agent_id)
            if not claimed:
                self.status = "idle"
                await self._emit("agent_status", {"status": "idle", "message": "No targets available. Waiting..."})
                await asyncio.sleep(15)
                continue

            self.target = claimed["url"]
            self.mode = claimed.get("mode", self.mode)
            self.status = "running"

            try:
                await self._run_assessment()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                import traceback
                print(f"[AGENT ERROR] {self.agent_id} on {self.target}: {exc}", flush=True)
                traceback.print_exc()
                await self._emit("agent_error", {"error": str(exc), "target": self.target})
                if self.session_id:
                    await self.private.fail_session(self.session_id)
            finally:
                if self.target:
                    await self.private.release_target(self.target, completed=True)
                self.target = None
                self.session_id = None
                self.history = []

        self.status = "stopped"
        await self._emit("agent_status", {"status": "stopped", "message": "Agent stopped."})

    async def _run_assessment(self) -> None:
        self.session_id = await self.private.start_session(
            self.target, self.agent_id, self.mode
        )

        await self._emit("agent_status", {
            "status": "running",
            "target": self.target,
            "mode": self.mode,
            "session_id": self.session_id,
            "message": f"Starting {self.mode} assessment on {self.target}",
        })

        # Extract tech hints from target URL for relevant pattern matching
        _url_lower = (self.target or "").lower()
        tech_hints = []
        for hint in ["cloudflare", "akamai", "magento", "wordpress", "php", "api", "admin", "graphql", "oauth", "jwt"]:
            if hint in _url_lower:
                tech_hints.append(hint)

        # Fetch both general techniques and target-specific hot patterns
        techniques = await self.global_brain.get_techniques(limit=10)
        hot = await self.global_brain.get_hot_patterns(tech_hints=tech_hints, limit=5)

        brain_hint = ""
        all_patterns = {t["title"]: t for t in (techniques[:5] + hot)}  # deduplicate by title
        if all_patterns:
            brain_hint = "\n\nSwarm Intelligence (proven techniques from other agents):\n" + "\n".join(
                f"- [{t['category']}] {t['title']} (confirmed {t.get('success_count',1)}x): {t.get('context_hint','')[:120]}"
                for t in all_patterns.values()
            )

        initial = (
            f"Begin authorized assessment on: {self.target}\n"
            f"Mode: {self.mode}{brain_hint}\n\n"
            "Check memory first, then proceed with recon → scan → exploit → confirm → report. "
            "Use browser_probe for targets where httpx returns 0 results — it uses a real browser and bypasses many WAF fingerprints."
        )

        self.history = [{"role": "user", "content": initial}]
        findings_this_session: List[str] = []

        # ── Adaptive routing state ─────────────────────────────────────────────
        # heat 0=cold (Haiku/fast), 1=warm (Haiku/full), 2=hot (Sonnet), 3=critical (Sonnet/deep)
        self._heat = 0
        self._dead_signals = 0
        prev_heat = -1

        for i in range(40):
            if not self.running:
                break

            # Announce heat escalation to UI
            if self._heat != prev_heat:
                await self._emit("agent_heat", {
                    "heat": self._heat,
                    "model": self._current_model(),
                    "label": ["cold", "warm", "hot", "critical"][self._heat],
                })
                prev_heat = self._heat

            # Early exit: target is a dead end
            if self._should_abort_early(i):
                await self._emit("agent_log", {"message": "No significant attack surface found. Cutting assessment short — moving to next target."})
                break

            # Dynamic max_iter: don't burn 20 calls on cold targets
            if i >= self._max_iter_for_heat():
                break

            response = await self.client.messages.create(
                model=self._current_model(),
                max_tokens=self._current_max_tokens(),
                system=[{
                    "type": "text",
                    "text": get_system_prompt(self.mode),
                    "cache_control": {"type": "ephemeral"},
                }],
                tools=self._tool_defs(),
                messages=self._trimmed_history(),
            )

            self.history.append({"role": "assistant", "content": response.content})

            for block in response.content:
                if hasattr(block, "text") and block.text:
                    await self._emit("agent_log", {"message": block.text[:600]})

            if response.stop_reason == "end_turn":
                break

            if response.stop_reason != "tool_use":
                break

            tool_results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue

                await self._emit("agent_tool", {"tool": block.name, "input_preview": str(block.input)[:200]})

                result = await asyncio.to_thread(self._dispatch, block.name, block.input, findings_this_session)

                # Update heat based on what we found
                self._update_heat(block.name, result)

                await self._emit("agent_tool_result", {"tool": block.name, "result_preview": str(result)[:300]})

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(result, default=str),
                })

            self.history.append({"role": "user", "content": tool_results})

        await self.private.complete_session(self.session_id, len(findings_this_session))
        await self._emit("agent_status", {
            "status": "idle",
            "message": f"Assessment complete on {self.target}. {len(findings_this_session)} finding(s).",
            "findings_count": len(findings_this_session),
        })

    # ── Tool dispatch ─────────────────────────────────────────────────────────

    def _dispatch(self, name: str, inp: Dict, findings_list: List) -> Any:
        """Synchronous tool dispatcher (runs in thread pool via asyncio.to_thread)."""
        try:
            if name == "subfinder_recon":
                return run_subfinder(inp["domain"])

            if name == "httpx_probe":
                return run_httpx(inp["hosts"])

            if name == "shodan_lookup":
                return run_shodan(inp["query"], os.environ.get("SHODAN_API_KEY", ""))

            if name == "nuclei_scan":
                return run_nuclei(
                    inp["targets"],
                    templates=inp.get("templates", ""),
                    severity=inp.get("severity", "low"),
                )

            if name == "ffuf_fuzz":
                _default_wl = str(Path(__file__).parent / "tools" / "bin" / "common.txt")
                wordlist = inp.get("wordlist") or os.environ.get("FFUF_WORDLIST") or _default_wl
                return run_ffuf(
                    inp["url"], wordlist,
                    mode=inp.get("mode", "dirs"),
                    extensions=inp.get("extensions", ""),
                )

            if name == "sqlmap_test":
                return run_sqlmap(
                    inp["url"],
                    params=inp.get("params", ""),
                    data=inp.get("data", ""),
                    level=inp.get("level", 1),
                )

            if name == "idor_probe":
                return probe_idor(
                    inp["url"], inp["param"], inp["id_value"],
                    headers=inp.get("headers", {}),
                )

            if name == "auth_bypass_probe":
                return probe_auth_bypass(
                    inp["url"],
                    auth_type=inp.get("auth_type", "auto"),
                    headers=inp.get("headers", {}),
                )

            if name == "browser_probe":
                return browser_probe(
                    inp["url"],
                    actions=inp.get("actions", []),
                    extract=inp.get("extract", ["forms", "inputs", "links", "text", "dom_xss_sinks"]),
                )

            if name == "calculate_cvss":
                return calculate_cvss(**inp)

            if name == "find_security_contact":
                return find_security_contact(inp["domain"])

            if name == "draft_outreach_email":
                return draft_outreach_email(**inp)

            if name == "discover_programs":
                result = discover_all_programs(
                    platforms=inp.get("platforms"),
                    min_bounty=inp.get("min_bounty", 0),
                    limit_per_platform=inp.get("limit", 20),
                )
                asyncio.run_coroutine_threadsafe(
                    self._emit_programs(result.get("programs", []), result.get("needs_keys", [])),
                    self._event_loop,
                )
                return result

            if name == "report_blocker":
                asyncio.run_coroutine_threadsafe(
                    self._emit("agent_blocker", {
                        "blocker": inp.get("reason", ""),
                        "what_i_need": inp.get("what_i_need", ""),
                        "what_ill_do_without_it": inp.get("fallback", ""),
                    }),
                    self._event_loop,
                )
                return {"status": "reported"}

            if name == "save_finding":
                asyncio.run_coroutine_threadsafe(
                    self._async_save_finding(inp, findings_list),
                    self._event_loop,
                )
                return {"status": "saving", "vuln_type": inp.get("vuln_type")}

            if name == "generate_report":
                fut = asyncio.run_coroutine_threadsafe(
                    self._async_generate_report(inp), self._event_loop
                )
                return fut.result(timeout=60)

            if name == "memory_query":
                fut = asyncio.run_coroutine_threadsafe(
                    self._async_memory_query(inp), self._event_loop
                )
                return fut.result(timeout=30)

            # ── Network tools ──────────────────────────────────────────────
            if name == "nmap_scan":
                return nmap_scan(
                    inp["target"],
                    ports=inp.get("ports", "top1000"),
                    scan_type=inp.get("scan_type", "full"),
                )

            if name == "credential_bruteforce":
                return credential_bruteforce(
                    inp["target"], inp["service"], inp["port"],
                    userlist=inp.get("userlist"),
                    passlist=inp.get("passlist"),
                )

            if name == "default_creds_check":
                return default_creds_check(inp["target"], inp["service"], inp["port"])

            if name == "smb_enumerate":
                return smb_enumerate(inp["target"])

            if name == "exploit_search":
                return exploit_search(inp["query"], limit=inp.get("limit", 10))

            if name == "ssh_audit":
                return ssh_audit(inp["target"], port=inp.get("port", 22))

            # ── OSINT tools ────────────────────────────────────────────────
            if name == "certsh_search":
                return certsh_search(inp["domain"])

            if name == "wayback_urls":
                return wayback_urls(inp["domain"], limit=inp.get("limit", 500))

            if name == "github_dork":
                return github_dork(inp["domain"], dork_type=inp.get("dork_type", "all"))

            if name == "google_dork":
                return google_dork(inp["domain"], dork=inp.get("dork", "all"))

            if name == "whois_lookup":
                return whois_lookup(inp["domain"])

            if name == "paste_search":
                return paste_search(inp["domain"])

            return {"error": f"Unknown tool: {name}"}

        except Exception as e:
            return {"error": str(e), "tool": name}

    async def _emit_programs(self, programs: List[Dict], needs_keys: List[Dict]) -> None:
        """Push discovered bounty programs to the user's UI."""
        await self._emit("programs_discovered", {
            "programs": programs,
            "count": len(programs),
            "needs_keys": needs_keys,
        })

    async def _hive_listener(self) -> None:
        """Subscribe to Redis and inject live swarm intel into running assessments."""
        try:
            pubsub = self.global_brain.redis.pubsub()
            await pubsub.subscribe("global_techniques")
            async for message in pubsub.listen():
                if not self.running:
                    break
                if message["type"] != "message":
                    continue
                # Only inject if actively assessing a target
                if not self.target or not self.history:
                    continue
                try:
                    pattern = json.loads(message["data"])
                    inject = (
                        f"[LIVE SWARM INTEL] Another agent just confirmed a finding!\n"
                        f"Technique: {pattern.get('title')}\n"
                        f"Category: {pattern.get('category')}\n"
                        f"Payload/Method: {pattern.get('payload','(see context)')}\n"
                        f"Context: {pattern.get('context_hint','')}\n\n"
                        f"If this technique applies to your current target ({self.target}), try it NOW before moving on."
                    )
                    self.history.append({"role": "user", "content": inject})
                    await self._emit("hive_intel", {
                        "pattern": pattern.get("title"),
                        "category": pattern.get("category"),
                    })
                except Exception:
                    continue
        except Exception:
            pass  # hive listener is non-critical

    async def _async_save_finding(self, inp: Dict, findings_list: List) -> None:
        finding_id = await self.private.save_finding(
            session_id=self.session_id or "",
            target=self.target or "",
            vuln_type=inp.get("vuln_type", ""),
            severity=inp.get("severity", "info"),
            url=inp.get("url", ""),
            description=inp.get("description", ""),
            poc=inp.get("poc", ""),
            confirmed=inp.get("confirmed", False),
            cvss_score=inp.get("cvss_score"),
            cvss_vector=inp.get("cvss_vector"),
            cvss_components=inp.get("cvss_components"),
            submit_url=inp.get("submit_url", ""),
            platform=inp.get("platform", ""),
            program_name=inp.get("program_name", ""),
        )
        findings_list.append(finding_id)

        finding = {
            "id": finding_id,
            "vuln_type": inp.get("vuln_type"),
            "severity": inp.get("severity"),
            "url": inp.get("url"),
            "confirmed": inp.get("confirmed", False),
            "cvss_score": inp.get("cvss_score"),
            "submit_url": inp.get("submit_url", ""),
            "platform": inp.get("platform", ""),
            "program_name": inp.get("program_name", ""),
        }
        await self._emit("new_finding", {"finding": finding})

        # Contribute technique to global brain if tier allows
        if TIER_LIMITS[self.tier]["can_contribute"] and inp.get("confirmed"):
            await self.global_brain.contribute_technique(
                technique_type="vuln",
                category=inp.get("vuln_type", "unknown").lower().replace(" ", "_"),
                title=f"{inp.get('vuln_type')} via {inp.get('poc','')[:80]}",
                payload=inp.get("poc", ""),
                context_hint=inp.get("description", "")[:200],
                contributed_by_tier=self.tier,
            )

    async def _async_generate_report(self, inp: Dict) -> Dict:
        findings = await self.private.get_findings(confirmed_only=not inp.get("include_unconfirmed", False))
        # Enrich findings with CVSS components
        enriched = []
        for f in findings:
            d = dict(f)
            full = await self.private.get_finding(str(f["id"]))
            if full:
                d.update(full)
            enriched.append(d)

        if self.mode == "disclosure":
            contact_info = find_security_contact(inp["target"])
            path = generate_disclosure_report(enriched, inp["target"], contact_info, self.reports_dir)
        else:
            path = generate_report(enriched, inp["target"], self.reports_dir)

        await self._emit("report_ready", {"report_path": path, "target": inp["target"]})
        return {"status": "success", "report_path": path, "mode": self.mode}

    async def _async_memory_query(self, inp: Dict) -> Dict:
        qt = inp["query_type"]
        f = inp.get("filter", "")

        if qt == "subdomains":
            targets = await self.private.get_targets()
            return {"targets": targets}
        if qt == "findings":
            findings = await self.private.get_findings(
                severity=f if f in ("critical","high","medium","low","info") else None
            )
            return {"findings": findings}
        if qt == "sessions":
            return {"note": "Sessions tracked in PostgreSQL"}
        return {"error": f"Unknown query_type: {qt}"}

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _emit(self, event_type: str, data: Dict) -> None:
        try:
            await self.push({
                "type": event_type,
                "agent_id": self.agent_id,
                **data,
            })
        except Exception:
            pass

    # ── Adaptive routing ──────────────────────────────────────────────────────

    def _update_heat(self, tool_name: str, result: Any) -> None:
        """Raise heat level based on what the tool found. Never lowers."""
        if not isinstance(result, dict):
            return

        if tool_name == "subfinder_recon":
            count = result.get("count", 0)
            if count > 20:  self._heat = max(self._heat, 2)
            elif count > 3: self._heat = max(self._heat, 1)
            else:           self._dead_signals += 1

        elif tool_name == "httpx_probe":
            alive = result.get("alive_hosts", [])
            if not alive:
                self._dead_signals += 1
                return
            self._heat = max(self._heat, 1)
            # High-value surface indicators → push to hot
            high_value = ("api", "admin", "auth", "login", "internal", "staging", "graphql", "dashboard")
            for h in alive:
                url  = (h.get("url") or "").lower()
                title = (h.get("title") or "").lower()
                tech  = " ".join(str(t) for t in h.get("technologies", [])).lower()
                if any(kw in url + title + tech for kw in high_value):
                    self._heat = max(self._heat, 2)
                    break
                if h.get("status_code") in (401, 403):  # auth-gated → worth attacking
                    self._heat = max(self._heat, 2)

        elif tool_name == "nuclei_scan":
            findings = result.get("findings", [])
            if findings:
                self._heat = 3  # any nuclei hit → critical
            else:
                self._dead_signals += 1

        elif tool_name == "auth_bypass_probe":
            bypasses = result.get("bypasses_found", []) or []
            if bypasses or result.get("vulnerable"):
                self._heat = 3

        elif tool_name == "browser_probe":
            if result.get("error"):
                self._dead_signals += 1
            else:
                sinks = result.get("dom_xss_sinks", [])
                forms = result.get("forms", [])
                if sinks:  self._heat = max(self._heat, 2)
                if forms:  self._heat = max(self._heat, 1)
                else:      self._dead_signals += 1

        elif tool_name == "nmap_scan":
            ports = result.get("open_ports", [])
            if not ports:
                self._dead_signals += 1
            elif len(ports) > 5:
                self._heat = max(self._heat, 2)
            else:
                self._heat = max(self._heat, 1)
            if result.get("script_findings"):
                self._heat = 3

        elif tool_name in ("credential_bruteforce", "default_creds_check"):
            if result.get("vulnerable") or result.get("credentials_found"):
                self._heat = 3
            else:
                self._dead_signals += 1

        elif tool_name == "smb_enumerate":
            if result.get("null_session") or result.get("shares"):
                self._heat = max(self._heat, 2)
            if any("CRITICAL" in f or "VULNERABLE" in f for f in result.get("findings", [])):
                self._heat = 3

        elif tool_name == "exploit_search":
            count = result.get("count", 0)
            if count > 0:
                self._heat = max(self._heat, 2)
            if result.get("has_metasploit"):
                self._heat = 3

        elif tool_name == "certsh_search":
            if result.get("interesting"):
                self._heat = max(self._heat, 1)

        elif tool_name == "wayback_urls":
            if result.get("juicy_endpoints"):
                self._heat = max(self._heat, 2)

        elif tool_name in ("github_dork", "paste_search"):
            if result.get("count", 0) > 0 or result.get("breach_count", 0) > 0:
                self._heat = max(self._heat, 2)
            if result.get("results") and any(
                "password" in str(r).lower() or "secret" in str(r).lower() or "token" in str(r).lower()
                for r in result.get("results", [])
            ):
                self._heat = 3

        elif tool_name == "save_finding":
            self._heat = 3  # confirmed finding → always critical depth

        elif tool_name in ("httpx_probe", "ffuf_fuzz"):
            if result.get("error"):
                self._dead_signals += 1

    def _trimmed_history(self, keep: int = 12) -> List[Dict]:
        """Keep first message (task) + last N messages to limit input tokens."""
        if len(self.history) <= keep:
            return self.history
        return [self.history[0]] + self.history[-(keep - 1):]

    def _current_model(self) -> str:
        if self._heat >= 3:
            return "claude-sonnet-4-6"
        return "claude-haiku-4-5-20251001"

    def _current_max_tokens(self) -> int:
        return {0: 1024, 1: 1536, 2: 3072, 3: 4096}.get(self._heat, 2048)

    def _max_iter_for_heat(self) -> int:
        """Cold targets get fewer iterations — don't waste calls on dead ends."""
        return {0: 8, 1: 18, 2: 30, 3: 40}.get(self._heat, 40)

    def _should_abort_early(self, iteration: int) -> bool:
        """Cut the session if the target is clearly a dead end."""
        # Need at least 3 tool calls before giving up
        if iteration < 3:
            return False
        # 3+ dead signals and still cold → nothing here
        if self._dead_signals >= 3 and self._heat == 0:
            return True
        # 4+ dead signals even on warm → move on
        if self._dead_signals >= 4 and self._heat <= 1:
            return True
        return False

    def _tool_defs(self) -> List[Dict]:
        return [
            {"name": "subfinder_recon", "description": "Enumerate subdomains.", "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
            {"name": "httpx_probe", "description": "Probe live hosts.", "input_schema": {"type": "object", "properties": {"hosts": {"type": "array", "items": {"type": "string"}}}, "required": ["hosts"]}},
            {"name": "shodan_lookup", "description": "Passive recon via Shodan.", "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}},
            {"name": "nuclei_scan", "description": "Template vulnerability scanner.", "input_schema": {"type": "object", "properties": {"targets": {"type": "array", "items": {"type": "string"}}, "templates": {"type": "string"}, "severity": {"type": "string", "enum": ["info","low","medium","high","critical"]}}, "required": ["targets"]}},
            {"name": "ffuf_fuzz", "description": "Directory/param fuzzing. URL must have FUZZ.", "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "wordlist": {"type": "string"}, "mode": {"type": "string", "enum": ["dirs","params","vhosts"]}, "extensions": {"type": "string"}}, "required": ["url"]}},
            {"name": "sqlmap_test", "description": "SQL injection testing.", "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "params": {"type": "string"}, "data": {"type": "string"}, "level": {"type": "integer"}}, "required": ["url"]}},
            {"name": "idor_probe", "description": "IDOR vulnerability probe.", "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string"}, "id_value": {"type": "string"}, "headers": {"type": "object"}}, "required": ["url","param","id_value"]}},
            {"name": "auth_bypass_probe", "description": "Auth bypass testing (JWT, verb, path).", "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "auth_type": {"type": "string", "enum": ["jwt","basic","cookie","header","auto"]}, "headers": {"type": "object"}}, "required": ["url"]}},
            {"name": "calculate_cvss", "description": "Calculate CVSS v3.1 score.", "input_schema": {"type": "object", "properties": {"attack_vector": {"type": "string", "enum": ["N","A","L","P"]}, "attack_complexity": {"type": "string", "enum": ["L","H"]}, "privileges_required": {"type": "string", "enum": ["N","L","H"]}, "user_interaction": {"type": "string", "enum": ["N","R"]}, "scope": {"type": "string", "enum": ["U","C"]}, "confidentiality": {"type": "string", "enum": ["N","L","H"]}, "integrity": {"type": "string", "enum": ["N","L","H"]}, "availability": {"type": "string", "enum": ["N","L","H"]}}, "required": ["attack_vector","attack_complexity","privileges_required","user_interaction","scope","confidentiality","integrity","availability"]}},
            {"name": "find_security_contact", "description": "Find security contact for disclosure.", "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
            {"name": "draft_outreach_email", "description": "Draft responsible disclosure email.", "input_schema": {"type": "object", "properties": {"target": {"type": "string"}, "vuln_summary": {"type": "string"}, "severity": {"type": "string"}, "cvss_score": {"type": "number"}, "contact": {"type": "string"}, "researcher_name": {"type": "string"}, "deadline_days": {"type": "integer"}}, "required": ["target","vuln_summary","severity","cvss_score","contact"]}},
            {"name": "save_finding", "description": "Save confirmed vulnerability.", "input_schema": {"type": "object", "properties": {"vuln_type": {"type": "string"}, "severity": {"type": "string", "enum": ["critical","high","medium","low","info"]}, "url": {"type": "string"}, "description": {"type": "string"}, "poc": {"type": "string"}, "confirmed": {"type": "boolean"}, "cvss_score": {"type": "number"}, "cvss_vector": {"type": "string"}, "cvss_components": {"type": "object"}}, "required": ["vuln_type","severity","url","description"]}},
            {"name": "generate_report", "description": "Generate final assessment report.", "input_schema": {"type": "object", "properties": {"target": {"type": "string"}, "include_unconfirmed": {"type": "boolean"}}, "required": ["target"]}},
            {"name": "memory_query", "description": "Query agent's memory.", "input_schema": {"type": "object", "properties": {"query_type": {"type": "string", "enum": ["subdomains","findings","sessions"]}, "filter": {"type": "string"}}, "required": ["query_type"]}},
            {"name": "discover_programs", "description": "Search HackerOne, Bugcrowd and Intigriti for active bug bounty programs with their scope and reward info.", "input_schema": {"type": "object", "properties": {"platforms": {"type": "array", "items": {"type": "string", "enum": ["hackerone","bugcrowd","intigriti"]}, "description": "Which platforms to search. Omit to search all."}, "min_bounty": {"type": "integer", "description": "Minimum max bounty in USD to include."}, "limit": {"type": "integer", "description": "Programs per platform (default 20)."}}, "required": []}},
            {"name": "report_blocker", "description": "Tell the user you cannot complete a task and why, what you need to proceed, and what you will do in the meantime.", "input_schema": {"type": "object", "properties": {"reason": {"type": "string", "description": "What you cannot do and why."}, "what_i_need": {"type": "string", "description": "Tool, API key, credential, or capability needed."}, "fallback": {"type": "string", "description": "What you will attempt instead."}}, "required": ["reason", "what_i_need"]}},
            {"name": "browser_probe", "description": "Open target in a real headless Chromium browser. Use this when httpx returns 0 results (WAF bypass), to extract forms/inputs for XSS testing, to find DOM XSS sinks, or to navigate multi-step auth flows. Much harder to fingerprint than raw HTTP.", "input_schema": {"type": "object", "properties": {"url": {"type": "string", "description": "URL to open in the browser"}, "actions": {"type": "array", "description": "Steps to perform after page load", "items": {"type": "object", "properties": {"type": {"type": "string", "enum": ["fill","click","wait"]}, "selector": {"type": "string"}, "value": {"type": "string"}, "ms": {"type": "integer"}}}}, "extract": {"type": "array", "description": "What to extract", "items": {"type": "string", "enum": ["forms","inputs","links","text","cookies","headers","dom_xss_sinks"]}}}, "required": ["url"]}},

            # ── Network tools ──────────────────────────────────────────────────
            {"name": "nmap_scan", "description": "Full port/service/version/OS scan with nmap. Run this on every discovered IP — don't assume only web ports are open. Use scan_type=vuln to run NSE vuln scripts.", "input_schema": {"type": "object", "properties": {"target": {"type": "string", "description": "IP or hostname"}, "ports": {"type": "string", "description": "top1000 | all | comma-separated list e.g. '22,80,443,8080'"}, "scan_type": {"type": "string", "enum": ["fast","full","vuln","stealth"], "description": "fast=quick, full=default+scripts, vuln=NSE vuln scripts, stealth=SYN slow"}}, "required": ["target"]}},
            {"name": "credential_bruteforce", "description": "Brute force credentials on SSH, FTP, RDP, SMB, HTTP using hydra. Use when default_creds_check fails but the service is worth attacking. Provide wordlist paths or leave empty to use defaults.", "input_schema": {"type": "object", "properties": {"target": {"type": "string"}, "service": {"type": "string", "description": "ssh | ftp | rdp | smb | http | https | mysql | mssql | telnet"}, "port": {"type": "integer"}, "userlist": {"type": "string", "description": "Path to username wordlist (optional)"}, "passlist": {"type": "string", "description": "Path to password wordlist (optional)"}}, "required": ["target","service","port"]}},
            {"name": "default_creds_check", "description": "Try known default credentials for common services (SSH, FTP, Redis, MySQL, HTTP, etc.). Always try this before full brute force — default creds are extremely common.", "input_schema": {"type": "object", "properties": {"target": {"type": "string"}, "service": {"type": "string", "description": "ssh | ftp | http | https | redis | mysql | postgres | mssql | rdp | smb | vnc | snmp"}, "port": {"type": "integer"}}, "required": ["target","service","port"]}},
            {"name": "smb_enumerate", "description": "Enumerate SMB shares, users, OS, and check for critical vulns like EternalBlue (MS17-010). Run whenever port 445 or 139 is open.", "input_schema": {"type": "object", "properties": {"target": {"type": "string", "description": "IP or hostname"}}, "required": ["target"]}},
            {"name": "exploit_search", "description": "Search exploit-db/searchsploit for known public exploits matching a service name and version. Use the exact version string from nmap output. Check for Metasploit modules.", "input_schema": {"type": "object", "properties": {"query": {"type": "string", "description": "Service name + version e.g. 'OpenSSH 7.4' or 'Apache 2.4.49' or 'ProFTPD 1.3.5'"}, "limit": {"type": "integer", "description": "Max results (default 10)"}}, "required": ["query"]}},
            {"name": "ssh_audit", "description": "Audit SSH configuration for weak algorithms, outdated versions, and exposed host keys. Run when port 22 is open.", "input_schema": {"type": "object", "properties": {"target": {"type": "string"}, "port": {"type": "integer", "description": "SSH port (default 22)"}}, "required": ["target"]}},

            # ── OSINT tools ────────────────────────────────────────────────────
            {"name": "certsh_search", "description": "Search certificate transparency logs (crt.sh) for every subdomain the target has ever had a TLS cert for. Finds staging, internal, and forgotten assets. Run this FIRST before subfinder.", "input_schema": {"type": "object", "properties": {"domain": {"type": "string", "description": "Root domain e.g. example.com"}}, "required": ["domain"]}},
            {"name": "wayback_urls", "description": "Pull historical URLs from the Wayback Machine. Finds deleted endpoints, old API versions, backup files, and forgotten admin panels. Combine with httpx to check which are still live.", "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
            {"name": "github_dork", "description": "Search GitHub for accidentally committed secrets, config files, API keys, and internal hostnames related to the target. Often finds credentials that work on live systems.", "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}, "dork_type": {"type": "string", "enum": ["all","secrets","config","code"], "description": "Category to search (default all)"}}, "required": ["domain"]}},
            {"name": "google_dork", "description": "Run Google/DuckDuckGo dork queries to find exposed admin panels, directory listings, sensitive files, and API keys indexed by search engines.", "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}, "dork": {"type": "string", "enum": ["all","files","admin","sensitive"], "description": "Dork category (default all)"}}, "required": ["domain"]}},
            {"name": "whois_lookup", "description": "WHOIS lookup to find registrant org, email, nameservers, and related domains. Useful for pivoting to sibling targets and finding security contact info.", "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
            {"name": "paste_search", "description": "Search paste sites, IntelligenceX, GreyNoise, and HaveIBeenPwned for the target domain. May surface leaked credentials, internal URLs, or API keys from historical breaches.", "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
        ]

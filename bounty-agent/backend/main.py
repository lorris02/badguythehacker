"""
BountyAgent — FastAPI backend.

Endpoints:
  /api/auth/*      — register, login, me
  /api/agents/*    — spawn/stop agents, manage targets
  /api/findings/*  — list/get findings and reports
  /ws              — authenticated WebSocket for real-time updates + chat
"""

import asyncio
import json
import os
from pathlib import Path
from typing import Dict, Optional

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")   # loads backend/.env if present
load_dotenv(Path(__file__).parent.parent / ".env")  # fallback: project root .env

import redis.asyncio as aioredis
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from api import agents, auth, findings
from tools.setup_tools import setup_all as _install_tools_bg, tools_status
from api.auth import verify_token
from db import get_pool, init_db
from orchestrator import Orchestrator

app = FastAPI(title="BountyAgent", version="2.0.0", docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(agents.router, prefix="/api/agents", tags=["agents"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])


# ── WebSocket connection manager ──────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self._connections: Dict[str, WebSocket] = {}

    async def connect(self, user_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._connections[user_id] = ws

    def disconnect(self, user_id: str) -> None:
        self._connections.pop(user_id, None)

    async def send(self, user_id: str, data: dict) -> None:
        ws = self._connections.get(user_id)
        if ws:
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect(user_id)

    async def broadcast(self, data: dict) -> None:
        dead = []
        for uid, ws in list(self._connections.items()):
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(uid)
        for uid in dead:
            self.disconnect(uid)


# ── App lifecycle ─────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    pool = await get_pool()
    await init_db(pool)

    redis = aioredis.from_url(os.environ["REDIS_URL"], decode_responses=True)

    manager = ConnectionManager()
    orchestrator = Orchestrator(pool=pool, redis=redis, ws_manager=manager)

    app.state.pool = pool
    app.state.redis = redis
    app.state.ws_manager = manager
    app.state.orchestrator = orchestrator

    asyncio.create_task(orchestrator.listen_global_brain())

    # Auto-install scanning tools in background — doesn't block startup
    asyncio.create_task(asyncio.to_thread(_install_tools_bg))


@app.on_event("shutdown")
async def shutdown() -> None:
    await app.state.orchestrator.stop_all()
    await app.state.pool.close()
    await app.state.redis.aclose()


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, token: str = ""):
    try:
        payload = verify_token(token)
        user_id = payload["sub"]
        tier = payload.get("tier", "free")
        role = payload.get("role", "user")
    except Exception:
        await ws.close(code=4001)
        return

    manager: ConnectionManager = app.state.ws_manager
    orchestrator: Orchestrator = app.state.orchestrator

    await manager.connect(user_id, ws)

    # Push initial state on connect
    agents_status = orchestrator.get_user_status(user_id)
    brain_count = await app.state.orchestrator.global_brain.get_total_count()
    await manager.send(user_id, {
        "type": "connected",
        "user_id": user_id,
        "tier": tier,
        "role": role,
        "agents": agents_status,
        "brain_techniques": brain_count,
    })

    try:
        while True:
            raw = await ws.receive_json()
            if raw.get("type") == "chat":
                try:
                    response = await _handle_chat(
                        user_id=user_id,
                        tier=tier,
                        role=role,
                        message=raw.get("message", ""),
                        orchestrator=orchestrator,
                        pool=app.state.pool,
                    )
                except Exception as e:
                    response = {"type": "chat_response", "message": f"Error: {e}"}
                await manager.send(user_id, response)
            elif raw.get("type") == "ping":
                await manager.send(user_id, {"type": "pong"})

    except WebSocketDisconnect:
        manager.disconnect(user_id)
    except Exception:
        manager.disconnect(user_id)


# ── Chat command router ───────────────────────────────────────────────────────

TIER_LIMITS = {
    "free":       {"max_agents": 1,    "max_targets": 5},
    "pro":        {"max_agents": 5,    "max_targets": None},
    "enterprise": {"max_agents": None, "max_targets": None},
    "admin":      {"max_agents": None, "max_targets": None},
}


def _score_program(prog: dict) -> int:
    """Score a program 0-100. Higher = agents hunt this first."""
    score = 40  # baseline

    # Platform credibility
    platform_pts = {"hackerone": 20, "bugcrowd": 18, "intigriti": 18, "yeswehack": 12, "immunefi": 12, "hackenproof": 10, "openbugbounty": 5}
    score += platform_pts.get(prog.get("platform", ""), 3)

    # Bounty amount — biggest signal
    try:
        bounty = float(prog.get("max_bounty") or 0)
    except (TypeError, ValueError):
        bounty = 0
    if bounty > 10_000: score += 25
    elif bounty > 1_000: score += 15
    elif bounty > 0:    score += 5

    # URL / scope value hints
    url = (prog.get("url") or "").lower()
    if any(x in url for x in ("api.", "api/", "/api")): score += 12
    if any(x in url for x in ("admin", "internal", "staging", "dev.")): score += 8
    if url.startswith("https"): score += 4

    # Old/known-vulnerable tech stacks in program name
    name = (prog.get("name") or "").lower()
    if any(x in name for x in ("wordpress", "magento", "joomla", "drupal", "php")): score += 10

    return min(score, 100)


async def _handle_chat(
    user_id: str,
    tier: str,
    role: str,
    message: str,
    orchestrator: Orchestrator,
    pool,
) -> dict:
    msg = message.strip()
    limits = TIER_LIMITS["admin"] if role == "admin" else TIER_LIMITS.get(tier, TIER_LIMITS["free"])

    # /help
    if msg in ("/help", "/help ") or msg.startswith("/help "):
        label = "admin (no limits)" if role == "admin" else tier
        return {"type": "chat_response", "message": (
            f"**BountyAgent commands** — you are [{label}]\n\n"
            "/hunt                          — discover programs from all platforms & sources\n"
            "/hunt --min-bounty 500         — only programs paying $500+\n"
            "/hunt --min-bounty 1000        — programs paying $1000+\n"
            "/hunt --platforms h1,bc        — pick platforms (h1, bc, intigriti, ywh, hp, twitter, web)\n\n"
            "**Where it looks:**\n"
            "  · HackerOne      — tech, finance, social media, gaming, healthcare, govt…\n"
            "  · Bugcrowd       — startups to Fortune 500 across every industry\n"
            "  · Intigriti      — European companies, all sectors\n"
            "  · YesWeHack      — global, all industries\n"
            "  · HackenProof    — software & security companies\n"
            "  · Open Bug Bounty — coordinated disclosure, all domains\n"
            "  · Immunefi       — crypto/DeFi only (opt-in with --platforms immunefi)\n"
            "  · Twitter/X      — companies announcing new programs\n"
            "  · Web search     — programs not on any platform\n\n"
            "/swarm start [n]               — spawn n agents to start hunting\n"
            "/swarm stop                    — stop all agents\n"
            "/swarm status                  — show running agents\n"
            "/targets add <url>             — manually add a target URL\n"
            "/targets                       — list your targets\n"
            "/findings                      — list discovered vulnerabilities\n"
            "/report <id>                   — view full finding report\n"
            "/mode bounty|disclosure        — set hunt mode\n"
            "/brain                         — show global technique brain\n\n"
            "**Workflow:** /hunt → /swarm start 2 → findings come in automatically"
        )}

    # /swarm (bare) → show status
    if msg == "/swarm":
        status = orchestrator.get_user_status(user_id)
        if status:
            return {"type": "swarm_status", "agents": status, "message": f"{len(status)} active agent(s)."}
        return {"type": "chat_response", "message": "No agents running. Use /swarm start 1 to spawn one."}

    # /swarm start [n]
    if msg.startswith("/swarm start"):
        parts = msg.split()
        try:
            n = int(parts[2]) if len(parts) > 2 else 1
        except (IndexError, ValueError):
            n = 1

        max_a = limits["max_agents"]
        current = orchestrator.count_user_agents(user_id)
        if max_a and current + n > max_a:
            avail = max(0, max_a - current)
            if avail == 0:
                return {"type": "chat_response", "message": f"Agent limit reached ({max_a} max for {tier}). Upgrade to run more."}
            n = avail

        mode = orchestrator.user_modes.get(user_id, "bounty")
        ids = await orchestrator.spawn_agents(user_id, n, mode=mode, role=role)
        return {"type": "chat_response", "message": f"Spawned {len(ids)} agent(s): {', '.join(ids)}"}

    # /swarm stop
    if msg.startswith("/swarm stop"):
        stopped = await orchestrator.stop_all_for_user(user_id)
        return {"type": "chat_response", "message": f"Stopped {stopped} agent(s)."}

    # /swarm status
    if msg.startswith("/swarm status"):
        status = orchestrator.get_user_status(user_id)
        return {"type": "swarm_status", "agents": status, "message": f"{len(status)} active agent(s)."}

    # /targets add <url>
    if msg.startswith("/targets add"):
        url = msg.replace("/targets add", "", 1).strip()
        if not url:
            return {"type": "chat_response", "message": "Usage: /targets add <url>"}

        max_t = limits["max_targets"]
        if max_t:
            async with pool.acquire() as conn:
                count = await conn.fetchval("SELECT COUNT(*) FROM targets WHERE user_id=$1", user_id)
                if count >= max_t:
                    return {"type": "chat_response", "message": f"Target limit ({max_t}) reached for {tier}. Upgrade for unlimited."}

        mode = orchestrator.user_modes.get(user_id, "bounty")
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO targets (user_id, url, mode) VALUES ($1,$2,$3) ON CONFLICT (user_id, url) DO NOTHING",
                user_id, url, mode,
            )
        return {"type": "chat_response", "message": f"Target added: {url}"}

    # /targets list
    if msg.startswith("/targets"):
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT url, status, mode FROM targets WHERE user_id=$1 ORDER BY added_at DESC LIMIT 20", user_id)
        return {"type": "targets_list", "targets": [dict(r) for r in rows]}

    # /findings
    if msg.startswith("/findings"):
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id::text, vuln_type, severity, url, confirmed, discovered_at FROM findings WHERE user_id=$1 ORDER BY discovered_at DESC LIMIT 20",
                user_id,
            )
        return {"type": "findings_list", "findings": [dict(r) for r in rows]}

    # /report <id>
    if msg.startswith("/report"):
        parts = msg.split()
        if len(parts) < 2:
            return {"type": "chat_response", "message": "Usage: /report <finding_id>"}
        fid = parts[1]
        async with pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM findings WHERE id=$1::uuid AND user_id=$2", fid, user_id)
        if not row:
            return {"type": "chat_response", "message": "Finding not found."}
        finding = dict(row)
        content = ""
        rp = finding.get("report_path", "")
        if rp and os.path.exists(rp):
            with open(rp) as f:
                content = f.read()
        return {"type": "report", "finding": finding, "content": content}

    # /mode bounty|disclosure
    if msg.startswith("/mode"):
        parts = msg.split()
        if len(parts) < 2 or parts[1] not in ("bounty", "disclosure"):
            return {"type": "chat_response", "message": "Usage: /mode bounty|disclosure"}
        orchestrator.user_modes[user_id] = parts[1]
        return {"type": "chat_response", "message": f"Mode set to: {parts[1]}"}

    # /hunt [--min-bounty N] [--platforms h1,bc,intigriti]
    if msg.startswith("/hunt"):
        import asyncio as _aio
        from tools.bounty_discovery import discover_all_programs

        parts = msg.split()
        min_bounty = 0
        platforms  = None

        for i, p in enumerate(parts):
            if p == "--min-bounty" and i + 1 < len(parts):
                try: min_bounty = int(parts[i + 1])
                except ValueError: pass
            if p == "--platforms" and i + 1 < len(parts):
                mapping = {
                    "h1": "hackerone", "hackerone": "hackerone",
                    "bc": "bugcrowd",  "bugcrowd": "bugcrowd",
                    "intigriti": "intigriti",
                    "immunefi": "immunefi", "web3": "immunefi",
                    "yeswehack": "yeswehack", "ywh": "yeswehack",
                    "hackenproof": "hackenproof", "hp": "hackenproof",
                    "openbugbounty": "openbugbounty", "obb": "openbugbounty",
                    "twitter": "twitter", "x": "twitter",
                    "web": "web",
                }
                platforms = [mapping[x] for x in parts[i + 1].split(",") if x in mapping]

        result = await _aio.to_thread(discover_all_programs, platforms, min_bounty, 25)

        programs = result.get("programs", [])
        needs_keys = result.get("needs_keys", [])

        if not programs and not needs_keys:
            return {"type": "chat_response", "message": "No programs found. Try lowering --min-bounty or check your API keys."}

        # Auto-add top 10 programs as targets for agents to hunt
        mode = orchestrator.user_modes.get(user_id, "bounty")
        added = 0
        # Sort by score descending so the top 20 added are the best ones
        scored = sorted(programs, key=_score_program, reverse=True)
        async with pool.acquire() as conn:
            for prog in scored[:20]:
                scope_url = prog["scope"][0] if prog.get("scope") else prog["url"]
                prog_score = _score_program(prog)
                try:
                    await conn.execute(
                        """INSERT INTO targets (user_id, url, mode, platform, program_name, submit_url, score)
                           VALUES ($1,$2,$3,$4,$5,$6,$7)
                           ON CONFLICT (user_id, url) DO UPDATE
                           SET status='unclaimed', claimed_by=NULL,
                               platform=EXCLUDED.platform,
                               program_name=EXCLUDED.program_name,
                               submit_url=EXCLUDED.submit_url,
                               score=EXCLUDED.score""",
                        user_id, scope_url, mode,
                        prog["platform"], prog["name"], prog["submit_url"], prog_score,
                    )
                    added += 1
                except Exception:
                    pass

        key_warning = ""
        if needs_keys:
            missing = [k["platform"] for k in needs_keys]
            key_warning = f"\n\n⚠️ Missing API keys for: {', '.join(missing)}. Add them to backend/.env for better results."

        return {
            "type":            "programs_discovered",
            "programs":        programs,
            "by_platform":     result.get("by_platform", {}),
            "added_as_targets": added,
            "message": (
                f"Found {len(programs)} programs across "
                f"{len(set(p['platform'] for p in programs))} platform(s). "
                f"Added top {added} as targets — use /swarm start 1 to begin hunting."
                + key_warning
            ),
        }

    # /tools — show scanning tool install status
    if msg.startswith("/tools"):
        status = tools_status()
        lines = []
        for tool, installed in status.items():
            lines.append(f"{'[OK]' if installed else '[--]'} {tool}")
        installed_count = sum(status.values())
        summary = f"{installed_count}/{len(status)} tools ready"
        if installed_count < len(status):
            summary += " — missing tools are being downloaded in background"
        return {"type": "chat_response", "message": f"**Scanning tools** — {summary}\n\n" + "\n".join(lines)}

    # /brain
    if msg.startswith("/brain"):
        techniques = await orchestrator.global_brain.get_techniques(limit=10)
        count = await orchestrator.global_brain.get_total_count()
        return {"type": "brain_snapshot", "total": count, "top_techniques": techniques}

    # Natural language fallback → Claude
    try:
        import anthropic
        client = anthropic.AsyncAnthropic()
        resp = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=400,
            system=(
                "You are BountyAgent's assistant. Help users manage their bug bounty swarm concisely. "
                "Available slash commands: /swarm start [n], /swarm stop, /swarm status, "
                "/targets add <url>, /targets, /findings, /report <id>, /mode bounty|disclosure, /brain"
            ),
            messages=[{"role": "user", "content": msg}],
        )
        return {"type": "chat_response", "message": resp.content[0].text}
    except Exception as e:
        return {"type": "chat_response", "message": f"Unknown command. Try /swarm start 1 or /targets add https://example.com"}


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "BountyAgent"}

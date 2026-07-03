"""
Orchestrator — manages multiple BountyAgent instances per user.

Responsibilities:
  • Spawn / stop agents per user within tier limits
  • Route WebSocket pushes to the right connection
  • Listen to Redis pubsub for global brain broadcasts → push to all live agents
  • Track agent status in memory (Redis-backed for cross-process visibility)
"""

import asyncio
import json
import os
from typing import Any, Callable, Dict, List, Optional

import asyncpg
import redis.asyncio as aioredis

from brain.global_brain import GlobalBrain
from brain.private_brain import PrivateBrain

TIER_LIMITS = {
    "free":       {"max_agents": 1},
    "pro":        {"max_agents": 5},
    "enterprise": {"max_agents": 999},
    "admin":      {"max_agents": 999},
}


class Orchestrator:
    def __init__(self, pool: asyncpg.Pool, redis: aioredis.Redis, ws_manager):
        self.pool = pool
        self.redis = redis
        self.ws_manager = ws_manager
        self.global_brain = GlobalBrain(pool, redis)

        # user_id → {agent_id → BountyAgent}
        self._agents: Dict[str, Dict[str, Any]] = {}
        # user_id → preferred mode
        self.user_modes: Dict[str, str] = {}

    # ── Spawn / stop ──────────────────────────────────────────────────────────

    async def spawn_agents(self, user_id: str, n: int = 1, mode: str = "bounty", role: str = "user") -> List[str]:
        """Spawn up to n agents for a user. Returns list of spawned agent IDs."""
        from agent import BountyAgent

        tier = await self._get_tier(user_id)
        # admins bypass all limits
        if role == "admin":
            limit = 999
        else:
            limit = TIER_LIMITS.get(tier, {}).get("max_agents", 1)
        current = len(self._agents.get(user_id, {}))
        can_spawn = min(n, max(0, limit - current))

        spawned = []
        for _ in range(can_spawn):
            private = PrivateBrain(self.pool, user_id)

            async def push(data: Dict, uid=user_id):
                await self.ws_manager.send(uid, data)

            agent = BountyAgent(
                user_id=user_id,
                tier=tier,
                mode=self.user_modes.get(user_id, mode),
                private_brain=private,
                global_brain=self.global_brain,
                push=push,
                reports_dir=os.environ.get("REPORTS_DIR", "/app/reports"),
            )

            task = agent.start()

            if user_id not in self._agents:
                self._agents[user_id] = {}
            self._agents[user_id][agent.agent_id] = agent

            # Store status in Redis (TTL = 24h)
            await self.redis.setex(
                f"agent:{agent.agent_id}",
                86400,
                json.dumps({"user_id": user_id, "status": "starting", "mode": mode}),
            )

            spawned.append(agent.agent_id)
            task.add_done_callback(lambda t, aid=agent.agent_id, uid=user_id: self._on_agent_done(uid, aid, t))

        return spawned

    def stop_agent(self, user_id: str, agent_id: str) -> bool:
        agent = self._agents.get(user_id, {}).get(agent_id)
        if agent:
            agent.stop()
            return True
        return False

    async def stop_all_for_user(self, user_id: str) -> int:
        agents = list(self._agents.get(user_id, {}).values())
        for a in agents:
            a.stop()
        return len(agents)

    async def stop_all(self) -> None:
        for user_id in list(self._agents):
            await self.stop_all_for_user(user_id)

    # ── Status ────────────────────────────────────────────────────────────────

    def get_user_status(self, user_id: str) -> List[Dict]:
        agents = self._agents.get(user_id, {})
        return [a.state() for a in agents.values()]

    def count_user_agents(self, user_id: str) -> int:
        return len(self._agents.get(user_id, {}))

    # ── Global brain pubsub ───────────────────────────────────────────────────

    async def listen_global_brain(self) -> None:
        """Background task: relay global technique broadcasts to all connected users."""
        async def on_technique(technique: Dict):
            count = await self.global_brain.get_total_count()
            # Broadcast to all connected WebSocket users
            await self.ws_manager.broadcast({
                "type": "brain_update",
                "technique": technique,
                "total_techniques": count,
            })

        try:
            await self.global_brain.subscribe(on_technique)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _get_tier(self, user_id: str) -> str:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT tier FROM users WHERE id=$1", user_id)
            return row["tier"] if row else "free"

    def _on_agent_done(self, user_id: str, agent_id: str, task: asyncio.Task) -> None:
        self._agents.get(user_id, {}).pop(agent_id, None)
        asyncio.ensure_future(
            self.redis.delete(f"agent:{agent_id}")
        )

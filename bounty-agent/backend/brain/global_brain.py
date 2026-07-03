"""
Global Brain — shared knowledge layer across all agents and users.

Stores proven techniques, bypass patterns, and payloads in PostgreSQL.
Broadcasts new discoveries in real time over Redis pubsub.

Privacy model:
  • Only technique + category + payload are stored — no target/user data.
  • Write access: Pro and Enterprise tiers only.
  • Read access: all tiers.
"""

import json
from typing import Any, Dict, List, Optional

import asyncpg
import redis.asyncio as aioredis

CHANNEL = "global_techniques"


class GlobalBrain:
    def __init__(self, pool: asyncpg.Pool, redis: aioredis.Redis):
        self.pool = pool
        self.redis = redis

    # ── Read ─────────────────────────────────────────────────────────────────

    async def get_techniques(
        self,
        category: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict]:
        """Fetch top techniques ordered by success count."""
        async with self.pool.acquire() as conn:
            if category:
                rows = await conn.fetch(
                    """SELECT id, technique_type, category, title, description,
                              payload, context_hint, success_count
                       FROM global_techniques
                       WHERE category = $1
                       ORDER BY success_count DESC LIMIT $2""",
                    category, limit,
                )
            else:
                rows = await conn.fetch(
                    """SELECT id, technique_type, category, title, description,
                              payload, context_hint, success_count
                       FROM global_techniques
                       ORDER BY success_count DESC LIMIT $1""",
                    limit,
                )
            return [dict(r) for r in rows]

    async def get_total_count(self) -> int:
        async with self.pool.acquire() as conn:
            return await conn.fetchval("SELECT COUNT(*) FROM global_techniques") or 0

    async def get_hot_patterns(self, tech_hints: List[str] = None, limit: int = 10) -> List[Dict]:
        """Return recently discovered high-value patterns, optionally filtered by tech stack hints."""
        async with self.pool.acquire() as conn:
            if tech_hints:
                # Match any hint against context_hint or category
                hint_filter = " OR ".join(
                    f"(LOWER(context_hint) LIKE '%{h.lower()[:30]}%' OR LOWER(category) LIKE '%{h.lower()[:20]}%')"
                    for h in tech_hints[:5]
                )
                rows = await conn.fetch(
                    f"""SELECT technique_type, category, title, payload, context_hint, success_count
                        FROM global_techniques
                        WHERE {hint_filter}
                        ORDER BY success_count DESC, created_at DESC LIMIT $1""",
                    limit,
                )
                if rows:
                    return [dict(r) for r in rows]
            # Fallback: just return top techniques
            rows = await conn.fetch(
                """SELECT technique_type, category, title, payload, context_hint, success_count
                   FROM global_techniques
                   ORDER BY success_count DESC, created_at DESC LIMIT $1""",
                limit,
            )
            return [dict(r) for r in rows]

    # ── Write ─────────────────────────────────────────────────────────────────

    async def contribute_technique(
        self,
        technique_type: str,
        category: str,
        title: str,
        description: str = "",
        payload: str = "",
        context_hint: str = "",
        contributed_by_tier: str = "pro",
    ) -> Dict:
        """
        Save a new technique (or increment success_count if it already exists).
        Broadcasts to all live agents via Redis pubsub.
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO global_techniques
                       (technique_type, category, title, description, payload,
                        context_hint, contributed_by_tier)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)
                   ON CONFLICT DO NOTHING
                   RETURNING id""",
                technique_type, category, title, description,
                payload, context_hint, contributed_by_tier,
            )

            if row is None:
                # Already exists — just bump the counter
                await conn.execute(
                    """UPDATE global_techniques
                       SET success_count = success_count + 1
                       WHERE title = $1 AND category = $2""",
                    title, category,
                )

        technique = {
            "technique_type": technique_type,
            "category": category,
            "title": title,
            "payload": payload,
            "context_hint": context_hint,
        }

        # Broadcast to all live agent instances
        await self.redis.publish(CHANNEL, json.dumps(technique))
        return technique

    # ── Pubsub listener ───────────────────────────────────────────────────────

    async def subscribe(self, on_technique):
        """
        Listen for new techniques on Redis pubsub.
        Calls on_technique(technique_dict) for each new message.
        """
        pubsub = self.redis.pubsub()
        await pubsub.subscribe(CHANNEL)
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    await on_technique(data)
                except Exception:
                    continue

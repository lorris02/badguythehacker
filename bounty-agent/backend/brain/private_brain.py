"""
Private Brain — per-user isolated knowledge store backed by PostgreSQL.

Each user's findings, sessions, and targets are stored filtered by user_id.
Application-level isolation: every query includes WHERE user_id = $N.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

import asyncpg


class PrivateBrain:
    def __init__(self, pool: asyncpg.Pool, user_id: str):
        self.pool = pool
        self.user_id = user_id

    # ── Targets ───────────────────────────────────────────────────────────────

    async def add_target(self, url: str, mode: str = "bounty") -> bool:
        async with self.pool.acquire() as conn:
            try:
                await conn.execute(
                    """INSERT INTO targets (user_id, url, mode)
                       VALUES ($1, $2, $3)
                       ON CONFLICT (user_id, url) DO NOTHING""",
                    self.user_id, url, mode,
                )
                return True
            except Exception:
                return False

    async def get_targets(self, status: Optional[str] = None) -> List[Dict]:
        async with self.pool.acquire() as conn:
            if status:
                rows = await conn.fetch(
                    "SELECT * FROM targets WHERE user_id=$1 AND status=$2 ORDER BY added_at DESC",
                    self.user_id, status,
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM targets WHERE user_id=$1 ORDER BY added_at DESC",
                    self.user_id,
                )
            return [dict(r) for r in rows]

    async def claim_target(self, agent_id: str) -> Optional[Dict]:
        """Atomically claim the highest-scored unclaimed target."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """UPDATE targets SET status='claimed', claimed_by=$1
                   WHERE id = (
                       SELECT id FROM targets
                       WHERE user_id=$2 AND status='unclaimed'
                       ORDER BY score DESC, added_at
                       LIMIT 1
                       FOR UPDATE SKIP LOCKED
                   )
                   RETURNING *""",
                agent_id, self.user_id,
            )
            return dict(row) if row else None

    async def release_target(self, target_url: str, completed: bool = True) -> None:
        status = "completed" if completed else "unclaimed"
        async with self.pool.acquire() as conn:
            await conn.execute(
                """UPDATE targets SET status=$1, claimed_by=NULL
                   WHERE user_id=$2 AND url=$3""",
                status, self.user_id, target_url,
            )

    async def target_count(self) -> int:
        async with self.pool.acquire() as conn:
            return await conn.fetchval(
                "SELECT COUNT(*) FROM targets WHERE user_id=$1", self.user_id
            ) or 0

    # ── Sessions ──────────────────────────────────────────────────────────────

    async def start_session(self, target_url: str, agent_id: str, mode: str) -> str:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO sessions (user_id, target_url, agent_id, mode)
                   VALUES ($1, $2, $3, $4) RETURNING id""",
                self.user_id, target_url, agent_id, mode,
            )
            return str(row["id"])

    async def complete_session(self, session_id: str, findings_count: int = 0) -> None:
        async with self.pool.acquire() as conn:
            await conn.execute(
                """UPDATE sessions
                   SET status='completed', completed_at=NOW(), findings_count=$1
                   WHERE id=$2 AND user_id=$3""",
                findings_count, session_id, self.user_id,
            )

    async def fail_session(self, session_id: str, reason: str = "") -> None:
        async with self.pool.acquire() as conn:
            await conn.execute(
                """UPDATE sessions SET status='failed', completed_at=NOW()
                   WHERE id=$1 AND user_id=$2""",
                session_id, self.user_id,
            )

    # ── Findings ──────────────────────────────────────────────────────────────

    async def save_finding(
        self,
        session_id: str,
        target: str,
        vuln_type: str,
        severity: str,
        url: str,
        description: str,
        poc: str = "",
        confirmed: bool = False,
        cvss_score: Optional[float] = None,
        cvss_vector: Optional[str] = None,
        cvss_components: Optional[Dict] = None,
        report_path: str = "",
        submit_url: str = "",
        platform: str = "",
        program_name: str = "",
    ) -> str:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO findings
                   (user_id, session_id, target, vuln_type, severity, url,
                    description, poc, confirmed, cvss_score, cvss_vector,
                    cvss_components, report_path, submit_url, platform, program_name)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
                   RETURNING id""",
                self.user_id,
                session_id,
                target,
                vuln_type,
                severity,
                url,
                description,
                poc,
                confirmed,
                cvss_score,
                cvss_vector,
                json.dumps(cvss_components) if cvss_components else None,
                report_path,
                submit_url,
                platform,
                program_name,
            )
            return str(row["id"])

    async def get_findings(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        confirmed_only: bool = False,
    ) -> List[Dict]:
        async with self.pool.acquire() as conn:
            clauses = ["user_id=$1"]
            params: list = [self.user_id]
            if severity:
                params.append(severity)
                clauses.append(f"severity=${len(params)}")
            if confirmed_only:
                clauses.append("confirmed=TRUE")
            where = " AND ".join(clauses)
            params.append(limit)
            rows = await conn.fetch(
                f"""SELECT id, target, vuln_type, severity, url, confirmed,
                           cvss_score, cvss_vector, report_path, discovered_at,
                           submit_url, platform, program_name
                    FROM findings WHERE {where}
                    ORDER BY discovered_at DESC LIMIT ${len(params)}""",
                *params,
            )
            return [dict(r) for r in rows]

    async def get_finding(self, finding_id: str) -> Optional[Dict]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM findings WHERE id=$1 AND user_id=$2",
                finding_id, self.user_id,
            )
            if not row:
                return None
            d = dict(row)
            if d.get("cvss_components") and isinstance(d["cvss_components"], str):
                try:
                    d["cvss_components"] = json.loads(d["cvss_components"])
                except Exception:
                    pass
            return d

    async def finding_count(self) -> int:
        async with self.pool.acquire() as conn:
            return await conn.fetchval(
                "SELECT COUNT(*) FROM findings WHERE user_id=$1", self.user_id
            ) or 0

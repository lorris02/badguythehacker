"""PostgreSQL connection pool and schema initialisation."""

import os
from typing import Optional

import asyncpg

_pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            os.environ["DATABASE_URL"],
            min_size=2,
            max_size=20,
        )
    return _pool


async def init_db(pool: asyncpg.Pool) -> None:
    """Create all tables on first run."""
    async with pool.acquire() as conn:
        await conn.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                email        TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                tier         TEXT DEFAULT 'free',
                role         TEXT DEFAULT 'user',
                created_at   TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        # Migrate existing tables that predate the role column
        await conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user'")

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                url          TEXT NOT NULL,
                mode         TEXT DEFAULT 'bounty',
                status       TEXT DEFAULT 'unclaimed',
                claimed_by   TEXT,
                platform     TEXT,
                program_name TEXT,
                submit_url   TEXT,
                added_at     TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE (user_id, url)
            )
        """)
        for col, typedef in [
            ("platform",     "TEXT"),
            ("program_name", "TEXT"),
            ("submit_url",   "TEXT"),
            ("score",        "INTEGER DEFAULT 50"),
        ]:
            await conn.execute(f"ALTER TABLE targets ADD COLUMN IF NOT EXISTS {col} {typedef}")

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                target_url    TEXT NOT NULL,
                mode          TEXT DEFAULT 'bounty',
                agent_id      TEXT,
                status        TEXT DEFAULT 'running',
                started_at    TIMESTAMPTZ DEFAULT NOW(),
                completed_at  TIMESTAMPTZ,
                findings_count INTEGER DEFAULT 0
            )
        """)

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                session_id     UUID REFERENCES sessions(id) ON DELETE SET NULL,
                target         TEXT,
                vuln_type      TEXT,
                severity       TEXT,
                url            TEXT,
                description    TEXT,
                poc            TEXT,
                confirmed      BOOLEAN DEFAULT FALSE,
                cvss_score     REAL,
                cvss_vector    TEXT,
                cvss_components JSONB,
                report_path    TEXT,
                platform       TEXT,
                program_name   TEXT,
                submit_url     TEXT,
                discovered_at  TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        # Migrate existing tables
        for col, typedef in [
            ("platform",     "TEXT"),
            ("program_name", "TEXT"),
            ("submit_url",   "TEXT"),
        ]:
            await conn.execute(f"ALTER TABLE findings ADD COLUMN IF NOT EXISTS {col} {typedef}")

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS global_techniques (
                id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                technique_type     TEXT NOT NULL,
                category           TEXT NOT NULL,
                title              TEXT NOT NULL,
                description        TEXT,
                payload            TEXT,
                context_hint       TEXT,
                success_count      INTEGER DEFAULT 1,
                contributed_by_tier TEXT,
                created_at         TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        # Indexes
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_user ON targets(user_id, status)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_user ON findings(user_id, discovered_at DESC)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, started_at DESC)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_techniques_cat ON global_techniques(category)")

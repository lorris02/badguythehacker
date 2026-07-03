"""Agent management REST endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.auth import get_current_user

router = APIRouter()

TIER_LIMITS = {
    "free":       {"max_agents": 1,    "max_targets": 5},
    "pro":        {"max_agents": 5,    "max_targets": None},
    "enterprise": {"max_agents": None, "max_targets": None},
    "admin":      {"max_agents": None, "max_targets": None},
}

def _is_admin(user: dict) -> bool:
    return user.get("role") == "admin"

def _limits(user: dict) -> dict:
    if _is_admin(user):
        return TIER_LIMITS["admin"]
    return TIER_LIMITS.get(user.get("tier", "free"), TIER_LIMITS["free"])


class SpawnRequest(BaseModel):
    count: int = 1
    mode: str = "bounty"


class AddTargetRequest(BaseModel):
    url: str
    mode: str = "bounty"


@router.get("/")
async def list_agents(request: Request, user: dict = Depends(get_current_user)):
    orch = request.app.state.orchestrator
    agents = orch.get_user_status(user["sub"])
    return {"agents": agents, "count": len(agents)}


@router.post("/spawn", status_code=201)
async def spawn(body: SpawnRequest, request: Request, user: dict = Depends(get_current_user)):
    orch = request.app.state.orchestrator
    limits = _limits(user)
    max_a = limits["max_agents"]
    current = orch.count_user_agents(user["sub"])

    if max_a and current >= max_a:
        raise HTTPException(
            status_code=403,
            detail=f"Agent limit reached for {user['tier']} tier ({max_a} max). Upgrade your plan.",
        )

    allowed = min(body.count, (max_a - current) if max_a else body.count)
    agent_ids = await orch.spawn_agents(user["sub"], allowed, mode=body.mode)
    return {"spawned": agent_ids, "count": len(agent_ids)}


@router.delete("/{agent_id}")
async def stop_agent(agent_id: str, request: Request, user: dict = Depends(get_current_user)):
    orch = request.app.state.orchestrator
    ok = orch.stop_agent(user["sub"], agent_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"stopped": agent_id}


@router.delete("/")
async def stop_all(request: Request, user: dict = Depends(get_current_user)):
    orch = request.app.state.orchestrator
    count = await orch.stop_all_for_user(user["sub"])
    return {"stopped_count": count}


# ── Target pool management ────────────────────────────────────────────────────

@router.get("/targets")
async def list_targets(request: Request, user: dict = Depends(get_current_user)):
    pool = request.app.state.pool
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, url, mode, status, added_at FROM targets WHERE user_id=$1 ORDER BY added_at DESC",
            user["sub"],
        )
    return {"targets": [dict(r) for r in rows]}


@router.post("/targets", status_code=201)
async def add_target(body: AddTargetRequest, request: Request, user: dict = Depends(get_current_user)):
    pool = request.app.state.pool
    limits = _limits(user)
    max_t = limits["max_targets"]

    if max_t:
        async with pool.acquire() as conn:
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM targets WHERE user_id=$1", user["sub"]
            )
            if count >= max_t:
                raise HTTPException(
                    status_code=403,
                    detail=f"Target limit reached ({max_t} max for {user['tier']} tier). Upgrade for unlimited targets.",
                )

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO targets (user_id, url, mode)
               VALUES ($1,$2,$3)
               ON CONFLICT (user_id, url) DO UPDATE SET mode=EXCLUDED.mode
               RETURNING id, url, mode, status""",
            user["sub"], body.url, body.mode,
        )
    return dict(row)


@router.delete("/targets/{target_id}")
async def remove_target(target_id: str, request: Request, user: dict = Depends(get_current_user)):
    pool = request.app.state.pool
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM targets WHERE id=$1 AND user_id=$2 AND status='unclaimed'",
            target_id, user["sub"],
        )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Target not found or currently claimed")
    return {"deleted": target_id}

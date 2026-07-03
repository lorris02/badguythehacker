"""Findings REST endpoints."""

import os

from fastapi import APIRouter, Depends, HTTPException, Request

from api.auth import get_current_user
from brain.private_brain import PrivateBrain

router = APIRouter()


@router.get("/")
async def list_findings(
    request: Request,
    user: dict = Depends(get_current_user),
    severity: str = "",
    confirmed: bool = False,
    limit: int = 50,
):
    brain = PrivateBrain(request.app.state.pool, user["sub"])
    findings = await brain.get_findings(
        limit=limit,
        severity=severity or None,
        confirmed_only=confirmed,
    )
    return {"findings": findings, "count": len(findings)}


@router.get("/{finding_id}")
async def get_finding(finding_id: str, request: Request, user: dict = Depends(get_current_user)):
    brain = PrivateBrain(request.app.state.pool, user["sub"])
    finding = await brain.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get("/{finding_id}/report")
async def get_report(finding_id: str, request: Request, user: dict = Depends(get_current_user)):
    brain = PrivateBrain(request.app.state.pool, user["sub"])
    finding = await brain.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    report_path = finding.get("report_path", "")
    if not report_path or not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report file not found")

    with open(report_path, encoding="utf-8") as f:
        content = f.read()

    return {"finding_id": finding_id, "report_path": report_path, "content": content}


@router.get("/stats/summary")
async def stats(request: Request, user: dict = Depends(get_current_user)):
    pool = request.app.state.pool
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM findings WHERE user_id=$1", user["sub"]) or 0
        confirmed = await conn.fetchval("SELECT COUNT(*) FROM findings WHERE user_id=$1 AND confirmed=TRUE", user["sub"]) or 0
        by_severity = await conn.fetch(
            "SELECT severity, COUNT(*) as count FROM findings WHERE user_id=$1 GROUP BY severity",
            user["sub"],
        )
        sessions = await conn.fetchval("SELECT COUNT(*) FROM sessions WHERE user_id=$1", user["sub"]) or 0

    return {
        "total_findings": total,
        "confirmed": confirmed,
        "by_severity": {r["severity"]: r["count"] for r in by_severity},
        "total_sessions": sessions,
    }

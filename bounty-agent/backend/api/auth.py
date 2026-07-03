"""JWT auth — register, login, get current user."""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

router = APIRouter()
bearer = HTTPBearer()
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 72


def _secret() -> str:
    s = os.environ.get("JWT_SECRET", "")
    if not s:
        raise RuntimeError("JWT_SECRET not set")
    return s


def _admin_email() -> str:
    return os.environ.get("ADMIN_EMAIL", "").lower().strip()


def create_token(user_id: str, email: str, tier: str, role: str = "user") -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode(
        {"sub": user_id, "email": email, "tier": tier, "role": role, "exp": expire},
        _secret(),
        algorithm=ALGORITHM,
    )


def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, _secret(), algorithms=[ALGORITHM])
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")


async def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
) -> dict:
    return verify_token(creds.credentials)


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ── Schemas ───────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/register", status_code=201)
async def register(body: RegisterRequest, request: Request):
    pool = request.app.state.pool
    email_lower = body.email.lower()
    is_admin = email_lower == _admin_email() and _admin_email() != ""
    role = "admin" if is_admin else "user"

    async with pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT id FROM users WHERE email=$1", email_lower)
        if existing:
            raise HTTPException(status_code=409, detail="Email already registered")

        hashed = pwd.hash(body.password)
        row = await conn.fetchrow(
            "INSERT INTO users (email, password_hash, role) VALUES ($1,$2,$3) RETURNING id, tier, role",
            email_lower, hashed, role,
        )

    token = create_token(str(row["id"]), email_lower, row["tier"], row["role"])
    return {"access_token": token, "token_type": "bearer", "tier": row["tier"], "role": row["role"]}


@router.post("/login")
async def login(body: LoginRequest, request: Request):
    pool = request.app.state.pool
    email_lower = body.email.lower()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, password_hash, tier, role FROM users WHERE email=$1", email_lower
        )

    if not row or not pwd.verify(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(str(row["id"]), email_lower, row["tier"], row["role"])
    return {"access_token": token, "token_type": "bearer", "tier": row["tier"], "role": row["role"]}


@router.get("/me")
async def me(user: dict = Depends(get_current_user)):
    return {
        "id": user["sub"],
        "email": user["email"],
        "tier": user["tier"],
        "role": user.get("role", "user"),
    }

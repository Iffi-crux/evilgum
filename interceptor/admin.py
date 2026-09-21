"""
Admin control plane + role store.

Backend-agnostic role loader for RbacEngine (SQLite now, Postgres-ready). The
admin router is mounted behind a scope check (auth.require_admin) in proxy.py, so
authority is a proven IdP scope, never a username. Role mutations invalidate the
RBAC cache in the current process. Deploy one worker for immediate revocation.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import Column, String, JSON

_default_db = str(Path(os.environ.get("EVILGUM_DATA_DIR", "data")).resolve() / "admin.db").replace("\\", "/")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///" + _default_db)
engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()


class RoleModel(Base):
    # Deliberately do not inherit unscoped grants from the legacy roles table.
    __tablename__ = "tenant_roles"
    tenant_id = Column(String, primary_key=True)
    agent_id = Column(String, primary_key=True, index=True)
    allowed_tools = Column(JSON, nullable=False)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def sqlalchemy_role_loader(tenant_id: str, agent_id: str) -> Optional[list]:
    async with AsyncSessionLocal() as session:
        role = await session.get(RoleModel, (tenant_id, agent_id))
        return role.allowed_tools if role else None


router = APIRouter(prefix="/admin", tags=["admin"])


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


@router.post("/roles/{agent_id}")
async def update_role(agent_id: str, allowed_tools: list[str], request: Request,
                      db: AsyncSession = Depends(get_db)):
    tenant_id = request.state.principal.tenant_id
    role = await db.get(RoleModel, (tenant_id, agent_id))
    if role:
        role.allowed_tools = allowed_tools
    else:
        db.add(RoleModel(tenant_id=tenant_id, agent_id=agent_id, allowed_tools=allowed_tools))
    await db.commit()
    # Invalidate the RBAC cache so the change is visible immediately.
    rbac = getattr(request.app.state, "rbac", None)
    if rbac is not None:
        rbac.invalidate(agent_id, tenant_id=tenant_id)
    return {"status": "ok", "agent_id": agent_id, "allowed_tools": allowed_tools}


@router.get("/roles/{agent_id}")
async def get_role(agent_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    role = await db.get(RoleModel, (request.state.principal.tenant_id, agent_id))
    return {"allowed_tools": role.allowed_tools if role else []}

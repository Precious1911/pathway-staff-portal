from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .audit import log_activity
from .config import get_settings
from .database import get_db
from .models import ClientAssignment, Role, SessionToken, StaffUser


ROOT = Path(__file__).resolve().parents[1]
SETTINGS = get_settings(ROOT)


def utc_now_like(value: datetime | None = None) -> datetime:
    now = datetime.now(timezone.utc)
    if value is not None and value.tzinfo is None:
        return now.replace(tzinfo=None)
    return now


def is_trusted_proxy(client_host: str) -> bool:
    try:
        addr = ipaddress.ip_address(client_host)
    except ValueError:
        return False
    for entry in SETTINGS.trusted_proxy_ips:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_secure_request(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    client_host = request.client.host if request.client else ""
    return is_trusted_proxy(client_host) and request.headers.get("x-forwarded-proto", "").lower() == "https"


async def require_https(request: Request) -> None:
    if SETTINGS.require_https and not is_secure_request(request):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="HTTPS is required")


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(require_https),
) -> StaffUser:
    token = request.cookies.get("staff_session")
    if not token:
        raise HTTPException(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})
    db.execute(delete(SessionToken).where(SessionToken.expires_at <= utc_now_like()))
    session = db.execute(
        select(SessionToken).where(SessionToken.token == token).limit(1)
    ).scalar_one_or_none()
    if not session or session.expires_at <= utc_now_like(session.expires_at):
        raise HTTPException(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})
    user = db.get(StaffUser, session.user_id)
    if not user or not user.active:
        raise HTTPException(status_code=status.HTTP_302_FOUND, headers={"Location": "/login"})
    return user


def require_roles(*roles: str) -> Callable:
    def dependency(user: StaffUser = Depends(get_current_user)) -> StaffUser:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        return user

    return dependency


def client_ids_for_user(db: Session, user: StaffUser) -> list[int]:
    if user.role == Role.ADMIN:
        return [row[0] for row in db.execute(select(ClientAssignment.client_id).distinct()).all()]
    return [row[0] for row in db.execute(select(ClientAssignment.client_id).where(ClientAssignment.user_id == user.id)).all()]


def ensure_client_access(db: Session, user: StaffUser, client_id: int) -> None:
    if user.role == Role.ADMIN:
        return
    assigned = db.execute(
        select(ClientAssignment).where(ClientAssignment.user_id == user.id, ClientAssignment.client_id == client_id)
    ).scalar_one_or_none()
    if not assigned:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Client not assigned to this user")

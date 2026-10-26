from __future__ import annotations

from sqlalchemy.orm import Session

from .models import ActivityLog


def log_activity(
    db: Session,
    actor_user_id: int | None,
    action: str,
    target_type: str,
    target_id: int | None,
    details: str,
) -> None:
    db.add(
        ActivityLog(
            actor_user_id=actor_user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details,
        )
    )


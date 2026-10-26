from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Role:
    ADMIN = "Admin"
    THERAPIST = "Therapist"
    SUPPORT = "Support Staff"


class StaffUser(Base):
    __tablename__ = "staff_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    username: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    password_salt: Mapped[str] = mapped_column(String(128), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SessionToken(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("staff_users.id", ondelete="CASCADE"), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user: Mapped["StaffUser"] = relationship()


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    date_of_birth: Mapped[date | None] = mapped_column(Date, nullable=True)
    primary_concern: Mapped[str | None] = mapped_column(Text, nullable=True)
    intake_status: Mapped[str] = mapped_column(String(40), default="MISSING", nullable=False)
    billing_documents: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ClientAssignment(Base):
    __tablename__ = "client_assignments"
    __table_args__ = (UniqueConstraint("user_id", "client_id", name="uq_user_client_assignment"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("staff_users.id", ondelete="CASCADE"), nullable=False, index=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), nullable=False, index=True)
    assignment_role: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user: Mapped["StaffUser"] = relationship()
    client: Mapped["Client"] = relationship()


class SoapNote(Base):
    __tablename__ = "soap_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), nullable=False, index=True)
    session_date: Mapped[date] = mapped_column(Date, nullable=False)
    subjective: Mapped[str] = mapped_column(Text, default="", nullable=False)
    objective: Mapped[str] = mapped_column(Text, default="", nullable=False)
    assessment: Mapped[str] = mapped_column(Text, default="", nullable=False)
    plan: Mapped[str] = mapped_column(Text, default="", nullable=False)
    risk_assessment: Mapped[str] = mapped_column(Text, default="", nullable=False)
    interventions: Mapped[str] = mapped_column(Text, default="", nullable=False)
    therapist_signature: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    created_by: Mapped[int] = mapped_column(ForeignKey("staff_users.id"), nullable=False)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("staff_users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TreatmentPlan(Base):
    __tablename__ = "treatment_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), nullable=False, index=True)
    created_date: Mapped[date] = mapped_column(Date, nullable=False)
    presenting_problem: Mapped[str] = mapped_column(Text, default="", nullable=False)
    diagnosis: Mapped[str] = mapped_column(Text, default="", nullable=False)
    long_term_goal: Mapped[str] = mapped_column(Text, default="", nullable=False)
    short_term_goals: Mapped[str] = mapped_column(Text, default="", nullable=False)
    objectives: Mapped[str] = mapped_column(Text, default="", nullable=False)
    interventions: Mapped[str] = mapped_column(Text, default="", nullable=False)
    frequency: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    review_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    client_signature: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    therapist_signature: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    created_by: Mapped[int] = mapped_column(ForeignKey("staff_users.id"), nullable=False)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("staff_users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SummaryReport(Base):
    __tablename__ = "summary_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), nullable=False, index=True)
    report_date: Mapped[date] = mapped_column(Date, nullable=False)
    referral_reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    current_concerns: Mapped[str] = mapped_column(Text, default="", nullable=False)
    progress_to_date: Mapped[str] = mapped_column(Text, default="", nullable=False)
    interventions_used: Mapped[str] = mapped_column(Text, default="", nullable=False)
    barriers: Mapped[str] = mapped_column(Text, default="", nullable=False)
    recommendations: Mapped[str] = mapped_column(Text, default="", nullable=False)
    clinical_summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    therapist_signature: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    created_by: Mapped[int] = mapped_column(ForeignKey("staff_users.id"), nullable=False)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("staff_users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SafetyPlan(Base):
    __tablename__ = "safety_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), nullable=False, index=True)
    created_date: Mapped[date] = mapped_column(Date, nullable=False)
    warning_signs: Mapped[str] = mapped_column(Text, default="", nullable=False)
    internal_coping_strategies: Mapped[str] = mapped_column(Text, default="", nullable=False)
    distraction_places: Mapped[str] = mapped_column(Text, default="", nullable=False)
    help_people: Mapped[str] = mapped_column(Text, default="", nullable=False)
    professionals_resources: Mapped[str] = mapped_column(Text, default="", nullable=False)
    means_safety_steps: Mapped[str] = mapped_column(Text, default="", nullable=False)
    reasons_for_living: Mapped[str] = mapped_column(Text, default="", nullable=False)
    signature_and_date: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    created_by: Mapped[int] = mapped_column(ForeignKey("staff_users.id"), nullable=False)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("staff_users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Worksheet(Base):
    __tablename__ = "worksheets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    assigned_client_id: Mapped[int | None] = mapped_column(ForeignKey("clients.id"), nullable=True, index=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("staff_users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    document_type: Mapped[str] = mapped_column(String(120), nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    storage_key: Mapped[str] = mapped_column(String(500), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(120), default="application/octet-stream", nullable=False)
    created_by: Mapped[int] = mapped_column(ForeignKey("staff_users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ActivityLog(Base):
    __tablename__ = "activity_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("staff_users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    target_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    details: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


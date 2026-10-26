from __future__ import annotations

from datetime import date

from pydantic import BaseModel


class LoginForm(BaseModel):
    username: str
    password: str


class SoapNoteIn(BaseModel):
    client_id: int
    session_date: date
    subjective: str = ""
    objective: str = ""
    assessment: str = ""
    plan: str = ""
    risk_assessment: str = ""
    interventions: str = ""
    therapist_signature: str = ""


class TreatmentPlanIn(BaseModel):
    client_id: int
    created_date: date
    presenting_problem: str = ""
    diagnosis: str = ""
    long_term_goal: str = ""
    short_term_goals: str = ""
    objectives: str = ""
    interventions: str = ""
    frequency: str = ""
    review_date: date | None = None
    client_signature: str = ""
    therapist_signature: str = ""


class SummaryReportIn(BaseModel):
    client_id: int
    report_date: date
    referral_reason: str = ""
    current_concerns: str = ""
    progress_to_date: str = ""
    interventions_used: str = ""
    barriers: str = ""
    recommendations: str = ""
    clinical_summary: str = ""
    therapist_signature: str = ""


class SafetyPlanIn(BaseModel):
    client_id: int
    created_date: date
    warning_signs: str = ""
    internal_coping_strategies: str = ""
    distraction_places: str = ""
    help_people: str = ""
    professionals_resources: str = ""
    means_safety_steps: str = ""
    reasons_for_living: str = ""
    signature_and_date: str = ""


class WorksheetIn(BaseModel):
    title: str
    category: str
    description: str = ""
    assigned_client_id: int | None = None


from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, func, or_, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from .audit import log_activity
from .config import get_settings
from .database import Base, engine, get_db
from .dependencies import ensure_client_access, get_current_user, require_https, require_roles, utc_now_like
from .models import (
    ActivityLog,
    Client,
    ClientAssignment,
    Document,
    Role,
    SafetyPlan,
    SessionToken,
    SoapNote,
    StaffUser,
    SummaryReport,
    TreatmentPlan,
    Worksheet,
)
from .security import generate_session_token, hash_password, make_session_expiry, verify_password
from .seed import seed_data
from .storage import build_storage


ROOT = Path(__file__).resolve().parents[1]
SETTINGS = get_settings(ROOT)
app = FastAPI(title=SETTINGS.app_name, debug=SETTINGS.debug)
templates = Jinja2Templates(directory=str(ROOT / "webapp" / "templates"))
app.mount("/static", StaticFiles(directory=str(ROOT / "webapp" / "static")), name="static")
STORAGE = build_storage(ROOT)


DEMO_SEED_USERS = [
    ("Admin", "drbarnett_admin", "see console output from the seed script"),
    ("Therapist", "therapist_jackson", "see console output from the seed script"),
    ("Therapist 2", "therapist_williams", "see console output from the seed script"),
    ("Support Staff", "assistant_morgan", "see console output from the seed script"),
]


MIN_PASSWORD_LENGTH = 12
VALID_ROLES = {Role.ADMIN, Role.THERAPIST, Role.SUPPORT}


def today_value() -> str:
    return datetime.now().strftime("%Y-%m-%d")


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    with Session(bind=engine) as db:
        seed_data(db, STORAGE)


def dashboard_heading(role: str) -> str:
    return {
        Role.ADMIN: "Admin Dashboard",
        Role.THERAPIST: "Therapist Dashboard",
        Role.SUPPORT: "Support Dashboard",
    }[role]


def permission_summary(role: str) -> dict[str, list[str]]:
    if role == Role.ADMIN:
        return {
            "allowed": [
                "All clients, all notes, all documents, and all worksheets",
                "Staff management, client assignments, reports, settings, and audit review",
                "Full portal oversight for internal rollout",
            ],
            "restricted": ["No admin restrictions in this hosted baseline"],
        }
    if role == Role.THERAPIST:
        return {
            "allowed": [
                "Assigned clients only",
                "Create and edit SOAP notes, treatment plans, summary reports, and safety plans",
                "Upload worksheets and documents for assigned clients",
            ],
            "restricted": [
                "No admin-only reports, settings, assignments, or audit pages",
                "No access to unassigned clients",
            ],
        }
    return {
        "allowed": [
            "Assigned clients only",
            "Upload worksheets and documents",
            "Review billing/documents and flag missing forms",
        ],
        "restricted": [
            "Cannot create or edit SOAP notes",
            "Cannot create or edit treatment plans",
            "Cannot create or edit safety plans",
            "No admin-only pages",
        ],
    }


def scoped_clients(db: Session, user: StaffUser, search: str = "") -> list[Client]:
    stmt = select(Client)
    if user.role != Role.ADMIN:
        stmt = stmt.join(ClientAssignment, ClientAssignment.client_id == Client.id).where(ClientAssignment.user_id == user.id)
    if search:
        stmt = stmt.where(Client.name.ilike(f"%{search}%"))
    stmt = stmt.order_by(Client.name)
    return list(db.execute(stmt).scalars().unique().all())


def status_for_client(db: Session, client: Client) -> dict[str, Any]:
    sessions_count = db.scalar(select(func.count(SoapNote.id)).where(SoapNote.client_id == client.id)) or 0
    treatment_count = db.scalar(select(func.count(TreatmentPlan.id)).where(TreatmentPlan.client_id == client.id)) or 0
    summary_count = db.scalar(select(func.count(SummaryReport.id)).where(SummaryReport.client_id == client.id)) or 0
    safety_count = db.scalar(select(func.count(SafetyPlan.id)).where(SafetyPlan.client_id == client.id)) or 0
    document_count = db.scalar(select(func.count(Document.id)).where(Document.client_id == client.id)) or 0
    treatment_status = "OK" if treatment_count else "MISSING"
    missing_forms_flag = "OK" if summary_count and safety_count else "MISSING"
    if treatment_status == "OK" and missing_forms_flag == "OK" and client.intake_status == "COMPLETE":
        alert = "GREEN"
    elif sessions_count > 0 and (treatment_status != "OK" or missing_forms_flag != "OK" or client.intake_status != "COMPLETE"):
        alert = "RED"
    else:
        alert = "YELLOW"
    return {
        "client": client,
        "sessions_count": sessions_count,
        "treatment_plan_status": treatment_status,
        "missing_forms_flag": missing_forms_flag,
        "alert_level": alert,
        "document_count": document_count,
    }


def redirect(location: str) -> RedirectResponse:
    return RedirectResponse(location, status_code=302)


def note_context(
    request: Request,
    user: StaffUser,
    clients: list[Client],
    kind: str,
    action: str,
    record: Any | None = None,
    client_id: int | None = None,
    heading: str | None = None,
) -> dict[str, Any]:
    return {
        "request": request,
        "user": user,
        "clients": clients,
        "kind": kind,
        "action": action,
        "record": record,
        "heading": heading or f"New {kind.replace('_', ' ').title()}",
        "today": today_value(),
        "selected_client_id": client_id or (record.client_id if record else None),
    }


def fetch_record_or_404(db: Session, model: Any, record_id: int) -> Any:
    record = db.get(model, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return record


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "app": SETTINGS.app_name, "environment": SETTINGS.environment}


@app.get("/")
def root(request: Request) -> RedirectResponse:
    if request.cookies.get("staff_session"):
        return redirect("/dashboard")
    return redirect("/login")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = "") -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": error,
            "app_name": SETTINGS.app_name,
            "seeded_users": DEMO_SEED_USERS if SETTINGS.show_demo_credentials else [],
        },
    )


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
    _: None = Depends(require_https),
):
    empty_users = DEMO_SEED_USERS if SETTINGS.show_demo_credentials else []
    user = db.execute(select(StaffUser).where(StaffUser.username == username, StaffUser.active.is_(True))).scalar_one_or_none()

    if user and user.locked_until and user.locked_until <= utc_now_like(user.locked_until):
        user.locked_until = None
        user.failed_login_attempts = 0
        db.commit()

    if user and user.locked_until and user.locked_until > utc_now_like(user.locked_until):
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "error": "Account temporarily locked after repeated failed attempts. Try again later.",
                "app_name": SETTINGS.app_name,
                "seeded_users": empty_users,
            },
            status_code=429,
        )

    if not user or not verify_password(password, user.password_salt, user.password_hash):
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= SETTINGS.max_login_attempts:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=SETTINGS.login_lockout_minutes)
                log_activity(db, user.id, "account locked", "session", None, "Too many failed login attempts")
            db.commit()
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid username or password.", "app_name": SETTINGS.app_name, "seeded_users": empty_users},
            status_code=400,
        )
    if SETTINGS.require_mfa and not user.mfa_enabled:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "MFA is required in hosted mode. Enable MFA before deployment.", "app_name": SETTINGS.app_name, "seeded_users": empty_users},
            status_code=400,
        )
    user.failed_login_attempts = 0
    user.locked_until = None
    db.query(SessionToken).filter(
        or_(SessionToken.user_id == user.id, SessionToken.expires_at <= datetime.now(timezone.utc))
    ).delete(synchronize_session=False)
    session = SessionToken(token=generate_session_token(), user_id=user.id, expires_at=make_session_expiry(SETTINGS.session_hours))
    db.add(session)
    log_activity(db, user.id, "login", "session", None, f"Role {user.role}")
    db.commit()
    response = redirect("/dashboard")
    response.set_cookie(
        "staff_session",
        session.token,
        httponly=True,
        secure=SETTINGS.require_https,
        samesite="lax",
        max_age=SETTINGS.session_hours * 3600,
    )
    return response


@app.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    token = request.cookies.get("staff_session")
    if token:
        db.query(SessionToken).filter(SessionToken.token == token).delete(synchronize_session=False)
        db.commit()
    response = redirect("/login")
    response.delete_cookie("staff_session")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    q: str = "",
    user: StaffUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    statuses = [status_for_client(db, client) for client in scoped_clients(db, user, q)]
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "query": q,
            "statuses": statuses,
            "heading": dashboard_heading(user.role),
            "permission_summary": permission_summary(user.role),
            "total_sessions": sum(int(row["sessions_count"]) for row in statuses),
            "red_alerts": sum(1 for row in statuses if row["alert_level"] == "RED"),
        },
    )


@app.get("/clients", response_class=HTMLResponse)
def client_list(
    request: Request,
    q: str = "",
    user: StaffUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    statuses = [status_for_client(db, client) for client in scoped_clients(db, user, q)]
    return templates.TemplateResponse(request, "clients.html", {"user": user, "query": q, "statuses": statuses})


@app.get("/clients/{client_id}", response_class=HTMLResponse)
def client_detail(
    request: Request,
    client_id: int,
    tab: str = "overview",
    user: StaffUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    client = db.get(Client, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    ensure_client_access(db, user, client_id)
    can_view_clinical = user.role in {Role.ADMIN, Role.THERAPIST}
    if not can_view_clinical and tab in {"soap", "treatment", "summary", "safety"}:
        raise HTTPException(status_code=403, detail="Clinical records are not available to this role")
    context = {
        "request": request,
        "user": user,
        "client": client,
        "tab": tab,
        "status": status_for_client(db, client),
        "soap_notes": list(db.execute(select(SoapNote).where(SoapNote.client_id == client_id).order_by(SoapNote.session_date.desc())).scalars().all()) if can_view_clinical else [],
        "treatment_plans": list(db.execute(select(TreatmentPlan).where(TreatmentPlan.client_id == client_id).order_by(TreatmentPlan.created_date.desc())).scalars().all()) if can_view_clinical else [],
        "summary_reports": list(db.execute(select(SummaryReport).where(SummaryReport.client_id == client_id).order_by(SummaryReport.report_date.desc())).scalars().all()) if can_view_clinical else [],
        "safety_plans": list(db.execute(select(SafetyPlan).where(SafetyPlan.client_id == client_id).order_by(SafetyPlan.created_date.desc())).scalars().all()) if can_view_clinical else [],
        "worksheets": list(db.execute(select(Worksheet).where(Worksheet.assigned_client_id == client_id).order_by(Worksheet.created_at.desc())).scalars().all()),
        "documents": list(db.execute(select(Document).where(Document.client_id == client_id).order_by(Document.created_at.desc())).scalars().all()),
        "can_edit_clinical": user.role in {Role.ADMIN, Role.THERAPIST},
        "can_upload_support": user.role in {Role.ADMIN, Role.THERAPIST, Role.SUPPORT},
        "can_flag_missing": user.role in {Role.ADMIN, Role.SUPPORT},
    }
    return templates.TemplateResponse(request, "client_detail.html", context)


@app.get("/soap/new", response_class=HTMLResponse)
def new_soap_page(
    request: Request,
    client_id: int | None = None,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "form_note.html",
        note_context(request, user, scoped_clients(db, user), "soap", "/soap/new", None, client_id),
    )


@app.post("/soap/new")
def create_soap(
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
    client_id: int = Form(...),
    session_date: str = Form(...),
    subjective: str = Form(""),
    objective: str = Form(""),
    assessment: str = Form(""),
    plan: str = Form(""),
    risk_assessment: str = Form(""),
    interventions: str = Form(""),
    therapist_signature: str = Form(""),
) -> RedirectResponse:
    ensure_client_access(db, user, client_id)
    record = SoapNote(
        client_id=client_id,
        session_date=datetime.strptime(session_date, "%Y-%m-%d").date(),
        subjective=subjective,
        objective=objective,
        assessment=assessment,
        plan=plan,
        risk_assessment=risk_assessment,
        interventions=interventions,
        therapist_signature=therapist_signature,
        created_by=user.id,
    )
    db.add(record)
    db.flush()
    log_activity(db, user.id, "created soap note", "soap_note", record.id, f"Client ID {client_id}")
    db.commit()
    return redirect(f"/clients/{client_id}?tab=soap")


@app.get("/soap/{note_id}/edit", response_class=HTMLResponse)
def edit_soap_page(
    request: Request,
    note_id: int,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    record = fetch_record_or_404(db, SoapNote, note_id)
    ensure_client_access(db, user, record.client_id)
    return templates.TemplateResponse(
        request,
        "form_note.html",
        note_context(request, user, scoped_clients(db, user), "soap", f"/soap/{note_id}/edit", record, heading="Edit SOAP Note"),
    )


@app.post("/soap/{note_id}/edit")
def update_soap(
    note_id: int,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
    client_id: int = Form(...),
    session_date: str = Form(...),
    subjective: str = Form(""),
    objective: str = Form(""),
    assessment: str = Form(""),
    plan: str = Form(""),
    risk_assessment: str = Form(""),
    interventions: str = Form(""),
    therapist_signature: str = Form(""),
) -> RedirectResponse:
    record = fetch_record_or_404(db, SoapNote, note_id)
    ensure_client_access(db, user, record.client_id)
    ensure_client_access(db, user, client_id)
    record.client_id = client_id
    record.session_date = datetime.strptime(session_date, "%Y-%m-%d").date()
    record.subjective = subjective
    record.objective = objective
    record.assessment = assessment
    record.plan = plan
    record.risk_assessment = risk_assessment
    record.interventions = interventions
    record.therapist_signature = therapist_signature
    record.updated_by = user.id
    record.updated_at = datetime.now(timezone.utc)
    log_activity(db, user.id, "edited soap note", "soap_note", record.id, f"Client ID {client_id}")
    db.commit()
    return redirect(f"/clients/{client_id}?tab=soap")


@app.get("/treatment/new", response_class=HTMLResponse)
def new_treatment_page(
    request: Request,
    client_id: int | None = None,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "form_note.html",
        note_context(request, user, scoped_clients(db, user), "treatment", "/treatment/new", None, client_id),
    )


@app.post("/treatment/new")
def create_treatment(
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
    client_id: int = Form(...),
    created_date: str = Form(...),
    presenting_problem: str = Form(""),
    diagnosis: str = Form(""),
    long_term_goal: str = Form(""),
    short_term_goals: str = Form(""),
    objectives: str = Form(""),
    interventions: str = Form(""),
    frequency: str = Form(""),
    review_date: str = Form(""),
    client_signature: str = Form(""),
    therapist_signature: str = Form(""),
) -> RedirectResponse:
    ensure_client_access(db, user, client_id)
    record = TreatmentPlan(
        client_id=client_id,
        created_date=datetime.strptime(created_date, "%Y-%m-%d").date(),
        presenting_problem=presenting_problem,
        diagnosis=diagnosis,
        long_term_goal=long_term_goal,
        short_term_goals=short_term_goals,
        objectives=objectives,
        interventions=interventions,
        frequency=frequency,
        review_date=datetime.strptime(review_date, "%Y-%m-%d").date() if review_date else None,
        client_signature=client_signature,
        therapist_signature=therapist_signature,
        created_by=user.id,
    )
    db.add(record)
    db.flush()
    log_activity(db, user.id, "created treatment plan", "treatment_plan", record.id, f"Client ID {client_id}")
    db.commit()
    return redirect(f"/clients/{client_id}?tab=treatment")


@app.get("/treatment/{plan_id}/edit", response_class=HTMLResponse)
def edit_treatment_page(
    request: Request,
    plan_id: int,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    record = fetch_record_or_404(db, TreatmentPlan, plan_id)
    ensure_client_access(db, user, record.client_id)
    return templates.TemplateResponse(
        request,
        "form_note.html",
        note_context(request, user, scoped_clients(db, user), "treatment", f"/treatment/{plan_id}/edit", record, heading="Edit Treatment Plan"),
    )


@app.post("/treatment/{plan_id}/edit")
def update_treatment(
    plan_id: int,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
    client_id: int = Form(...),
    created_date: str = Form(...),
    presenting_problem: str = Form(""),
    diagnosis: str = Form(""),
    long_term_goal: str = Form(""),
    short_term_goals: str = Form(""),
    objectives: str = Form(""),
    interventions: str = Form(""),
    frequency: str = Form(""),
    review_date: str = Form(""),
    client_signature: str = Form(""),
    therapist_signature: str = Form(""),
) -> RedirectResponse:
    record = fetch_record_or_404(db, TreatmentPlan, plan_id)
    ensure_client_access(db, user, record.client_id)
    ensure_client_access(db, user, client_id)
    record.client_id = client_id
    record.created_date = datetime.strptime(created_date, "%Y-%m-%d").date()
    record.presenting_problem = presenting_problem
    record.diagnosis = diagnosis
    record.long_term_goal = long_term_goal
    record.short_term_goals = short_term_goals
    record.objectives = objectives
    record.interventions = interventions
    record.frequency = frequency
    record.review_date = datetime.strptime(review_date, "%Y-%m-%d").date() if review_date else None
    record.client_signature = client_signature
    record.therapist_signature = therapist_signature
    record.updated_by = user.id
    record.updated_at = datetime.now(timezone.utc)
    log_activity(db, user.id, "edited treatment plan", "treatment_plan", record.id, f"Client ID {client_id}")
    db.commit()
    return redirect(f"/clients/{client_id}?tab=treatment")


@app.get("/summary/new", response_class=HTMLResponse)
def new_summary_page(
    request: Request,
    client_id: int | None = None,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "form_note.html",
        note_context(request, user, scoped_clients(db, user), "summary", "/summary/new", None, client_id),
    )


@app.post("/summary/new")
def create_summary(
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
    client_id: int = Form(...),
    report_date: str = Form(...),
    referral_reason: str = Form(""),
    current_concerns: str = Form(""),
    progress_to_date: str = Form(""),
    interventions_used: str = Form(""),
    barriers: str = Form(""),
    recommendations: str = Form(""),
    clinical_summary: str = Form(""),
    therapist_signature: str = Form(""),
) -> RedirectResponse:
    ensure_client_access(db, user, client_id)
    record = SummaryReport(
        client_id=client_id,
        report_date=datetime.strptime(report_date, "%Y-%m-%d").date(),
        referral_reason=referral_reason,
        current_concerns=current_concerns,
        progress_to_date=progress_to_date,
        interventions_used=interventions_used,
        barriers=barriers,
        recommendations=recommendations,
        clinical_summary=clinical_summary,
        therapist_signature=therapist_signature,
        created_by=user.id,
    )
    db.add(record)
    db.flush()
    log_activity(db, user.id, "created summary report", "summary_report", record.id, f"Client ID {client_id}")
    db.commit()
    return redirect(f"/clients/{client_id}?tab=summary")


@app.get("/summary/{report_id}/edit", response_class=HTMLResponse)
def edit_summary_page(
    request: Request,
    report_id: int,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    record = fetch_record_or_404(db, SummaryReport, report_id)
    ensure_client_access(db, user, record.client_id)
    return templates.TemplateResponse(
        request,
        "form_note.html",
        note_context(request, user, scoped_clients(db, user), "summary", f"/summary/{report_id}/edit", record, heading="Edit Summary Report"),
    )


@app.post("/summary/{report_id}/edit")
def update_summary(
    report_id: int,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
    client_id: int = Form(...),
    report_date: str = Form(...),
    referral_reason: str = Form(""),
    current_concerns: str = Form(""),
    progress_to_date: str = Form(""),
    interventions_used: str = Form(""),
    barriers: str = Form(""),
    recommendations: str = Form(""),
    clinical_summary: str = Form(""),
    therapist_signature: str = Form(""),
) -> RedirectResponse:
    record = fetch_record_or_404(db, SummaryReport, report_id)
    ensure_client_access(db, user, record.client_id)
    ensure_client_access(db, user, client_id)
    record.client_id = client_id
    record.report_date = datetime.strptime(report_date, "%Y-%m-%d").date()
    record.referral_reason = referral_reason
    record.current_concerns = current_concerns
    record.progress_to_date = progress_to_date
    record.interventions_used = interventions_used
    record.barriers = barriers
    record.recommendations = recommendations
    record.clinical_summary = clinical_summary
    record.therapist_signature = therapist_signature
    record.updated_by = user.id
    record.updated_at = datetime.now(timezone.utc)
    log_activity(db, user.id, "edited summary report", "summary_report", record.id, f"Client ID {client_id}")
    db.commit()
    return redirect(f"/clients/{client_id}?tab=summary")


@app.get("/safety/new", response_class=HTMLResponse)
def new_safety_page(
    request: Request,
    client_id: int | None = None,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "form_note.html",
        note_context(request, user, scoped_clients(db, user), "safety", "/safety/new", None, client_id),
    )


@app.post("/safety/new")
def create_safety(
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
    client_id: int = Form(...),
    created_date: str = Form(...),
    warning_signs: str = Form(""),
    internal_coping_strategies: str = Form(""),
    distraction_places: str = Form(""),
    help_people: str = Form(""),
    professionals_resources: str = Form(""),
    means_safety_steps: str = Form(""),
    reasons_for_living: str = Form(""),
    signature_and_date: str = Form(""),
) -> RedirectResponse:
    ensure_client_access(db, user, client_id)
    record = SafetyPlan(
        client_id=client_id,
        created_date=datetime.strptime(created_date, "%Y-%m-%d").date(),
        warning_signs=warning_signs,
        internal_coping_strategies=internal_coping_strategies,
        distraction_places=distraction_places,
        help_people=help_people,
        professionals_resources=professionals_resources,
        means_safety_steps=means_safety_steps,
        reasons_for_living=reasons_for_living,
        signature_and_date=signature_and_date,
        created_by=user.id,
    )
    db.add(record)
    db.flush()
    log_activity(db, user.id, "created safety plan", "safety_plan", record.id, f"Client ID {client_id}")
    db.commit()
    return redirect(f"/clients/{client_id}?tab=safety")


@app.get("/safety/{plan_id}/edit", response_class=HTMLResponse)
def edit_safety_page(
    request: Request,
    plan_id: int,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    record = fetch_record_or_404(db, SafetyPlan, plan_id)
    ensure_client_access(db, user, record.client_id)
    return templates.TemplateResponse(
        request,
        "form_note.html",
        note_context(request, user, scoped_clients(db, user), "safety", f"/safety/{plan_id}/edit", record, heading="Edit Safety Plan"),
    )


@app.post("/safety/{plan_id}/edit")
def update_safety(
    plan_id: int,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST)),
    db: Session = Depends(get_db),
    client_id: int = Form(...),
    created_date: str = Form(...),
    warning_signs: str = Form(""),
    internal_coping_strategies: str = Form(""),
    distraction_places: str = Form(""),
    help_people: str = Form(""),
    professionals_resources: str = Form(""),
    means_safety_steps: str = Form(""),
    reasons_for_living: str = Form(""),
    signature_and_date: str = Form(""),
) -> RedirectResponse:
    record = fetch_record_or_404(db, SafetyPlan, plan_id)
    ensure_client_access(db, user, record.client_id)
    ensure_client_access(db, user, client_id)
    record.client_id = client_id
    record.created_date = datetime.strptime(created_date, "%Y-%m-%d").date()
    record.warning_signs = warning_signs
    record.internal_coping_strategies = internal_coping_strategies
    record.distraction_places = distraction_places
    record.help_people = help_people
    record.professionals_resources = professionals_resources
    record.means_safety_steps = means_safety_steps
    record.reasons_for_living = reasons_for_living
    record.signature_and_date = signature_and_date
    record.updated_by = user.id
    record.updated_at = datetime.now(timezone.utc)
    log_activity(db, user.id, "edited safety plan", "safety_plan", record.id, f"Client ID {client_id}")
    db.commit()
    return redirect(f"/clients/{client_id}?tab=safety")


@app.get("/worksheets", response_class=HTMLResponse)
def worksheets_page(
    request: Request,
    q: str = "",
    user: StaffUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    clients = scoped_clients(db, user)
    stmt = select(Worksheet)
    if q:
        stmt = stmt.where(or_(Worksheet.title.ilike(f"%{q}%"), Worksheet.category.ilike(f"%{q}%")))
    if user.role != Role.ADMIN:
        client_ids = [client.id for client in clients]
        if client_ids:
            stmt = stmt.where(or_(Worksheet.assigned_client_id.is_(None), Worksheet.assigned_client_id.in_(client_ids)))
        else:
            stmt = stmt.where(Worksheet.assigned_client_id.is_(None))
    worksheets = list(db.execute(stmt.order_by(Worksheet.created_at.desc())).scalars().all())
    return templates.TemplateResponse(
        request,
        "worksheets.html",
        {"user": user, "clients": clients, "worksheets": worksheets, "query": q},
    )


@app.post("/worksheets/assign")
def create_worksheet(
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST, Role.SUPPORT)),
    db: Session = Depends(get_db),
    title: str = Form(...),
    category: str = Form(...),
    description: str = Form(""),
    assigned_client_id: str = Form(""),
) -> RedirectResponse:
    client_id = int(assigned_client_id) if assigned_client_id else None
    if client_id:
        ensure_client_access(db, user, client_id)
    worksheet = Worksheet(
        title=title,
        category=category,
        description=description,
        assigned_client_id=client_id,
        created_by=user.id,
    )
    db.add(worksheet)
    db.flush()
    log_activity(db, user.id, "worksheet upload", "worksheet", worksheet.id, f"Client ID {client_id or 'library'}")
    db.commit()
    return redirect("/worksheets")


@app.post("/documents/upload")
async def upload_document(
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST, Role.SUPPORT)),
    db: Session = Depends(get_db),
    client_id: int = Form(...),
    title: str = Form(...),
    document_type: str = Form(...),
    notes: str = Form(""),
    upload: UploadFile = File(...),
) -> RedirectResponse:
    ensure_client_access(db, user, client_id)
    content = await upload.read()
    storage_key = STORAGE.save(client_id, upload.filename or title, content)
    document = Document(
        client_id=client_id,
        title=title,
        document_type=document_type,
        notes=notes,
        storage_key=storage_key,
        original_filename=upload.filename or title,
        content_type=upload.content_type or "application/octet-stream",
        created_by=user.id,
    )
    db.add(document)
    db.flush()
    log_activity(db, user.id, "document upload", "document", document.id, f"Client ID {client_id}")
    db.commit()
    return redirect(f"/clients/{client_id}?tab=billing")


@app.get("/documents/{document_id}/download")
def download_document(
    document_id: int,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.THERAPIST, Role.SUPPORT)),
    db: Session = Depends(get_db),
) -> FileResponse:
    document = fetch_record_or_404(db, Document, document_id)
    ensure_client_access(db, user, document.client_id)
    if SETTINGS.storage_backend != "local":
        raise HTTPException(status_code=501, detail="Hosted object-storage downloads are not wired in this baseline")
    local_path = SETTINGS.storage_root / document.storage_key
    if not local_path.exists():
        raise HTTPException(status_code=404, detail="Stored file not found")
    log_activity(db, user.id, "document download", "document", document.id, f"Client ID {document.client_id}")
    db.commit()
    return FileResponse(path=local_path, media_type=document.content_type, filename=document.original_filename)


@app.post("/clients/{client_id}/flag-missing")
def flag_missing_forms(
    client_id: int,
    user: StaffUser = Depends(require_roles(Role.ADMIN, Role.SUPPORT)),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    ensure_client_access(db, user, client_id)
    log_activity(db, user.id, "flagged missing forms", "client", client_id, "Support review flagged documentation follow-up.")
    db.commit()
    return redirect(f"/clients/{client_id}?tab=billing")


@app.get("/reports", response_class=HTMLResponse)
def reports_page(
    request: Request,
    user: StaffUser = Depends(require_roles(Role.ADMIN)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    statuses = [status_for_client(db, client) for client in scoped_clients(db, user)]
    return templates.TemplateResponse(
        request,
        "reports.html",
        {
            "user": user,
            "total_clients": len(statuses),
            "total_sessions": sum(int(row["sessions_count"]) for row in statuses),
            "missing_plans": sum(1 for row in statuses if row["treatment_plan_status"] != "OK"),
            "missing_forms": sum(1 for row in statuses if row["missing_forms_flag"] != "OK"),
        },
    )


@app.get("/admin/staff", response_class=HTMLResponse)
def admin_staff_page(
    request: Request,
    user: StaffUser = Depends(require_roles(Role.ADMIN)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    staff_users = list(db.execute(select(StaffUser).order_by(StaffUser.role, StaffUser.name)).scalars().all())
    clients = list(db.execute(select(Client).order_by(Client.name)).scalars().all())
    assignments = list(db.execute(select(ClientAssignment).order_by(ClientAssignment.user_id, ClientAssignment.client_id)).scalars().all())
    return templates.TemplateResponse(
        request,
        "admin_staff.html",
        {"user": user, "staff_users": staff_users, "clients": clients, "assignments": assignments},
    )


@app.post("/admin/staff/create")
def create_staff_user(
    user: StaffUser = Depends(require_roles(Role.ADMIN)),
    db: Session = Depends(get_db),
    name: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
) -> RedirectResponse:
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    existing = db.execute(select(StaffUser).where(StaffUser.username == username)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    salt, hashed = hash_password(password)
    staff = StaffUser(name=name, username=username, password_salt=salt, password_hash=hashed, role=role)
    db.add(staff)
    log_activity(db, user.id, "created staff user", "staff_user", None, f"Username {username}")
    db.commit()
    return redirect("/admin/staff")


@app.post("/admin/assign-client")
def assign_client(
    user: StaffUser = Depends(require_roles(Role.ADMIN)),
    db: Session = Depends(get_db),
    user_id: int = Form(...),
    client_id: int = Form(...),
    assignment_role: str = Form(...),
) -> RedirectResponse:
    if not db.get(StaffUser, user_id) or not db.get(Client, client_id):
        raise HTTPException(status_code=404, detail="Staff user or client not found")
    existing = db.execute(
        select(ClientAssignment).where(ClientAssignment.user_id == user_id, ClientAssignment.client_id == client_id)
    ).scalar_one_or_none()
    if existing:
        existing.assignment_role = assignment_role
    else:
        assignment = ClientAssignment(user_id=user_id, client_id=client_id, assignment_role=assignment_role)
        db.add(assignment)
    log_activity(db, user.id, "client assignment change", "client_assignment", None, f"User {user_id} -> Client {client_id} as {assignment_role}")
    db.commit()
    return redirect("/admin/staff")


@app.post("/admin/staff/{staff_id}/deactivate")
def deactivate_staff(
    staff_id: int,
    user: StaffUser = Depends(require_roles(Role.ADMIN)),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    staff = fetch_record_or_404(db, StaffUser, staff_id)
    if staff.role == Role.ADMIN and staff.username == user.username:
        raise HTTPException(status_code=400, detail="Admin cannot deactivate the active admin account")
    staff.active = False
    db.execute(delete(SessionToken).where(SessionToken.user_id == staff.id))
    log_activity(db, user.id, "deactivated staff user", "staff_user", staff.id, f"Username {staff.username}")
    db.commit()
    return redirect("/admin/staff")


def account_page(request: Request, user: StaffUser, error: str = "", message: str = "", status_code: int = 200) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "account.html",
        {"user": user, "error": error, "message": message, "min_length": MIN_PASSWORD_LENGTH},
        status_code=status_code,
    )


@app.get("/account", response_class=HTMLResponse)
def account_get(request: Request, user: StaffUser = Depends(get_current_user)) -> HTMLResponse:
    return account_page(request, user)


@app.post("/account/password", response_class=HTMLResponse)
def change_password(
    request: Request,
    user: StaffUser = Depends(get_current_user),
    db: Session = Depends(get_db),
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
) -> HTMLResponse:
    if not verify_password(current_password, user.password_salt, user.password_hash):
        return account_page(request, user, error="Current password is incorrect.", status_code=400)
    if new_password != confirm_password:
        return account_page(request, user, error="New passwords do not match.", status_code=400)
    if len(new_password) < MIN_PASSWORD_LENGTH:
        return account_page(request, user, error=f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", status_code=400)
    user.password_salt, user.password_hash = hash_password(new_password)
    token = request.cookies.get("staff_session")
    db.execute(delete(SessionToken).where(SessionToken.user_id == user.id, SessionToken.token != token))
    log_activity(db, user.id, "changed password", "staff_user", user.id, "Self-service password change")
    db.commit()
    return account_page(request, user, message="Password updated.")


@app.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    user: StaffUser = Depends(require_roles(Role.ADMIN)),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    logs = list(db.execute(select(ActivityLog).order_by(ActivityLog.created_at.desc()).limit(200)).scalars().all())
    return templates.TemplateResponse(request, "audit.html", {"user": user, "logs": logs})


@app.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    user: StaffUser = Depends(require_roles(Role.ADMIN)),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "user": user,
            "settings_view": {
                "require_https": SETTINGS.require_https,
                "require_mfa": SETTINGS.require_mfa,
                "session_hours": SETTINGS.session_hours,
                "storage_backend": SETTINGS.storage_backend,
                "storage_root": str(SETTINGS.storage_root),
                "database_url": make_url(SETTINGS.database_url).render_as_string(hide_password=True),
            },
        },
    )

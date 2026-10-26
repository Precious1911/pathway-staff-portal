from __future__ import annotations

import secrets
from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import log_activity
from .config import get_settings
from .models import (
    Client,
    ClientAssignment,
    Document,
    Role,
    SafetyPlan,
    SoapNote,
    StaffUser,
    SummaryReport,
    TreatmentPlan,
    Worksheet,
)
from .security import hash_password
from .storage import StorageBackend
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def seed_data(db: Session, storage: StorageBackend) -> None:
    if db.execute(select(StaffUser.id).limit(1)).scalar_one_or_none():
        return

    settings = get_settings(ROOT)
    if not settings.allow_dev_seed_data:
        return

    users = [
        ("Dr. Jeremiah Barnett", "drbarnett_admin", Role.ADMIN),
        ("Therapist Jackson", "therapist_jackson", Role.THERAPIST),
        ("Therapist Williams", "therapist_williams", Role.THERAPIST),
        ("Assistant Morgan", "assistant_morgan", Role.SUPPORT),
    ]
    user_map: dict[str, StaffUser] = {}
    print("Seeding demo staff accounts with freshly generated passwords (shown once, not stored anywhere):")
    for name, username, role in users:
        password = secrets.token_urlsafe(12)
        salt, hashed = hash_password(password)
        user = StaffUser(name=name, username=username, password_salt=salt, password_hash=hashed, role=role)
        db.add(user)
        db.flush()
        user_map[username] = user
        print(f"  {role}: {username} / {password}")

    clients = [
        ("Anthony_Brown", date(2010, 3, 18), "School stress and emotional regulation", "COMPLETE"),
        ("Keisha_Thomas", date(2009, 7, 9), "Anxiety and peer conflict", "COMPLETE"),
        ("Marcus_Reed", date(2011, 1, 27), "Behavior and family transition adjustment", "MISSING"),
        ("Jalen_Carter", date(2010, 11, 4), "Trauma processing and grounding support", "COMPLETE"),
        ("Tasha_Wilson", date(2008, 5, 22), "Mood instability and coping deficits", "MISSING"),
    ]
    client_map: dict[str, Client] = {}
    for name, dob, concern, intake in clients:
        client = Client(name=name, date_of_birth=dob, primary_concern=concern, intake_status=intake, billing_documents="Insurance release, attendance log")
        db.add(client)
        db.flush()
        client_map[name] = client

    assignments = [
        ("therapist_jackson", "Anthony_Brown", "Primary Therapist"),
        ("therapist_jackson", "Keisha_Thomas", "Primary Therapist"),
        ("therapist_williams", "Marcus_Reed", "Primary Therapist"),
        ("therapist_williams", "Jalen_Carter", "Primary Therapist"),
        ("assistant_morgan", "Anthony_Brown", "Support Coverage"),
        ("assistant_morgan", "Keisha_Thomas", "Support Coverage"),
        ("assistant_morgan", "Marcus_Reed", "Support Coverage"),
        ("assistant_morgan", "Jalen_Carter", "Support Coverage"),
        ("assistant_morgan", "Tasha_Wilson", "Support Coverage"),
    ]
    for username, client_name, assignment_role in assignments:
        db.add(
            ClientAssignment(
                user_id=user_map[username].id,
                client_id=client_map[client_name].id,
                assignment_role=assignment_role,
            )
        )

    db.add(
        SoapNote(
            client_id=client_map["Anthony_Brown"].id,
            session_date=date.today(),
            subjective="Client reported increased stress at school and conflict with peers.",
            objective="Client was alert, oriented, and engaged. Affect mildly anxious.",
            assessment="Stress response appears related to school pressure and peer conflict.",
            plan="Continue weekly counseling. Practice coping skills and grounding.",
            risk_assessment="No current SI or HI reported.",
            interventions="Supportive counseling, emotional labeling, coping skills review.",
            therapist_signature="Dr. Jeremiah Barnett",
            created_by=user_map["therapist_jackson"].id,
        )
    )
    db.add(
        TreatmentPlan(
            client_id=client_map["Keisha_Thomas"].id,
            created_date=date.today(),
            presenting_problem="Anxiety, emotional overwhelm, school avoidance.",
            diagnosis="Adjustment disorder with anxiety.",
            long_term_goal="Improve emotional regulation and school functioning.",
            short_term_goals="Identify triggers, use coping skills, improve attendance.",
            objectives="Use 2 coping skills weekly and report stress level each session.",
            interventions="CBT support, grounding, emotional regulation, supportive counseling.",
            frequency="Weekly",
            review_date=date.today() + timedelta(days=30),
            client_signature="Keisha_Thomas",
            therapist_signature="Dr. Jeremiah Barnett",
            created_by=user_map["therapist_jackson"].id,
        )
    )
    db.add(
        SummaryReport(
            client_id=client_map["Marcus_Reed"].id,
            report_date=date.today(),
            referral_reason="Referral for emotional dysregulation and school behavior concerns.",
            current_concerns="Current stress with transitions and frustration tolerance.",
            progress_to_date="Some progress with labeling feelings and using breaks appropriately.",
            interventions_used="Grounding, supportive counseling, emotional regulation coaching.",
            barriers="Family stress and inconsistent routines.",
            recommendations="Maintain counseling support and school check-ins.",
            clinical_summary="Client benefits from predictable support and regulation strategies.",
            therapist_signature="Dr. Jeremiah Barnett",
            created_by=user_map["therapist_williams"].id,
        )
    )
    db.add(
        SafetyPlan(
            client_id=client_map["Jalen_Carter"].id,
            created_date=date.today(),
            warning_signs="Shutting down, irritability, avoiding peers.",
            internal_coping_strategies="Breathing, grounding, movement break.",
            distraction_places="Counseling office, music room, grandmother's porch.",
            help_people="Grandmother, counselor, trusted coach.",
            professionals_resources="Therapist, school counselor, 988.",
            means_safety_steps="Safe monitoring of sharps and medications at home.",
            reasons_for_living="Family connection, basketball, future goals.",
            signature_and_date="Jalen_Carter",
            created_by=user_map["therapist_williams"].id,
        )
    )

    db.add(
        Worksheet(
            title="Grounding Reset Worksheet",
            category="grounding",
            description="Daily grounding sequence for dysregulation.",
            assigned_client_id=client_map["Anthony_Brown"].id,
            created_by=user_map["assistant_morgan"].id,
        )
    )

    sample_docs = [
        ("Anthony_Brown", "Anthony_Brown_Intake_Form.pdf", "Intake Form"),
        ("Anthony_Brown", "Anthony_Brown_Worksheet_Grounding.pdf", "Worksheet"),
        ("Keisha_Thomas", "Keisha_Thomas_Summary_Report.pdf", "Summary Report"),
        ("Marcus_Reed", "Marcus_Reed_Billing_Document.pdf", "Billing"),
    ]
    for client_name, filename, doc_type in sample_docs:
        key = storage.save(client_map[client_name].id, filename, f"Sample file for {client_name}".encode("utf-8"))
        db.add(
            Document(
                client_id=client_map[client_name].id,
                title=filename,
                document_type=doc_type,
                notes="Seeded for hosted deployment preview.",
                storage_key=key,
                original_filename=filename,
                content_type="application/pdf",
                created_by=user_map["assistant_morgan"].id,
            )
        )

    log_activity(db, user_map["drbarnett_admin"].id, "seeded database", "system", None, "Hosted deployment seed data created.")
    db.commit()


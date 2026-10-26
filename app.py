#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta
from http import cookies
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlparse

from config import load_settings
from storage import LocalSecureStorage


ROOT = Path(__file__).resolve().parent
SETTINGS = load_settings(ROOT)
DB_PATH = ROOT / "data" / "portal.db"
STATIC_DIR = ROOT / "static"
HOST = SETTINGS.host
PORT = SETTINGS.port
SESSION_HOURS = SETTINGS.session_hours
STORAGE = LocalSecureStorage(SETTINGS.storage_root)

ROLE_ADMIN = "Admin"
ROLE_THERAPIST = "Therapist"
ROLE_SUPPORT = "Support Staff"


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _dev_seed_allowed() -> bool:
    if os.getenv("PATHWAY_ENV", "").strip().lower() == "production":
        return False
    return _env_flag("PATHWAY_STAFF_ALLOW_DEV_SEED", True)


def _demo_credentials_box() -> str:
    return (
        '<div class="demo-box">'
        "<strong>Local preview users</strong>"
        "<div>Demo account passwords are generated at startup and printed once to the "
        "server console — they are not stored here.</div>"
        "</div>"
    )


def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def html_escape(value: object) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def password_hash(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240000)
    return salt.hex(), hashed.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    _, candidate = password_hash(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(candidate, hash_hex)


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    ROOT.joinpath("data").mkdir(parents=True, exist_ok=True)
    ROOT.joinpath("static").mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS staff_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                mfa_enabled INTEGER NOT NULL DEFAULT 0,
                mfa_secret TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES staff_users(id)
            );

            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                date_of_birth TEXT,
                primary_concern TEXT,
                intake_status TEXT NOT NULL DEFAULT 'MISSING',
                billing_documents TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS soap_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                session_date TEXT NOT NULL,
                subjective TEXT,
                objective TEXT,
                assessment TEXT,
                plan TEXT,
                risk_assessment TEXT,
                interventions TEXT,
                therapist_signature TEXT,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(client_id) REFERENCES clients(id),
                FOREIGN KEY(created_by) REFERENCES staff_users(id)
            );

            CREATE TABLE IF NOT EXISTS treatment_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                created_date TEXT NOT NULL,
                presenting_problem TEXT,
                diagnosis TEXT,
                long_term_goal TEXT,
                short_term_goals TEXT,
                objectives TEXT,
                interventions TEXT,
                frequency TEXT,
                review_date TEXT,
                client_signature TEXT,
                therapist_signature TEXT,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(client_id) REFERENCES clients(id),
                FOREIGN KEY(created_by) REFERENCES staff_users(id)
            );

            CREATE TABLE IF NOT EXISTS summary_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                report_date TEXT NOT NULL,
                referral_reason TEXT,
                current_concerns TEXT,
                progress_to_date TEXT,
                interventions_used TEXT,
                barriers TEXT,
                recommendations TEXT,
                clinical_summary TEXT,
                therapist_signature TEXT,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(client_id) REFERENCES clients(id),
                FOREIGN KEY(created_by) REFERENCES staff_users(id)
            );

            CREATE TABLE IF NOT EXISTS safety_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                created_date TEXT NOT NULL,
                warning_signs TEXT,
                internal_coping_strategies TEXT,
                distraction_places TEXT,
                help_people TEXT,
                professionals_resources TEXT,
                means_safety_steps TEXT,
                reasons_for_living TEXT,
                signature_and_date TEXT,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(client_id) REFERENCES clients(id),
                FOREIGN KEY(created_by) REFERENCES staff_users(id)
            );

            CREATE TABLE IF NOT EXISTS worksheets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT,
                date_added TEXT NOT NULL,
                assigned_client_id INTEGER,
                created_by INTEGER,
                FOREIGN KEY(assigned_client_id) REFERENCES clients(id),
                FOREIGN KEY(created_by) REFERENCES staff_users(id)
            );

            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                document_type TEXT NOT NULL,
                notes TEXT,
                storage_key TEXT NOT NULL DEFAULT '',
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(client_id) REFERENCES clients(id),
                FOREIGN KEY(created_by) REFERENCES staff_users(id)
            );

            CREATE TABLE IF NOT EXISTS client_assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                client_id INTEGER NOT NULL,
                assignment_role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, client_id),
                FOREIGN KEY(user_id) REFERENCES staff_users(id),
                FOREIGN KEY(client_id) REFERENCES clients(id)
            );

            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_user_id INTEGER,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id INTEGER,
                details TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(actor_user_id) REFERENCES staff_users(id)
            );
            """
        )

        staff_columns = {row["name"] for row in conn.execute("PRAGMA table_info(staff_users)").fetchall()}
        if "mfa_enabled" not in staff_columns:
            conn.execute("ALTER TABLE staff_users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0")
        if "mfa_secret" not in staff_columns:
            conn.execute("ALTER TABLE staff_users ADD COLUMN mfa_secret TEXT NOT NULL DEFAULT ''")
        if "failed_login_attempts" not in staff_columns:
            conn.execute("ALTER TABLE staff_users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0")
        if "locked_until" not in staff_columns:
            conn.execute("ALTER TABLE staff_users ADD COLUMN locked_until TEXT")

        document_columns = {row["name"] for row in conn.execute("PRAGMA table_info(documents)").fetchall()}
        if "storage_key" not in document_columns:
            conn.execute("ALTER TABLE documents ADD COLUMN storage_key TEXT NOT NULL DEFAULT ''")

        user_count = conn.execute("SELECT COUNT(*) FROM staff_users").fetchone()[0]
        if user_count == 0 and _dev_seed_allowed():
            users = [
                ("Dr. Jeremiah Barnett", "drbarnett_admin", ROLE_ADMIN),
                ("Therapist Jackson", "therapist_jackson", ROLE_THERAPIST),
                ("Therapist Williams", "therapist_williams", ROLE_THERAPIST),
                ("Assistant Morgan", "assistant_morgan", ROLE_SUPPORT),
            ]
            print("Seeding demo staff accounts with freshly generated passwords (shown once, not stored anywhere):")
            for name, username, role in users:
                password = secrets.token_urlsafe(12)
                salt_hex, hash_hex = password_hash(password)
                conn.execute(
                    """
                    INSERT INTO staff_users (name, username, salt, password_hash, role, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (name, username, salt_hex, hash_hex, role, now_iso()),
                )
                print(f"  {role}: {username} / {password}")
        # Existing staff accounts are never modified here on restart: earlier
        # versions of this seeding step reset the admin/therapist/support
        # passwords back to fixed defaults on every startup, silently undoing
        # any password change made through the app.

        sample_clients = [
            ("Anthony Brown", "2010-03-18", "School stress and emotional regulation", "COMPLETE"),
            ("Keisha Thomas", "2009-07-09", "Anxiety and peer conflict", "COMPLETE"),
            ("Marcus Reed", "2011-01-27", "Behavior and family transition adjustment", "MISSING"),
            ("Jalen Carter", "2010-11-04", "Trauma processing and grounding support", "COMPLETE"),
            ("Tasha Wilson", "2008-05-22", "Mood instability and coping deficits", "MISSING"),
        ]

        client_count = conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
        if client_count == 0:
            client_ids = {}
            for name, dob, concern, intake in sample_clients:
                cur = conn.execute(
                    """
                    INSERT INTO clients (name, date_of_birth, primary_concern, intake_status, billing_documents, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (name, dob, concern, intake, "Insurance release, attendance log", now_iso()),
                )
                client_ids[name] = cur.lastrowid

            admin_id = conn.execute("SELECT id FROM staff_users WHERE username = ?", ("drbarnett_admin",)).fetchone()[0]
            therapist_jackson_id = conn.execute("SELECT id FROM staff_users WHERE username = ?", ("therapist_jackson",)).fetchone()[0]
            therapist_williams_id = conn.execute("SELECT id FROM staff_users WHERE username = ?", ("therapist_williams",)).fetchone()[0]
            support_id = conn.execute("SELECT id FROM staff_users WHERE username = ?", ("assistant_morgan",)).fetchone()[0]

            conn.executemany(
                """
                INSERT OR IGNORE INTO client_assignments (user_id, client_id, assignment_role, created_at)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (therapist_jackson_id, client_ids["Anthony Brown"], "Primary Therapist", now_iso()),
                    (therapist_jackson_id, client_ids["Keisha Thomas"], "Primary Therapist", now_iso()),
                    (therapist_williams_id, client_ids["Marcus Reed"], "Primary Therapist", now_iso()),
                    (therapist_williams_id, client_ids["Jalen Carter"], "Primary Therapist", now_iso()),
                    (support_id, client_ids["Anthony Brown"], "Support Coverage", now_iso()),
                    (support_id, client_ids["Keisha Thomas"], "Support Coverage", now_iso()),
                    (support_id, client_ids["Marcus Reed"], "Support Coverage", now_iso()),
                    (support_id, client_ids["Jalen Carter"], "Support Coverage", now_iso()),
                    (support_id, client_ids["Tasha Wilson"], "Support Coverage", now_iso()),
                ],
            )

            conn.execute(
                """
                INSERT INTO soap_notes (
                    client_id, session_date, subjective, objective, assessment, plan, risk_assessment,
                    interventions, therapist_signature, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_ids["Anthony Brown"],
                    "2026-04-05",
                    "Client reported fewer panic symptoms this week.",
                    "Client arrived regulated and engaged.",
                    "Improving emotional awareness with reduced acute distress.",
                    "Continue weekly therapy and grounding practice.",
                    "Denied suicidal ideation.",
                    "Grounding, cognitive reframing, psychoeducation.",
                    "Dr. Jeremiah Barnett",
                    therapist_jackson_id,
                    now_iso(),
                ),
            )
            conn.execute(
                """
                INSERT INTO treatment_plans (
                    client_id, created_date, presenting_problem, diagnosis, long_term_goal,
                    short_term_goals, objectives, interventions, frequency, review_date,
                    client_signature, therapist_signature, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_ids["Keisha Thomas"],
                    "2026-04-02",
                    "Anxiety, emotional overwhelm, school avoidance.",
                    "Adjustment disorder with anxiety.",
                    "Improve emotional regulation and school functioning.",
                    "Identify triggers, use coping skills, improve attendance.",
                    "Use 2 coping skills weekly and report stress level each session.",
                    "CBT support, grounding, emotional regulation, supportive counseling.",
                    "Weekly",
                    "2026-05-15",
                    "Keisha Thomas",
                    "Dr. Jeremiah Barnett",
                    therapist_jackson_id,
                    now_iso(),
                ),
            )
            conn.execute(
                """
                INSERT INTO summary_reports (
                    client_id, report_date, referral_reason, current_concerns, progress_to_date,
                    interventions_used, barriers, recommendations, clinical_summary,
                    therapist_signature, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_ids["Marcus Reed"],
                    "2026-04-04",
                    "Referral for emotional dysregulation and school behavior concerns.",
                    "Current stress with transitions and frustration tolerance.",
                    "Some progress with labeling feelings and using breaks appropriately.",
                    "Grounding, supportive counseling, emotional regulation coaching.",
                    "Family stress and inconsistent routines.",
                    "Maintain counseling support and school check-ins.",
                    "Client benefits from predictable support and regulation strategies.",
                    "Dr. Jeremiah Barnett",
                    therapist_williams_id,
                    now_iso(),
                ),
            )
            conn.execute(
                """
                INSERT INTO safety_plans (
                    client_id, created_date, warning_signs, internal_coping_strategies,
                    distraction_places, help_people, professionals_resources,
                    means_safety_steps, reasons_for_living, signature_and_date,
                    created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_ids["Jalen Carter"],
                    "2026-04-01",
                    "Shutting down, irritability, avoiding peers.",
                    "Breathing, grounding, movement break.",
                    "Counseling office, music room, grandmother's porch.",
                    "Grandmother, counselor, trusted coach.",
                    "Therapist, school counselor, 988.",
                    "Safe monitoring of sharps and medications at home.",
                    "Family connection, basketball, future goals.",
                    "Jalen Carter 2026-04-01",
                    therapist_williams_id,
                    now_iso(),
                ),
            )
            conn.execute(
                """
                INSERT INTO soap_notes (
                    client_id, session_date, subjective, objective, assessment, plan, risk_assessment,
                    interventions, therapist_signature, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_ids["Anthony Brown"],
                    "2026-04-06",
                    "Client reported increased stress at school and conflict with peers.",
                    "Client was alert, oriented, and engaged. Affect mildly anxious.",
                    "Stress response appears related to school pressure and peer conflict.",
                    "Continue weekly counseling. Practice coping skills and grounding.",
                    "No active suicidal ideation reported.",
                    "Supportive counseling, emotional labeling, coping skills review.",
                    "Dr. Jeremiah Barnett",
                    therapist_jackson_id,
                    now_iso(),
                ),
            )
            for title, category, desc, assigned_name in [
                ("Trauma Bond Clarity Boundary Worksheet", "relationships", "Boundaries and relationship pattern worksheet.", None),
                ("Trauma Bond Grounding Cycle Worksheet", "grounding", "Grounding sequence for dysregulation cycles.", None),
                ("NCE Intervention Pack", "CBT", "Intervention prompts for structured sessions.", "Anthony Brown"),
                ("Upheal Note-Ready Session Documents", "coping", "Session prep and note-ready support set.", None),
            ]:
                assigned_id = client_ids[assigned_name] if assigned_name else None
                conn.execute(
                    """
                    INSERT INTO worksheets (title, category, description, date_added, assigned_client_id, created_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (title, category, desc, today_str(), assigned_id, admin_id),
                )

            for client_name, title, document_type, notes, creator_id in [
                ("Anthony Brown", "Anthony_Brown_Intake_Form.pdf", "Intake Form", "Sample uploaded intake document for portal testing.", support_id),
                ("Anthony Brown", "Anthony_Brown_Worksheet_Grounding.pdf", "Worksheet", "Sample uploaded grounding worksheet for portal testing.", support_id),
                ("Keisha Thomas", "Keisha_Thomas_Summary_Report.pdf", "Summary Report", "Sample uploaded summary report document for portal testing.", support_id),
                ("Marcus Reed", "Marcus_Reed_Billing_Document.pdf", "Billing", "Sample uploaded billing document for portal testing.", support_id),
            ]:
                storage_key = STORAGE.store_document_placeholder(
                    title,
                    f"Pathway Guidance Services sample document\nClient: {client_name}\nType: {document_type}\nNotes: {notes}\n",
                )
                conn.execute(
                    """
                    INSERT INTO documents (client_id, title, document_type, notes, storage_key, created_by, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (client_ids[client_name], title, document_type, notes, storage_key, creator_id, now_iso()),
                )

            for action, target_type, target_id, details in [
                ("seeded database", "system", None, "Initial local preview data created."),
                ("created treatment plan", "treatment_plan", 1, "Seed plan for Keisha Thomas."),
                ("assigned worksheet", "worksheet", 3, "Assigned NCE Intervention Pack to Anthony Brown."),
                ("changed client assignment", "client_assignment", None, "Seeded therapist/support assignments."),
                ("document upload", "document", None, "Seeded document upload test area."),
            ]:
                conn.execute(
                    """
                    INSERT INTO activity_log (actor_user_id, action, target_type, target_id, details, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (admin_id, action, target_type, target_id, details, now_iso()),
                )
        else:
            for name, dob, concern, intake in sample_clients:
                if not conn.execute("SELECT 1 FROM clients WHERE name = ?", (name,)).fetchone():
                    conn.execute(
                        """
                        INSERT INTO clients (name, date_of_birth, primary_concern, intake_status, billing_documents, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (name, dob, concern, intake, "Insurance release, attendance log", now_iso()),
                    )


def log_activity(conn: sqlite3.Connection, actor_user_id: int | None, action: str, target_type: str, target_id: int | None, details: str) -> None:
    conn.execute(
        """
        INSERT INTO activity_log (actor_user_id, action, target_type, target_id, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (actor_user_id, action, target_type, target_id, details, now_iso()),
    )


def assigned_client_ids(conn: sqlite3.Connection, user_id: int) -> list[int]:
    return [
        int(row["client_id"])
        for row in conn.execute("SELECT client_id FROM client_assignments WHERE user_id = ? ORDER BY client_id", (user_id,)).fetchall()
    ]


def scoped_client_rows(conn: sqlite3.Connection, user: sqlite3.Row, query: str = "") -> list[sqlite3.Row]:
    params: list[object] = []
    sql = "SELECT * FROM clients"
    if user["role"] != ROLE_ADMIN:
        ids = assigned_client_ids(conn, int(user["id"]))
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        sql += f" WHERE id IN ({placeholders})"
        params.extend(ids)
        if query:
            sql += " AND LOWER(name) LIKE ?"
            params.append(f"%{query.lower()}%")
    elif query:
        sql += " WHERE LOWER(name) LIKE ?"
        params.append(f"%{query.lower()}%")
    sql += " ORDER BY name"
    return conn.execute(sql, params).fetchall()


def user_can_access_client(conn: sqlite3.Connection, user: sqlite3.Row, client_id: int) -> bool:
    if user["role"] == ROLE_ADMIN:
        return True
    return client_id in assigned_client_ids(conn, int(user["id"]))


def status_for_client(conn: sqlite3.Connection, client_row: sqlite3.Row) -> dict[str, object]:
    client_id = client_row["id"]
    sessions_count = conn.execute("SELECT COUNT(*) FROM soap_notes WHERE client_id = ?", (client_id,)).fetchone()[0]
    last_session = conn.execute(
        "SELECT MAX(session_date) FROM soap_notes WHERE client_id = ?",
        (client_id,),
    ).fetchone()[0] or "N/A"
    treatment_count = conn.execute("SELECT COUNT(*) FROM treatment_plans WHERE client_id = ?", (client_id,)).fetchone()[0]
    summary_count = conn.execute("SELECT COUNT(*) FROM summary_reports WHERE client_id = ?", (client_id,)).fetchone()[0]
    safety_count = conn.execute("SELECT COUNT(*) FROM safety_plans WHERE client_id = ?", (client_id,)).fetchone()[0]
    treatment_status = "OK" if treatment_count else "MISSING"
    missing_forms_flag = "OK" if summary_count and safety_count else "MISSING"
    intake_status = client_row["intake_status"]
    if treatment_status == "OK" and missing_forms_flag == "OK" and intake_status == "COMPLETE":
        alert = "GREEN"
    elif sessions_count > 0 and (treatment_status != "OK" or missing_forms_flag != "OK" or intake_status != "COMPLETE"):
        alert = "RED"
    else:
        alert = "YELLOW"
    return {
        "client_id": client_id,
        "client_name": client_row["name"],
        "sessions_count": sessions_count,
        "last_session_date": last_session,
        "treatment_plan_status": treatment_status,
        "missing_forms_flag": missing_forms_flag,
        "intake_status": intake_status,
        "alert_level": alert,
    }


def fetch_client_statuses(conn: sqlite3.Connection, query: str = "") -> list[dict[str, object]]:
    params = []
    sql = "SELECT * FROM clients"
    if query:
        sql += " WHERE LOWER(name) LIKE ?"
        params.append(f"%{query.lower()}%")
    sql += " ORDER BY name"
    return [status_for_client(conn, row) for row in conn.execute(sql, params).fetchall()]


def fetch_scoped_statuses(conn: sqlite3.Connection, user: sqlite3.Row, query: str = "") -> list[dict[str, object]]:
    return [status_for_client(conn, row) for row in scoped_client_rows(conn, user, query)]


def role_allows(user_role: str, allowed: set[str]) -> bool:
    return user_role in allowed


def permission_boundary_html(user: sqlite3.Row) -> str:
    if user["role"] == ROLE_ADMIN:
        allowed = [
            "All clients and all clinical records",
            "Staff management, client assignment changes, reports, settings, and audit log",
            "Document uploads, worksheet assignment, and clinical form creation and edits",
        ]
        blocked = [
            "No admin restrictions in local preview",
        ]
    elif user["role"] == ROLE_THERAPIST:
        allowed = [
            "Assigned clients only",
            "Create and edit SOAP notes, treatment plans, summary reports, and safety plans",
            "Upload documents and assign worksheets for assigned clients",
        ]
        blocked = [
            "No access to admin-only reports, settings, staff management, or audit log",
            "No access to unassigned clients",
        ]
    else:
        allowed = [
            "Assigned clients only",
            "View client profile basics, billing/documents, and assigned worksheet information",
            "Upload documents, assign worksheets, and flag missing forms",
        ]
        blocked = [
            "Cannot create or edit SOAP notes",
            "Cannot create or edit treatment plans",
            "Cannot create or edit safety plans",
            "No access to admin-only reports, settings, staff management, or audit log",
        ]
    allowed_html = "".join(f"<li>{html_escape(item)}</li>" for item in allowed)
    blocked_html = "".join(f"<li>{html_escape(item)}</li>" for item in blocked)
    return f"""
    <section class="card permissions-card">
      <div class="section-heading">
        <h2>Permission Boundary</h2>
        <span class="role-pill">{html_escape(user["role"])}</span>
      </div>
      <div class="permission-grid">
        <div>
          <h3>Allowed</h3>
          <ul class="permission-list">{allowed_html}</ul>
        </div>
        <div>
          <h3>Restricted</h3>
          <ul class="permission-list">{blocked_html}</ul>
        </div>
      </div>
    </section>
    """


def parse_form(body: bytes) -> dict[str, str]:
    values = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    return {key: vals[0] if vals else "" for key, vals in values.items()}


def badge_class(status: str) -> str:
    if status in {"OK", "GREEN", "COMPLETE"}:
        return "badge-ok"
    if status == "YELLOW":
        return "badge-warn"
    return "badge-bad"


def layout(title: str, content: str, user: sqlite3.Row | None = None) -> str:
    nav = ""
    if user:
        nav_links = [('/dashboard', 'Dashboard'), ('/clients', 'Clients'), ('/worksheets', 'Worksheet Library')]
        if role_allows(user["role"], {ROLE_ADMIN, ROLE_THERAPIST}):
            nav_links.extend(
                [
                    ('/soap/new', 'New SOAP Note'),
                    ('/treatment/new', 'New Treatment Plan'),
                    ('/summary/new', 'New Summary Report'),
                    ('/safety/new', 'New Safety Plan'),
                ]
            )
        if user["role"] == ROLE_ADMIN:
            nav_links.extend([('/reports', 'Reports'), ('/admin/staff', 'Staff Management'), ('/audit', 'Audit Log'), ('/settings', 'Settings')])
        links = "".join(f'<a href="{href}">{label}</a>' for href, label in nav_links)
        nav = f"""
        <div class="topbar">
          <div class="brandline">
            <img src="/static/logo.svg" alt="Pathway logo" class="logo">
            <div>
              <h1>Pathway Guidance Services</h1>
              <p>Staff Clinical Documentation Portal</p>
            </div>
          </div>
          <div class="userline">
            <span class="role-pill">{html_escape(user['role'])}</span>
            <span>{html_escape(user['name'])}</span>
            <form method="post" action="/logout"><button class="ghost-btn" type="submit">Logout</button></form>
          </div>
        </div>
        <nav class="navlinks">{links}</nav>
        """
    else:
        nav = """
        <div class="topbar">
          <div class="brandline">
            <img src="/static/logo.svg" alt="Pathway logo" class="logo">
            <div>
              <h1>Pathway Guidance Services</h1>
              <p>Staff Clinical Documentation Portal</p>
            </div>
          </div>
        </div>
        """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html_escape(title)}</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <header>{nav}</header>
  <main class="page-shell">{content}</main>
</body>
</html>"""


def form_shell(title: str, action: str, fields: list[str], client_options: list[sqlite3.Row], values: dict[str, str] | None = None) -> str:
    values = values or {}
    client_html = "".join(
        f'<option value="{row["id"]}" {"selected" if str(row["id"]) == values.get("client_id", "") else ""}>{html_escape(row["name"])}</option>'
        for row in client_options
    )
    inputs = []
    for label, name, kind in fields:
        value = values.get(name, today_str() if kind == "date" else "")
        if kind == "textarea":
            inputs.append(
                f'<label>{html_escape(label)}<textarea name="{name}">{html_escape(value)}</textarea></label>'
            )
        else:
            inputs.append(
                f'<label>{html_escape(label)}<input type="{kind}" name="{name}" value="{html_escape(value)}"></label>'
            )
    return f"""
    <section class="card form-card">
      <div class="section-heading">
        <h2>{html_escape(title)}</h2>
      </div>
      <form method="post" action="{action}" class="stack-form">
        <label>Client
          <select name="client_id" required>
            <option value="">Select client</option>
            {client_html}
          </select>
        </label>
        {''.join(inputs)}
        <button class="primary-btn" type="submit">Save</button>
      </form>
    </section>
    """


class StaffPortalHandler(BaseHTTPRequestHandler):
    def db_conn(self) -> sqlite3.Connection:
        return db()

    def parse_cookies(self) -> cookies.SimpleCookie[str]:
        jar = cookies.SimpleCookie()
        raw = self.headers.get("Cookie")
        if raw:
            jar.load(raw)
        return jar

    def current_user(self) -> sqlite3.Row | None:
        jar = self.parse_cookies()
        token = jar.get("staff_session")
        if not token:
            return None
        with self.db_conn() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_iso(),))
            row = conn.execute(
                """
                SELECT staff_users.* FROM sessions
                JOIN staff_users ON staff_users.id = sessions.user_id
                WHERE sessions.token = ? AND sessions.expires_at > ? AND staff_users.active = 1
                """,
                (token.value, now_iso()),
            ).fetchone()
            return row

    def request_is_secure(self) -> bool:
        try:
            client_ip = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return False
        trusted_proxy = any(
            client_ip in ipaddress.ip_network(network, strict=False)
            for network in SETTINGS.trusted_proxy_ips
        )
        return trusted_proxy and self.headers.get(SETTINGS.trusted_proxy_header, "").strip().lower() == "https"

    def enforce_https_if_needed(self) -> bool:
        if SETTINGS.require_https and not self.request_is_secure():
            self.send_html(
                layout(
                    "HTTPS Required",
                    '<section class="card"><h2>HTTPS required</h2><p>This portal is configured to require HTTPS in hosted environments.</p></section>',
                ),
                status=403,
            )
            return False
        return True

    def send_html(self, html: str, status: int = 200, cookie_header: str | None = None, location: str | None = None) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookie_header:
            self.send_header("Set-Cookie", cookie_header)
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str, cookie_header: str | None = None) -> None:
        self.send_html("", status=302, cookie_header=cookie_header, location=location)

    def send_json(self, payload: dict[str, object], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_static(self, path: Path, content_type: str) -> None:
        if not path.exists():
            self.send_error(404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def require_login(self) -> sqlite3.Row | None:
        user = self.current_user()
        if not user:
            self.redirect("/login")
            return None
        return user

    def require_role(self, allowed: set[str]) -> sqlite3.Row | None:
        user = self.require_login()
        if not user:
            return None
        if not role_allows(user["role"], allowed):
            html = layout(
                "Access Denied",
                '<section class="card"><h2>Access denied</h2><p>Your role does not allow this action.</p></section>',
                user,
            )
            self.send_html(html, status=403)
            return None
        return user

    def do_GET(self) -> None:
        if not self.enforce_https_if_needed():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/static/style.css":
            self.send_static(STATIC_DIR / "style.css", "text/css; charset=utf-8")
            return
        if parsed.path == "/static/logo.svg":
            self.send_static(STATIC_DIR / "logo.svg", "image/svg+xml")
            return
        if parsed.path == "/":
            if self.current_user():
                self.redirect("/dashboard")
            else:
                self.redirect("/login")
            return
        if parsed.path == "/login":
            self.page_login()
            return
        if parsed.path == "/dashboard":
            self.page_dashboard(parsed)
            return
        if parsed.path == "/reports":
            self.page_reports()
            return
        if parsed.path == "/clients":
            self.page_clients(parsed)
            return
        if re.fullmatch(r"/clients/\d+", parsed.path):
            self.page_client_detail(parsed)
            return
        if parsed.path == "/soap/new":
            self.page_new_soap(parsed)
            return
        if re.fullmatch(r"/soap/\d+/edit", parsed.path):
            self.page_edit_soap(parsed)
            return
        if parsed.path == "/treatment/new":
            self.page_new_treatment(parsed)
            return
        if re.fullmatch(r"/treatment/\d+/edit", parsed.path):
            self.page_edit_treatment(parsed)
            return
        if parsed.path == "/summary/new":
            self.page_new_summary(parsed)
            return
        if re.fullmatch(r"/summary/\d+/edit", parsed.path):
            self.page_edit_summary(parsed)
            return
        if parsed.path == "/safety/new":
            self.page_new_safety(parsed)
            return
        if re.fullmatch(r"/safety/\d+/edit", parsed.path):
            self.page_edit_safety(parsed)
            return
        if parsed.path == "/worksheets":
            self.page_worksheets(parsed)
            return
        if parsed.path == "/admin/staff":
            self.page_staff_management()
            return
        if parsed.path == "/audit":
            self.page_audit()
            return
        if parsed.path == "/settings":
            self.page_settings()
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if not self.enforce_https_if_needed():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            self.post_login()
            return
        if parsed.path == "/logout":
            self.post_logout()
            return
        if parsed.path == "/soap/new":
            self.post_new_soap()
            return
        if re.fullmatch(r"/soap/\d+/edit", parsed.path):
            self.post_edit_soap(parsed)
            return
        if parsed.path == "/treatment/new":
            self.post_new_treatment()
            return
        if re.fullmatch(r"/treatment/\d+/edit", parsed.path):
            self.post_edit_treatment(parsed)
            return
        if parsed.path == "/summary/new":
            self.post_new_summary()
            return
        if re.fullmatch(r"/summary/\d+/edit", parsed.path):
            self.post_edit_summary(parsed)
            return
        if parsed.path == "/safety/new":
            self.post_new_safety()
            return
        if re.fullmatch(r"/safety/\d+/edit", parsed.path):
            self.post_edit_safety(parsed)
            return
        if parsed.path == "/worksheets/assign":
            self.post_assign_worksheet()
            return
        if parsed.path == "/admin/staff/create":
            self.post_create_staff()
            return
        if parsed.path == "/admin/assign-client":
            self.post_assign_client()
            return
        if parsed.path == "/admin/deactivate-staff":
            self.post_deactivate_staff()
            return
        if parsed.path == "/clients/flag-missing":
            self.post_flag_missing()
            return
        if parsed.path == "/documents/upload":
            self.post_upload_document()
            return
        self.send_error(404)

    def read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0"))
        return parse_form(self.rfile.read(length))

    def page_login(self, error: str = "") -> None:
        content = f"""
        <section class="login-shell">
          <div class="card login-card">
            <h2>Staff Login</h2>
            <p class="muted">Secure staff-only access for Pathway Guidance Services.</p>
            {'<p class="error">' + html_escape(error) + '</p>' if error else ''}
            <form method="post" action="/login" class="stack-form">
              <label>Username<input name="username" required></label>
              <label>Password<input name="password" type="password" required></label>
              <button class="primary-btn" type="submit">Sign In</button>
            </form>
            {_demo_credentials_box() if os.getenv("PATHWAY_STAFF_SHOW_DEMO_CREDENTIALS", "false").strip().lower() in {"1", "true", "yes", "on"} else ""}
          </div>
        </section>
        """
        self.send_html(layout("Login", content))

    def post_login(self) -> None:
        form = self.read_form()
        username = form.get("username", "").strip()
        password = form.get("password", "")
        max_attempts = int(os.getenv("PATHWAY_STAFF_MAX_LOGIN_ATTEMPTS", "5"))
        lockout_minutes = int(os.getenv("PATHWAY_STAFF_LOGIN_LOCKOUT_MINUTES", "15"))
        with self.db_conn() as conn:
            user = conn.execute(
                "SELECT * FROM staff_users WHERE username = ? AND active = 1",
                (username,),
            ).fetchone()
            if user and user["locked_until"] and user["locked_until"] > now_iso():
                self.page_login("Account temporarily locked after repeated failed attempts. Try again later.")
                return
            if not user or not verify_password(password, user["salt"], user["password_hash"]):
                if user:
                    attempts = int(user["failed_login_attempts"]) + 1
                    locked_until = (
                        (datetime.now() + timedelta(minutes=lockout_minutes)).strftime("%Y-%m-%d %H:%M:%S")
                        if attempts >= max_attempts
                        else None
                    )
                    conn.execute(
                        "UPDATE staff_users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
                        (attempts, locked_until, user["id"]),
                    )
                    if locked_until:
                        log_activity(conn, user["id"], "account locked", "session", None, "Too many failed login attempts")
                self.page_login("Invalid username or password.")
                return
            if SETTINGS.require_mfa_all_staff and not int(user["mfa_enabled"]):
                self.page_login("MFA is required for this account in hosted mode. Enable MFA before deployment.")
                return
            conn.execute("UPDATE staff_users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
            conn.execute("DELETE FROM sessions WHERE user_id = ? OR expires_at <= ?", (user["id"], now_iso()))
            token = secrets.token_urlsafe(32)
            expires_at = (datetime.now() + timedelta(hours=SESSION_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (token, user["id"], expires_at, now_iso()),
            )
            log_activity(conn, user["id"], "logged in", "session", None, f"Role {user['role']}")
        cookie = f"staff_session={token}; HttpOnly; Path=/; SameSite=Lax"
        if SETTINGS.secure_cookies or SETTINGS.require_https:
            cookie += "; Secure"
        self.redirect("/dashboard", cookie_header=cookie)

    def post_logout(self) -> None:
        jar = self.parse_cookies()
        token = jar.get("staff_session")
        if token:
            with self.db_conn() as conn:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token.value,))
        cookie = "staff_session=deleted; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
        if SETTINGS.secure_cookies or SETTINGS.require_https:
            cookie += "; Secure"
        self.redirect("/login", cookie_header=cookie)

    def page_dashboard(self, parsed) -> None:
        user = self.require_login()
        if not user:
            return
        query = parse_qs(parsed.query).get("q", [""])[0]
        with self.db_conn() as conn:
            rows = fetch_scoped_statuses(conn, user, query)
        total_sessions = sum(int(row["sessions_count"]) for row in rows)
        red_alerts = sum(1 for row in rows if row["alert_level"] == "RED")
        heading = {
            ROLE_ADMIN: "Admin Dashboard",
            ROLE_THERAPIST: "Therapist Dashboard",
            ROLE_SUPPORT: "Support Dashboard",
        }[user["role"]]
        table_rows = "".join(
            f"""
            <tr onclick="window.location.href='/clients/{row['client_id']}'">
              <td>{html_escape(row['client_name'])}</td>
              <td>{row['sessions_count']}</td>
              <td><span class="{badge_class(str(row['treatment_plan_status']))}">{html_escape(row['treatment_plan_status'])}</span></td>
              <td><span class="{badge_class(str(row['missing_forms_flag']))}">{html_escape(row['missing_forms_flag'])}</span></td>
            </tr>
            """
            for row in rows
        )
        content = f"""
        <section class="stats-grid">
          <div class="card stat-card"><div class="eyebrow">Total Clients</div><div class="stat">{len(rows)}</div></div>
          <div class="card stat-card"><div class="eyebrow">Total Sessions</div><div class="stat">{total_sessions}</div></div>
          <div class="card stat-card"><div class="eyebrow">Red Alerts</div><div class="stat bad">{red_alerts}</div></div>
          <div class="card stat-card"><div class="eyebrow">Access Scope</div><div class="stat">{html_escape('All Clients' if user['role'] == ROLE_ADMIN else 'Assigned Clients')}</div></div>
        </section>
        {permission_boundary_html(user)}
        <section class="card">
          <div class="section-heading">
            <h2>{heading}</h2>
            <form method="get" action="/dashboard" class="inline-search">
              <input name="q" value="{html_escape(query)}" placeholder="Search clients by name">
              <button class="primary-btn" type="submit">Search</button>
            </form>
          </div>
          <table class="data-table">
            <thead><tr><th>Client Name</th><th>Sessions Count</th><th>Treatment Plan Status</th><th>Missing Forms Flag</th></tr></thead>
            <tbody>{table_rows or '<tr><td colspan="4">No clients found.</td></tr>'}</tbody>
          </table>
        </section>
        """
        self.send_html(layout("Staff Dashboard", content, user))

    def page_clients(self, parsed) -> None:
        user = self.require_login()
        if not user:
            return
        query = parse_qs(parsed.query).get("q", [""])[0]
        with self.db_conn() as conn:
            rows = fetch_scoped_statuses(conn, user, query)
        cards = "".join(
            f"""
            <a class="client-card" href="/clients/{row['client_id']}">
              <div><strong>{html_escape(row['client_name'])}</strong></div>
              <div class="muted">Sessions: {row['sessions_count']} | Last session: {html_escape(row['last_session_date'])}</div>
              <div class="pill-row">
                <span class="{badge_class(str(row['treatment_plan_status']))}">Plan {html_escape(row['treatment_plan_status'])}</span>
                <span class="{badge_class(str(row['missing_forms_flag']))}">Forms {html_escape(row['missing_forms_flag'])}</span>
                <span class="{badge_class(str(row['alert_level']))}">{html_escape(row['alert_level'])}</span>
              </div>
            </a>
            """
            for row in rows
        )
        content = f"""
        <section class="card">
          <div class="section-heading">
            <h2>Client List</h2>
            <form method="get" action="/clients" class="inline-search">
              <input name="q" value="{html_escape(query)}" placeholder="Search clients by name">
              <button class="primary-btn" type="submit">Search</button>
            </form>
          </div>
          <div class="client-grid">{cards or '<p>No clients found.</p>'}</div>
        </section>
        """
        self.send_html(layout("Client List", content, user))

    def page_client_detail(self, parsed) -> None:
        user = self.require_login()
        if not user:
            return
        client_id = int(parsed.path.rsplit("/", 1)[-1])
        tab = parse_qs(parsed.query).get("tab", ["overview"])[0]
        with self.db_conn() as conn:
            client = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
            if not client:
                self.send_error(404)
                return
            if not user_can_access_client(conn, user, client_id):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>This client is not assigned to your account.</p></section>', user), status=403)
                return
            status = status_for_client(conn, client)
            soap_notes = conn.execute("SELECT * FROM soap_notes WHERE client_id = ? ORDER BY session_date DESC", (client_id,)).fetchall()
            treatments = conn.execute("SELECT * FROM treatment_plans WHERE client_id = ? ORDER BY created_date DESC", (client_id,)).fetchall()
            summaries = conn.execute("SELECT * FROM summary_reports WHERE client_id = ? ORDER BY report_date DESC", (client_id,)).fetchall()
            safety_plans = conn.execute("SELECT * FROM safety_plans WHERE client_id = ? ORDER BY created_date DESC", (client_id,)).fetchall()
            documents = conn.execute("SELECT * FROM documents WHERE client_id = ? ORDER BY created_at DESC", (client_id,)).fetchall()
            worksheets = conn.execute(
                """
                SELECT worksheets.*, staff_users.name AS creator_name
                FROM worksheets
                LEFT JOIN staff_users ON staff_users.id = worksheets.created_by
                WHERE assigned_client_id = ?
                ORDER BY date_added DESC
                """,
                (client_id,),
            ).fetchall()

        def tab_link(name: str, key: str) -> str:
            active = "tab-active" if tab == key else ""
            return f'<a class="tab-link {active}" href="/clients/{client_id}?tab={key}">{name}</a>'

        tab_nav = "".join(
            [
                tab_link("Overview", "overview"),
                tab_link("Sessions", "sessions"),
                tab_link("SOAP Notes", "soap"),
                tab_link("Treatment Plans", "treatment"),
                tab_link("Summary Reports", "summary"),
                tab_link("Safety Plans", "safety"),
                tab_link("Worksheets", "worksheets"),
                tab_link("Billing/Documents", "billing"),
            ]
        )

        overview = f"""
        <div class="summary-grid">
          <div><span class="eyebrow">Client Name</span><strong>{html_escape(client['name'])}</strong></div>
          <div><span class="eyebrow">DOB</span><strong>{html_escape(client['date_of_birth'])}</strong></div>
          <div><span class="eyebrow">Primary Concern</span><strong>{html_escape(client['primary_concern'])}</strong></div>
          <div><span class="eyebrow">Sessions</span><strong>{status['sessions_count']}</strong></div>
          <div><span class="eyebrow">Treatment Plan</span><strong>{html_escape(status['treatment_plan_status'])}</strong></div>
          <div><span class="eyebrow">Missing Forms</span><strong>{html_escape(status['missing_forms_flag'])}</strong></div>
        </div>
        <div class="action-row">
          {('<a class="primary-btn" href="/soap/new?client_id=' + str(client_id) + '">New SOAP Note</a>') if role_allows(user['role'], {ROLE_ADMIN, ROLE_THERAPIST}) else ''}
          {('<a class="primary-btn" href="/treatment/new?client_id=' + str(client_id) + '">New Treatment Plan</a>') if role_allows(user['role'], {ROLE_ADMIN, ROLE_THERAPIST}) else ''}
          {('<a class="primary-btn" href="/summary/new?client_id=' + str(client_id) + '">New Summary Report</a>') if role_allows(user['role'], {ROLE_ADMIN, ROLE_THERAPIST}) else ''}
          {('<a class="primary-btn" href="/safety/new?client_id=' + str(client_id) + '">New Safety Plan</a>') if role_allows(user['role'], {ROLE_ADMIN, ROLE_THERAPIST}) else ''}
        </div>
        """

        def record_list(rows: list[sqlite3.Row], date_key: str, title_builder: Callable[[sqlite3.Row], str], edit_prefix: str | None = None) -> str:
            if not rows:
                return "<p>No records yet.</p>"
            return "".join(
                f'<div class="record-item"><div><strong>{html_escape(title_builder(row))}</strong><span>{html_escape(row[date_key])}</span></div>'
                + (
                    f'<a class="ghost-btn" href="{edit_prefix}/{row["id"]}/edit">Edit</a>'
                    if edit_prefix and role_allows(user["role"], {ROLE_ADMIN, ROLE_THERAPIST})
                    else ""
                )
                + '</div>'
                for row in rows
            )

        tab_content = {
            "overview": overview,
            "sessions": record_list(soap_notes, "session_date", lambda row: "Therapy Session", "/soap"),
            "soap": record_list(soap_notes, "session_date", lambda row: row["assessment"] or "SOAP Note", "/soap"),
            "treatment": record_list(treatments, "created_date", lambda row: row["diagnosis"] or "Treatment Plan", "/treatment"),
            "summary": record_list(summaries, "report_date", lambda row: row["clinical_summary"] or "Summary Report", "/summary"),
            "safety": record_list(safety_plans, "created_date", lambda row: row["warning_signs"] or "Safety Plan", "/safety"),
            "worksheets": record_list(worksheets, "date_added", lambda row: row["title"]),
            "billing": (
                f"<p>{html_escape(client['billing_documents'] or 'No billing or documents listed.')}</p>"
                + "".join(
                    f'<div class="record-item"><div><strong>{html_escape(row["title"])}</strong><span>{html_escape(row["document_type"])} · {html_escape(row["created_at"])}</span></div><span class="muted">{html_escape(row["storage_key"] or "secure storage pending")}</span></div>'
                    for row in documents
                )
                + (
                    f"""
                    <form method="post" action="/documents/upload" class="stack-form">
                      <input type="hidden" name="client_id" value="{client_id}">
                      <label>Document Title<input name="title" required></label>
                      <label>Document Type<input name="document_type" required></label>
                      <label>Notes<textarea name="notes"></textarea></label>
                      <button class="primary-btn" type="submit">Upload Document</button>
                    </form>
                    """
                    if role_allows(user["role"], {ROLE_ADMIN, ROLE_THERAPIST, ROLE_SUPPORT})
                    else ""
                )
                + (
                    f"""
                    <form method="post" action="/clients/flag-missing" class="inline-form">
                      <input type="hidden" name="client_id" value="{client_id}">
                      <button class="ghost-btn" type="submit">Flag Missing Forms</button>
                    </form>
                    """
                    if role_allows(user["role"], {ROLE_ADMIN, ROLE_SUPPORT})
                    else ""
                )
            ),
        }

        content = f"""
        <section class="card">
          <div class="section-heading">
            <h2>Client Detail</h2>
            <span class="{badge_class(str(status['alert_level']))}">{html_escape(status['alert_level'])}</span>
          </div>
          <p class="role-note">{html_escape('Clinical forms are editable for Admin and Therapist roles only.' if user['role'] == ROLE_SUPPORT else 'You can act only within your assigned-client scope unless you are an Admin.')}</p>
          <div class="tab-row">{tab_nav}</div>
          <div class="tab-panel">{tab_content.get(tab, overview)}</div>
        </section>
        """
        self.send_html(layout("Client Detail", content, user))

    def page_new_soap(self, parsed) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        query = parse_qs(parsed.query)
        with self.db_conn() as conn:
            clients = scoped_client_rows(conn, user)
        values = {"client_id": query.get("client_id", [""])[0], "session_date": today_str(), "therapist_signature": user["name"]}
        fields = [
            ("Session Date", "session_date", "date"),
            ("Subjective", "subjective", "textarea"),
            ("Objective", "objective", "textarea"),
            ("Assessment", "assessment", "textarea"),
            ("Plan", "plan", "textarea"),
            ("Risk Assessment", "risk_assessment", "textarea"),
            ("Interventions", "interventions", "textarea"),
            ("Therapist Signature", "therapist_signature", "text"),
        ]
        self.send_html(layout("New SOAP Note", form_shell("New SOAP Note", "/soap/new", fields, clients, values), user))

    def post_new_soap(self) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        form = self.read_form()
        with self.db_conn() as conn:
            if not user_can_access_client(conn, user, int(form.get("client_id") or 0)):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>This client is not assigned to you.</p></section>', user), status=403)
                return
            cur = conn.execute(
                """
                INSERT INTO soap_notes (
                    client_id, session_date, subjective, objective, assessment, plan, risk_assessment,
                    interventions, therapist_signature, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    form.get("client_id"),
                    form.get("session_date"),
                    form.get("subjective"),
                    form.get("objective"),
                    form.get("assessment"),
                    form.get("plan"),
                    form.get("risk_assessment"),
                    form.get("interventions"),
                    form.get("therapist_signature"),
                    user["id"],
                    now_iso(),
                ),
            )
            log_activity(conn, user["id"], "created soap note", "soap_note", cur.lastrowid, f"Client ID {form.get('client_id')}")
        self.redirect(f"/clients/{form.get('client_id')}?tab=soap")

    def page_new_treatment(self, parsed) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        query = parse_qs(parsed.query)
        with self.db_conn() as conn:
            clients = scoped_client_rows(conn, user)
        values = {
            "client_id": query.get("client_id", [""])[0],
            "created_date": today_str(),
            "therapist_signature": user["name"],
        }
        fields = [
            ("Created Date", "created_date", "date"),
            ("Presenting Problem", "presenting_problem", "textarea"),
            ("Diagnosis", "diagnosis", "textarea"),
            ("Long Term Goal", "long_term_goal", "textarea"),
            ("Short Term Goals", "short_term_goals", "textarea"),
            ("Objectives", "objectives", "textarea"),
            ("Interventions", "interventions", "textarea"),
            ("Frequency", "frequency", "text"),
            ("Review Date", "review_date", "date"),
            ("Client Signature", "client_signature", "text"),
            ("Therapist Signature", "therapist_signature", "text"),
        ]
        self.send_html(layout("New Treatment Plan", form_shell("New Treatment Plan", "/treatment/new", fields, clients, values), user))

    def post_new_treatment(self) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        form = self.read_form()
        with self.db_conn() as conn:
            if not user_can_access_client(conn, user, int(form.get("client_id") or 0)):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>This client is not assigned to you.</p></section>', user), status=403)
                return
            cur = conn.execute(
                """
                INSERT INTO treatment_plans (
                    client_id, created_date, presenting_problem, diagnosis, long_term_goal,
                    short_term_goals, objectives, interventions, frequency, review_date,
                    client_signature, therapist_signature, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    form.get("client_id"),
                    form.get("created_date"),
                    form.get("presenting_problem"),
                    form.get("diagnosis"),
                    form.get("long_term_goal"),
                    form.get("short_term_goals"),
                    form.get("objectives"),
                    form.get("interventions"),
                    form.get("frequency"),
                    form.get("review_date"),
                    form.get("client_signature"),
                    form.get("therapist_signature"),
                    user["id"],
                    now_iso(),
                ),
            )
            log_activity(conn, user["id"], "created treatment plan", "treatment_plan", cur.lastrowid, f"Client ID {form.get('client_id')}")
        self.redirect(f"/clients/{form.get('client_id')}?tab=treatment")

    def page_new_summary(self, parsed) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        query = parse_qs(parsed.query)
        with self.db_conn() as conn:
            clients = scoped_client_rows(conn, user)
        values = {"client_id": query.get("client_id", [""])[0], "report_date": today_str(), "therapist_signature": user["name"]}
        fields = [
            ("Report Date", "report_date", "date"),
            ("Referral Reason", "referral_reason", "textarea"),
            ("Current Concerns", "current_concerns", "textarea"),
            ("Progress to Date", "progress_to_date", "textarea"),
            ("Interventions Used", "interventions_used", "textarea"),
            ("Barriers", "barriers", "textarea"),
            ("Recommendations", "recommendations", "textarea"),
            ("Clinical Summary", "clinical_summary", "textarea"),
            ("Therapist Signature", "therapist_signature", "text"),
        ]
        self.send_html(layout("New Summary Report", form_shell("New Summary Report", "/summary/new", fields, clients, values), user))

    def post_new_summary(self) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        form = self.read_form()
        with self.db_conn() as conn:
            if not user_can_access_client(conn, user, int(form.get("client_id") or 0)):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>This client is not assigned to you.</p></section>', user), status=403)
                return
            cur = conn.execute(
                """
                INSERT INTO summary_reports (
                    client_id, report_date, referral_reason, current_concerns, progress_to_date,
                    interventions_used, barriers, recommendations, clinical_summary,
                    therapist_signature, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    form.get("client_id"),
                    form.get("report_date"),
                    form.get("referral_reason"),
                    form.get("current_concerns"),
                    form.get("progress_to_date"),
                    form.get("interventions_used"),
                    form.get("barriers"),
                    form.get("recommendations"),
                    form.get("clinical_summary"),
                    form.get("therapist_signature"),
                    user["id"],
                    now_iso(),
                ),
            )
            log_activity(conn, user["id"], "created summary report", "summary_report", cur.lastrowid, f"Client ID {form.get('client_id')}")
        self.redirect(f"/clients/{form.get('client_id')}?tab=summary")

    def page_new_safety(self, parsed) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        query = parse_qs(parsed.query)
        with self.db_conn() as conn:
            clients = scoped_client_rows(conn, user)
        values = {"client_id": query.get("client_id", [""])[0], "created_date": today_str()}
        fields = [
            ("Created Date", "created_date", "date"),
            ("Warning Signs", "warning_signs", "textarea"),
            ("Internal Coping Strategies", "internal_coping_strategies", "textarea"),
            ("People and Places for Distraction", "distraction_places", "textarea"),
            ("People to Ask for Help", "help_people", "textarea"),
            ("Professionals and Crisis Resources", "professionals_resources", "textarea"),
            ("Means Safety Steps", "means_safety_steps", "textarea"),
            ("Reasons for Living", "reasons_for_living", "textarea"),
            ("Signature and Date", "signature_and_date", "text"),
        ]
        self.send_html(layout("New Safety Plan", form_shell("New Safety Plan", "/safety/new", fields, clients, values), user))

    def post_new_safety(self) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        form = self.read_form()
        with self.db_conn() as conn:
            if not user_can_access_client(conn, user, int(form.get("client_id") or 0)):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>This client is not assigned to you.</p></section>', user), status=403)
                return
            cur = conn.execute(
                """
                INSERT INTO safety_plans (
                    client_id, created_date, warning_signs, internal_coping_strategies,
                    distraction_places, help_people, professionals_resources,
                    means_safety_steps, reasons_for_living, signature_and_date,
                    created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    form.get("client_id"),
                    form.get("created_date"),
                    form.get("warning_signs"),
                    form.get("internal_coping_strategies"),
                    form.get("distraction_places"),
                    form.get("help_people"),
                    form.get("professionals_resources"),
                    form.get("means_safety_steps"),
                    form.get("reasons_for_living"),
                    form.get("signature_and_date"),
                    user["id"],
                    now_iso(),
                ),
            )
            log_activity(conn, user["id"], "created safety plan", "safety_plan", cur.lastrowid, f"Client ID {form.get('client_id')}")
        self.redirect(f"/clients/{form.get('client_id')}?tab=safety")

    def page_edit_soap(self, parsed) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        note_id = int(parsed.path.split("/")[-2])
        with self.db_conn() as conn:
            note = conn.execute("SELECT * FROM soap_notes WHERE id = ?", (note_id,)).fetchone()
            if not note or not user_can_access_client(conn, user, int(note["client_id"])):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>You cannot edit this SOAP note.</p></section>', user), status=403)
                return
            clients = scoped_client_rows(conn, user)
        fields = [
            ("Session Date", "session_date", "date"),
            ("Subjective", "subjective", "textarea"),
            ("Objective", "objective", "textarea"),
            ("Assessment", "assessment", "textarea"),
            ("Plan", "plan", "textarea"),
            ("Risk Assessment", "risk_assessment", "textarea"),
            ("Interventions", "interventions", "textarea"),
            ("Therapist Signature", "therapist_signature", "text"),
        ]
        values = {key: str(note[key] or "") for key in note.keys()}
        self.send_html(layout("Edit SOAP Note", form_shell("Edit SOAP Note", f"/soap/{note_id}/edit", fields, clients, values), user))

    def post_edit_soap(self, parsed) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        note_id = int(parsed.path.split("/")[-2])
        form = self.read_form()
        with self.db_conn() as conn:
            note = conn.execute("SELECT * FROM soap_notes WHERE id = ?", (note_id,)).fetchone()
            if not note or not user_can_access_client(conn, user, int(note["client_id"])):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>You cannot edit this SOAP note.</p></section>', user), status=403)
                return
            conn.execute(
                """
                UPDATE soap_notes SET session_date = ?, subjective = ?, objective = ?, assessment = ?, plan = ?,
                risk_assessment = ?, interventions = ?, therapist_signature = ?
                WHERE id = ?
                """,
                (
                    form.get("session_date"),
                    form.get("subjective"),
                    form.get("objective"),
                    form.get("assessment"),
                    form.get("plan"),
                    form.get("risk_assessment"),
                    form.get("interventions"),
                    form.get("therapist_signature"),
                    note_id,
                ),
            )
            log_activity(conn, user["id"], "note edit", "soap_note", note_id, f"Client ID {note['client_id']}")
        self.redirect(f"/clients/{note['client_id']}?tab=soap")

    def page_edit_treatment(self, parsed) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        record_id = int(parsed.path.split("/")[-2])
        with self.db_conn() as conn:
            record = conn.execute("SELECT * FROM treatment_plans WHERE id = ?", (record_id,)).fetchone()
            if not record or not user_can_access_client(conn, user, int(record["client_id"])):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>You cannot edit this treatment plan.</p></section>', user), status=403)
                return
            clients = scoped_client_rows(conn, user)
        fields = [
            ("Created Date", "created_date", "date"),
            ("Presenting Problem", "presenting_problem", "textarea"),
            ("Diagnosis", "diagnosis", "textarea"),
            ("Long Term Goal", "long_term_goal", "textarea"),
            ("Short Term Goals", "short_term_goals", "textarea"),
            ("Objectives", "objectives", "textarea"),
            ("Interventions", "interventions", "textarea"),
            ("Frequency", "frequency", "text"),
            ("Review Date", "review_date", "date"),
            ("Client Signature", "client_signature", "text"),
            ("Therapist Signature", "therapist_signature", "text"),
        ]
        values = {key: str(record[key] or "") for key in record.keys()}
        self.send_html(layout("Edit Treatment Plan", form_shell("Edit Treatment Plan", f"/treatment/{record_id}/edit", fields, clients, values), user))

    def post_edit_treatment(self, parsed) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        record_id = int(parsed.path.split("/")[-2])
        form = self.read_form()
        with self.db_conn() as conn:
            record = conn.execute("SELECT * FROM treatment_plans WHERE id = ?", (record_id,)).fetchone()
            if not record or not user_can_access_client(conn, user, int(record["client_id"])):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>You cannot edit this treatment plan.</p></section>', user), status=403)
                return
            conn.execute(
                """
                UPDATE treatment_plans SET created_date = ?, presenting_problem = ?, diagnosis = ?, long_term_goal = ?,
                short_term_goals = ?, objectives = ?, interventions = ?, frequency = ?, review_date = ?,
                client_signature = ?, therapist_signature = ? WHERE id = ?
                """,
                (
                    form.get("created_date"),
                    form.get("presenting_problem"),
                    form.get("diagnosis"),
                    form.get("long_term_goal"),
                    form.get("short_term_goals"),
                    form.get("objectives"),
                    form.get("interventions"),
                    form.get("frequency"),
                    form.get("review_date"),
                    form.get("client_signature"),
                    form.get("therapist_signature"),
                    record_id,
                ),
            )
            log_activity(conn, user["id"], "treatment plan edit", "treatment_plan", record_id, f"Client ID {record['client_id']}")
        self.redirect(f"/clients/{record['client_id']}?tab=treatment")

    def page_edit_summary(self, parsed) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        record_id = int(parsed.path.split("/")[-2])
        with self.db_conn() as conn:
            record = conn.execute("SELECT * FROM summary_reports WHERE id = ?", (record_id,)).fetchone()
            if not record or not user_can_access_client(conn, user, int(record["client_id"])):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>You cannot edit this summary report.</p></section>', user), status=403)
                return
            clients = scoped_client_rows(conn, user)
        fields = [
            ("Report Date", "report_date", "date"),
            ("Referral Reason", "referral_reason", "textarea"),
            ("Current Concerns", "current_concerns", "textarea"),
            ("Progress to Date", "progress_to_date", "textarea"),
            ("Interventions Used", "interventions_used", "textarea"),
            ("Barriers", "barriers", "textarea"),
            ("Recommendations", "recommendations", "textarea"),
            ("Clinical Summary", "clinical_summary", "textarea"),
            ("Therapist Signature", "therapist_signature", "text"),
        ]
        values = {key: str(record[key] or "") for key in record.keys()}
        self.send_html(layout("Edit Summary Report", form_shell("Edit Summary Report", f"/summary/{record_id}/edit", fields, clients, values), user))

    def post_edit_summary(self, parsed) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        record_id = int(parsed.path.split("/")[-2])
        form = self.read_form()
        with self.db_conn() as conn:
            record = conn.execute("SELECT * FROM summary_reports WHERE id = ?", (record_id,)).fetchone()
            if not record or not user_can_access_client(conn, user, int(record["client_id"])):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>You cannot edit this summary report.</p></section>', user), status=403)
                return
            conn.execute(
                """
                UPDATE summary_reports SET report_date = ?, referral_reason = ?, current_concerns = ?, progress_to_date = ?,
                interventions_used = ?, barriers = ?, recommendations = ?, clinical_summary = ?, therapist_signature = ?
                WHERE id = ?
                """,
                (
                    form.get("report_date"),
                    form.get("referral_reason"),
                    form.get("current_concerns"),
                    form.get("progress_to_date"),
                    form.get("interventions_used"),
                    form.get("barriers"),
                    form.get("recommendations"),
                    form.get("clinical_summary"),
                    form.get("therapist_signature"),
                    record_id,
                ),
            )
            log_activity(conn, user["id"], "summary report edit", "summary_report", record_id, f"Client ID {record['client_id']}")
        self.redirect(f"/clients/{record['client_id']}?tab=summary")

    def page_edit_safety(self, parsed) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        record_id = int(parsed.path.split("/")[-2])
        with self.db_conn() as conn:
            record = conn.execute("SELECT * FROM safety_plans WHERE id = ?", (record_id,)).fetchone()
            if not record or not user_can_access_client(conn, user, int(record["client_id"])):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>You cannot edit this safety plan.</p></section>', user), status=403)
                return
            clients = scoped_client_rows(conn, user)
        fields = [
            ("Created Date", "created_date", "date"),
            ("Warning Signs", "warning_signs", "textarea"),
            ("Internal Coping Strategies", "internal_coping_strategies", "textarea"),
            ("People and Places for Distraction", "distraction_places", "textarea"),
            ("People to Ask for Help", "help_people", "textarea"),
            ("Professionals and Crisis Resources", "professionals_resources", "textarea"),
            ("Means Safety Steps", "means_safety_steps", "textarea"),
            ("Reasons for Living", "reasons_for_living", "textarea"),
            ("Signature and Date", "signature_and_date", "text"),
        ]
        values = {key: str(record[key] or "") for key in record.keys()}
        self.send_html(layout("Edit Safety Plan", form_shell("Edit Safety Plan", f"/safety/{record_id}/edit", fields, clients, values), user))

    def post_edit_safety(self, parsed) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST})
        if not user:
            return
        record_id = int(parsed.path.split("/")[-2])
        form = self.read_form()
        with self.db_conn() as conn:
            record = conn.execute("SELECT * FROM safety_plans WHERE id = ?", (record_id,)).fetchone()
            if not record or not user_can_access_client(conn, user, int(record["client_id"])):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>You cannot edit this safety plan.</p></section>', user), status=403)
                return
            conn.execute(
                """
                UPDATE safety_plans SET created_date = ?, warning_signs = ?, internal_coping_strategies = ?, distraction_places = ?,
                help_people = ?, professionals_resources = ?, means_safety_steps = ?, reasons_for_living = ?, signature_and_date = ?
                WHERE id = ?
                """,
                (
                    form.get("created_date"),
                    form.get("warning_signs"),
                    form.get("internal_coping_strategies"),
                    form.get("distraction_places"),
                    form.get("help_people"),
                    form.get("professionals_resources"),
                    form.get("means_safety_steps"),
                    form.get("reasons_for_living"),
                    form.get("signature_and_date"),
                    record_id,
                ),
            )
            log_activity(conn, user["id"], "safety plan edit", "safety_plan", record_id, f"Client ID {record['client_id']}")
        self.redirect(f"/clients/{record['client_id']}?tab=safety")

    def page_worksheets(self, parsed) -> None:
        user = self.require_login()
        if not user:
            return
        query = parse_qs(parsed.query).get("q", [""])[0]
        with self.db_conn() as conn:
            clients = scoped_client_rows(conn, user)
            client_ids = [int(row["id"]) for row in clients]
            sql = """
                SELECT worksheets.*, clients.name AS client_name
                FROM worksheets
                LEFT JOIN clients ON clients.id = worksheets.assigned_client_id
                WHERE LOWER(title || ' ' || category || ' ' || COALESCE(clients.name, '')) LIKE ?
            """
            params: list[object] = [f"%{query.lower()}%"]
            if user["role"] != ROLE_ADMIN:
                if client_ids:
                    placeholders = ",".join("?" for _ in client_ids)
                    sql += f" AND (assigned_client_id IS NULL OR assigned_client_id IN ({placeholders}))"
                    params.extend(client_ids)
                else:
                    sql += " AND assigned_client_id IS NULL"
            sql += " ORDER BY date_added DESC, title"
            worksheets = conn.execute(sql, params).fetchall()
        options = "".join(f'<option value="{row["id"]}">{html_escape(row["name"])}</option>' for row in clients)
        worksheet_rows = "".join(
            f"""
            <tr>
              <td>{html_escape(row['title'])}</td>
              <td>{html_escape(row['category'])}</td>
              <td>{html_escape(row['date_added'])}</td>
              <td>{html_escape(row['client_name'] or 'Library')}</td>
            </tr>
            """
            for row in worksheets
        )
        form = ""
        if role_allows(user["role"], {ROLE_ADMIN, ROLE_THERAPIST, ROLE_SUPPORT}):
            form = f"""
            <section class="card">
              <h2>Assign Worksheet</h2>
              <form method="post" action="/worksheets/assign" class="stack-form">
                <label>Worksheet Title<input name="title" required></label>
                <label>Category
                  <select name="category" required>
                    <option value="trauma">trauma</option>
                    <option value="coping">coping</option>
                    <option value="CBT">CBT</option>
                    <option value="grounding">grounding</option>
                    <option value="communication">communication</option>
                    <option value="relationships">relationships</option>
                    <option value="behavior">behavior</option>
                    <option value="self-worth">self-worth</option>
                  </select>
                </label>
                <label>Description<textarea name="description"></textarea></label>
                <label>Assign Client<select name="client_id"><option value="">Library only</option>{options}</select></label>
                <button class="primary-btn" type="submit">Save Worksheet</button>
              </form>
            </section>
            """
        content = f"""
        {form}
        <section class="card">
          <div class="section-heading">
            <h2>Worksheet Library</h2>
            <form method="get" action="/worksheets" class="inline-search">
              <input name="q" value="{html_escape(query)}" placeholder="Search worksheets or clients">
              <button class="primary-btn" type="submit">Search</button>
            </form>
          </div>
          <table class="data-table">
            <thead><tr><th>Worksheet Title</th><th>Category</th><th>Date Added</th><th>Assigned Client</th></tr></thead>
            <tbody>{worksheet_rows or '<tr><td colspan="4">No worksheets found.</td></tr>'}</tbody>
          </table>
        </section>
        """
        self.send_html(layout("Worksheet Library", content, user))

    def post_assign_worksheet(self) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST, ROLE_SUPPORT})
        if not user:
            return
        form = self.read_form()
        with self.db_conn() as conn:
            client_id = int(form.get("client_id")) if form.get("client_id") else None
            if client_id and not user_can_access_client(conn, user, client_id):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>This client is not assigned to you.</p></section>', user), status=403)
                return
            cur = conn.execute(
                """
                INSERT INTO worksheets (title, category, description, date_added, assigned_client_id, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    form.get("title"),
                    form.get("category"),
                    form.get("description"),
                    today_str(),
                    client_id,
                    user["id"],
                ),
            )
            log_activity(conn, user["id"], "worksheet upload", "worksheet", cur.lastrowid, f"Client ID {client_id or 'library'}")
        self.redirect("/worksheets")

    def page_staff_management(self) -> None:
        user = self.require_role({ROLE_ADMIN})
        if not user:
            return
        with self.db_conn() as conn:
            users = conn.execute("SELECT * FROM staff_users ORDER BY role, name").fetchall()
            clients = conn.execute("SELECT id, name FROM clients ORDER BY name").fetchall()
            assignments = conn.execute(
                """
                SELECT client_assignments.*, staff_users.name AS staff_name, clients.name AS client_name
                FROM client_assignments
                JOIN staff_users ON staff_users.id = client_assignments.user_id
                JOIN clients ON clients.id = client_assignments.client_id
                ORDER BY staff_users.name, clients.name
                """
            ).fetchall()
        rows = "".join(
            f"""<tr><td>{html_escape(row['name'])}</td><td>{html_escape(row['username'])}</td><td>{html_escape(row['role'])}</td><td>{'Active' if row['active'] else 'Inactive'}</td>
            <td>{'' if row['role'] == ROLE_ADMIN else f'<form method="post" action="/admin/deactivate-staff" class="inline-form"><input type="hidden" name="user_id" value="{row["id"]}"><button class="ghost-btn" type="submit">Deactivate</button></form>'}</td></tr>"""
            for row in users
        )
        staff_options = "".join(
            f'<option value="{row["id"]}">{html_escape(row["name"])} · {html_escape(row["role"])}</option>'
            for row in users
            if row["role"] != ROLE_ADMIN
        )
        client_options = "".join(f'<option value="{row["id"]}">{html_escape(row["name"])}</option>' for row in clients)
        assignment_rows = "".join(
            f"<tr><td>{html_escape(row['staff_name'])}</td><td>{html_escape(row['client_name'])}</td><td>{html_escape(row['assignment_role'])}</td></tr>"
            for row in assignments
        )
        content = f"""
        <section class="card">
          <h2>Admin Staff Management</h2>
          <form method="post" action="/admin/staff/create" class="stack-form two-col">
            <label>Name<input name="name" required></label>
            <label>Username<input name="username" required></label>
            <label>Password<input name="password" type="password" required></label>
            <label>Role
              <select name="role" required>
                <option>{ROLE_ADMIN}</option>
                <option>{ROLE_THERAPIST}</option>
                <option>{ROLE_SUPPORT}</option>
              </select>
            </label>
            <button class="primary-btn" type="submit">Create Staff User</button>
          </form>
        </section>
        <section class="card">
          <h2>Assign Clients to Staff</h2>
          <form method="post" action="/admin/assign-client" class="stack-form two-col">
            <label>Staff User<select name="user_id" required>{staff_options}</select></label>
            <label>Client<select name="client_id" required>{client_options}</select></label>
            <label>Assignment Type<input name="assignment_role" value="Assigned Caseload" required></label>
            <button class="primary-btn" type="submit">Assign Client</button>
          </form>
        </section>
        <section class="card">
          <table class="data-table">
            <thead><tr><th>Name</th><th>Username</th><th>Role</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </section>
        <section class="card">
          <h2>Client Assignments</h2>
          <table class="data-table">
            <thead><tr><th>Staff</th><th>Client</th><th>Assignment</th></tr></thead>
            <tbody>{assignment_rows or '<tr><td colspan="3">No assignments yet.</td></tr>'}</tbody>
          </table>
        </section>
        """
        self.send_html(layout("Admin Staff Management", content, user))

    def post_create_staff(self) -> None:
        user = self.require_role({ROLE_ADMIN})
        if not user:
            return
        form = self.read_form()
        role = form.get("role", "")
        password = form.get("password", "")
        if role not in {ROLE_ADMIN, ROLE_THERAPIST, ROLE_SUPPORT} or len(password) < 12:
            self.send_html(
                layout(
                    "Invalid Staff Details",
                    '<section class="card"><h2>Invalid staff details</h2><p>Select a valid role and use a password of at least 12 characters.</p></section>',
                    user,
                ),
                status=400,
            )
            return
        salt_hex, hash_hex = password_hash(password)
        with self.db_conn() as conn:
            conn.execute(
                """
                INSERT INTO staff_users (name, username, salt, password_hash, role, active, created_at)
                VALUES (?, ?, ?, ?, ?, 1, ?)
                """,
                (form.get("name"), form.get("username"), salt_hex, hash_hex, role, now_iso()),
            )
            log_activity(conn, user["id"], "created staff user", "staff_user", None, f"Username {form.get('username')}")
        self.redirect("/admin/staff")

    def post_assign_client(self) -> None:
        user = self.require_role({ROLE_ADMIN})
        if not user:
            return
        form = self.read_form()
        with self.db_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO client_assignments (user_id, client_id, assignment_role, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (form.get("user_id"), form.get("client_id"), form.get("assignment_role") or "Assigned Caseload", now_iso()),
            )
            log_activity(conn, user["id"], "client assignment change", "client_assignment", None, f"User {form.get('user_id')} -> Client {form.get('client_id')}")
        self.redirect("/admin/staff")

    def post_deactivate_staff(self) -> None:
        user = self.require_role({ROLE_ADMIN})
        if not user:
            return
        form = self.read_form()
        with self.db_conn() as conn:
            conn.execute("UPDATE staff_users SET active = 0 WHERE id = ? AND role != ?", (form.get("user_id"), ROLE_ADMIN))
            log_activity(conn, user["id"], "deactivated staff account", "staff_user", int(form.get("user_id") or 0), "Staff account deactivated.")
        self.redirect("/admin/staff")

    def post_upload_document(self) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_THERAPIST, ROLE_SUPPORT})
        if not user:
            return
        form = self.read_form()
        client_id = int(form.get("client_id") or 0)
        with self.db_conn() as conn:
            if not user_can_access_client(conn, user, client_id):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>This client is not assigned to you.</p></section>', user), status=403)
                return
            storage_key = STORAGE.store_document_placeholder(
                form.get("title") or "document.txt",
                f"Uploaded by: {user['name']}\nClient ID: {client_id}\nDocument type: {form.get('document_type')}\nNotes: {form.get('notes')}\n",
            )
            cur = conn.execute(
                """
                INSERT INTO documents (client_id, title, document_type, notes, storage_key, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (client_id, form.get("title"), form.get("document_type"), form.get("notes"), storage_key, user["id"], now_iso()),
            )
            log_activity(conn, user["id"], "document upload", "document", cur.lastrowid, f"Client ID {client_id}")
        self.redirect(f"/clients/{client_id}?tab=billing")

    def post_flag_missing(self) -> None:
        user = self.require_role({ROLE_ADMIN, ROLE_SUPPORT})
        if not user:
            return
        form = self.read_form()
        client_id = int(form.get("client_id") or 0)
        with self.db_conn() as conn:
            if not user_can_access_client(conn, user, client_id):
                self.send_html(layout("Access Denied", '<section class="card"><h2>Access denied</h2><p>This client is not assigned to you.</p></section>', user), status=403)
                return
            log_activity(conn, user["id"], "flagged missing forms", "client", client_id, "Support review flagged documentation follow-up.")
        self.redirect(f"/clients/{client_id}?tab=billing")

    def page_reports(self) -> None:
        user = self.require_role({ROLE_ADMIN})
        if not user:
            return
        with self.db_conn() as conn:
            rows = fetch_scoped_statuses(conn, user)
        total_sessions = sum(int(row["sessions_count"]) for row in rows)
        missing_plans = sum(1 for row in rows if row["treatment_plan_status"] != "OK")
        missing_forms = sum(1 for row in rows if row["missing_forms_flag"] != "OK")
        content = f"""
        <section class="card">
          <h2>Admin Reports</h2>
          <div class="summary-grid">
            <div><span class="eyebrow">Total Clients</span><strong>{len(rows)}</strong></div>
            <div><span class="eyebrow">Total Sessions</span><strong>{total_sessions}</strong></div>
            <div><span class="eyebrow">Missing Treatment Plans</span><strong>{missing_plans}</strong></div>
            <div><span class="eyebrow">Missing Forms</span><strong>{missing_forms}</strong></div>
          </div>
          <p class="muted">This local preview prepares the reporting layer for secure hosting later.</p>
        </section>
        """
        self.send_html(layout("Reports", content, user))

    def page_settings(self) -> None:
        user = self.require_role({ROLE_ADMIN})
        if not user:
            return
        content = f"""
        <section class="card">
          <h2>Portal Settings</h2>
          <div class="summary-grid">
            <div><span class="eyebrow">HTTPS Enforcement</span><strong>{"Required" if SETTINGS.require_https else "Prepared, off in local preview"}</strong></div>
            <div><span class="eyebrow">MFA Requirement</span><strong>{"Required" if SETTINGS.require_mfa_all_staff else "Prepared, off in local preview"}</strong></div>
            <div><span class="eyebrow">Session Timeout</span><strong>{SESSION_HOURS} hours</strong></div>
            <div><span class="eyebrow">Secure Cookies</span><strong>{"Enabled" if SETTINGS.secure_cookies else "Prepared, off in local preview"}</strong></div>
            <div><span class="eyebrow">Storage Root</span><strong>{html_escape(str(SETTINGS.storage_root))}</strong></div>
            <div><span class="eyebrow">Portal Scope</span><strong>Staff-only, no client portal routes enabled</strong></div>
          </div>
          <p>Settings management is reserved for admin users. This preview includes the secured route, audit-ready structure, secure storage abstraction, and hosted-mode configuration flags for later private deployment.</p>
        </section>
        """
        self.send_html(layout("Settings", content, user))

    def page_audit(self) -> None:
        user = self.require_role({ROLE_ADMIN})
        if not user:
            return
        with self.db_conn() as conn:
            rows = conn.execute(
                """
                SELECT activity_log.*, staff_users.name AS actor_name
                FROM activity_log
                LEFT JOIN staff_users ON staff_users.id = activity_log.actor_user_id
                ORDER BY activity_log.created_at DESC, activity_log.id DESC
                LIMIT 150
                """
            ).fetchall()
        table = "".join(
            f"<tr><td>{html_escape(row['created_at'])}</td><td>{html_escape(row['actor_name'] or 'System')}</td><td>{html_escape(row['action'])}</td><td>{html_escape(row['target_type'])}</td><td>{html_escape(row['details'] or '')}</td></tr>"
            for row in rows
        )
        content = f"""
        <section class="card">
          <h2>Audit Log</h2>
          <table class="data-table">
            <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
            <tbody>{table}</tbody>
          </table>
        </section>
        """
        self.send_html(layout("Audit Log", content, user))


def main() -> None:
    init_db()
    server = HTTPServer((HOST, PORT), StaffPortalHandler)
    print(f"Pathway staff portal running at http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()

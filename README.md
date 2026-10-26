# Pathway Staff Portal

Local-first staff-only clinical documentation portal for Pathway Guidance Services.

## Local Preview

Run:

```sh
cd /Users/pathway/pathway-staff-portal
chmod +x start_staff_portal.sh
./start_staff_portal.sh
```

Open:

```text
http://127.0.0.1:8890
```

## Deployable Web App

The hosted-ready app is the FastAPI version under [webapp/main.py](/Users/pathway/pathway-staff-portal/webapp/main.py), not the older local preview in [app.py](/Users/pathway/pathway-staff-portal/app.py).

### Local hosted-mode smoke test

Use a temporary SQLite database for local verification:

```sh
cd /Users/pathway/pathway-staff-portal
source .venv/bin/activate
export PATHWAY_DATABASE_URL=sqlite+pysqlite:///./data/hosted_preview.db
export PATHWAY_STORAGE_ROOT=/Users/pathway/pathway-staff-portal/data/secure_storage
gunicorn -c gunicorn.conf.py webapp.main:app
```

Open:

```text
http://127.0.0.1:8891
```

### Private deployment target

For secure hosted deployment, use:

- `webapp.main:app` as the Gunicorn target
- PostgreSQL via `PATHWAY_DATABASE_URL`
- HTTPS enforced by `PATHWAY_REQUIRE_HTTPS=true`
- MFA: the `PATHWAY_REQUIRE_MFA` flag exists, but MFA enrollment/verification is **not implemented yet**; setting it to `true` blocks every login. Keep it `false` until that flow is built.
- storage rooted at `/data/clients` or an object-storage backend

Production startup:

```sh
cd /Users/pathway/pathway-staff-portal
source .venv/bin/activate
gunicorn -c gunicorn.conf.py webapp.main:app
```

## Seeded Staff Accounts (local/dev only)

On first run against an empty database, the app creates four demo accounts
(`drbarnett_admin`, `therapist_jackson`, `therapist_williams`,
`assistant_morgan`) with a **random password generated at startup and printed
once to the server console/logs** — it is never written to this file, to a
template, or to the login page. Read it from the console output the first
time you start the app, then change it immediately from the "Change password" link (`/account`) in the header.

Seeding is skipped entirely when `PATHWAY_ENV=production` (set
`PATHWAY_ALLOW_DEV_SEED_DATA=true` to force it, which you should not do on a
real deployment). Restarting the app never resets an existing account's
password.

## Current Features

- Session-based authentication with hashed passwords
- Role-based access for Admin, Therapist, and Support Staff
- Clinical records are visible only to Admin and Therapist roles; Support Staff can access assigned-client billing and documents
- Self-service password change (minimum 12 characters)
- Login lockout after repeated failures
- Admin-only staff management, reporting, settings, and audit log
- Assigned-client scoping for Therapist and Support Staff
- Client dashboard and searchable client list
- Client detail page with overview, sessions, forms, worksheets, and billing/documents
- Create and edit flows for SOAP notes, treatment plans, summary reports, and safety plans
- Worksheet assignment
- Document upload and download records
- Audit logging for login, form creation, form edits, worksheet uploads, document uploads, and client assignment changes
- Secure local document storage abstraction under `data/secure_storage/`

## Deployment Prep

This preview uses SQLite and Python standard library components so it can later be moved into a hosted private deployment with:

- HTTPS enforcement via reverse proxy and app config
- MFA-required hosted mode: config flag and schema only (enrollment flow not built yet)
- Secure-cookie mode and session timeout configuration
- Role-based route protection already centralized in the app
- Audit logging already enabled
- Storage abstraction already separated from Desktop paths
- A separate future client portal stub so staff-only logic remains isolated

See [DEPLOYMENT_PLAN.md](/Users/pathway/pathway-staff-portal/DEPLOYMENT_PLAN.md) and [PRIVATE_DEPLOYMENT.env.example](/Users/pathway/pathway-staff-portal/deployment/PRIVATE_DEPLOYMENT.env.example).

## Staff Rollout

Staff onboarding materials are grouped in [staff_rollout](/Users/pathway/pathway-staff-portal/staff_rollout).

- [Quick Start SOP](/Users/pathway/pathway-staff-portal/staff_rollout/STAFF_PORTAL_QUICK_START_SOP.md)
- [5 Minute Training Script](/Users/pathway/pathway-staff-portal/staff_rollout/STAFF_PORTAL_5_MINUTE_TRAINING_SCRIPT.md)
cd /Users/pathway/pathway-staff-portal

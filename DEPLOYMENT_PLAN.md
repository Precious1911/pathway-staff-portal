# Pathway Staff Portal Deployment Plan

## Scope

This application is staff-only. It is intended for internal clinical documentation, operational support, and audit-ready staff workflows. No client-facing routes are enabled in this project.

## Current Local Preview

- Local database: SQLite at `data/portal.db`
- Local secure storage abstraction: `data/secure_storage/`
- Session-based authentication with PBKDF2 password hashing
- Role-based route protection for `Admin`, `Therapist`, and `Support Staff`
- Clinical records are restricted to Admin and Therapist; Support Staff can access assigned-client billing and documents
- Audit logging for login, form creation and edits, worksheet actions, document upload, and client assignment changes

## Hosted Deployment Target

Recommended first hosted environment:

- Private VPS or managed private container platform
- Reverse proxy termination with Nginx or Caddy
- HTTPS-only access
- Private DNS or restricted network/VPN access
- Managed database upgrade path from SQLite to Postgres
- Encrypted object or volume storage behind the storage abstraction layer

## Required Hosted Security Controls

1. Enable HTTPS enforcement:
   - Set `PATHWAY_REQUIRE_HTTPS=true` (this also marks the session cookie `Secure`)
   - Set `PATHWAY_TRUSTED_PROXY_IPS` to the reverse proxy's exact peer IP(s) (`/32` or `/128`), not a broad CIDR. For host nginx in front of Docker Compose, configure the Docker bridge gateway address observed by the app.
   - Terminate TLS at the reverse proxy

2. Require MFA for all staff:
   - NOT YET AVAILABLE: MFA enrollment/verification is not built. Do not set `PATHWAY_REQUIRE_MFA=true` until it is, or no one can log in
   - Store per-user MFA secret material encrypted at rest

3. Tighten session policy:
   - Reduce `PATHWAY_SESSION_HOURS` from local preview defaults
   - Consider 2-8 hour session windows depending on office workflow
   - Add idle timeout tracking in a later hosted iteration

4. Move storage off local disk:
   - Replace local secure storage placeholders with encrypted hosted storage
   - Recommended targets: private S3-compatible bucket, encrypted attached volume, or managed blob storage
   - Keep application writes going through `storage.py`

5. Protect infrastructure:
   - Restrict inbound IPs where possible
   - Enable system and application log shipping
   - Back up database and secure storage
   - Monitor failed logins and abnormal session creation

## Deployment Layout

Recommended structure:

- Reverse proxy: Nginx
- App process: `gunicorn -c gunicorn.conf.py webapp.main:app` (port 8891) behind the reverse proxy; `app.py` is the legacy local preview only
- Process manager: `systemd` or container supervisor
- Database: SQLite first, Postgres later
- Storage root: dedicated private path outside app code checkout

## Staff-Only Boundary

This project intentionally excludes a client portal. To keep that separation clear:

- Do not add client-facing authentication routes here
- Do not reuse staff session tables for client login later
- Keep future client portal logic in a separate application or service boundary

## Future Client Portal Stub

A placeholder directory exists at `future_client_portal/`. It is informational only and should remain separate from the staff runtime.

## Rollout Checklist

- Confirm fake preview data has been removed or replaced before production use
- Replace temporary passwords
- Have each staff member change their password at `/account` on first login (forced rotation is not implemented)
- Enable HTTPS enforcement (MFA flag only once MFA is implemented)
- Point storage root to encrypted hosted storage
- Migrate SQLite to Postgres if multi-user usage increases
- Validate admin-only views and assignment scoping in hosted mode
- Review audit log retention and backup policy

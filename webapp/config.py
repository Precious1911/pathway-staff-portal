from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


WEAK_SECRET_KEYS = {"", "change-me-before-hosting", "replace-with-a-long-random-secret"}
TRUSTED_PROXY_IPS_DEFAULT = "127.0.0.1,::1"


@dataclass(frozen=True)
class Settings:
    app_name: str
    environment: str
    debug: bool
    host: str
    port: int
    secret_key: str
    session_hours: int
    require_https: bool
    require_mfa: bool
    database_url: str
    storage_backend: str
    storage_root: Path
    s3_bucket: str
    s3_region: str
    show_demo_credentials: bool
    allow_dev_seed_data: bool
    trusted_proxy_ips: tuple[str, ...]
    max_login_attempts: int
    login_lockout_minutes: int


def get_settings(root: Path) -> Settings:
    environment = os.getenv("PATHWAY_ENV", "development").strip().lower()
    secret_key = os.getenv("PATHWAY_SECRET_KEY", "")
    if environment == "production" and (not secret_key or secret_key in WEAK_SECRET_KEYS or len(secret_key) < 32):
        raise RuntimeError(
            "PATHWAY_SECRET_KEY must be set to a long random value before running with PATHWAY_ENV=production."
        )
    if not secret_key:
        secret_key = "change-me-before-hosting"
    require_https = env_bool("PATHWAY_REQUIRE_HTTPS", environment == "production")
    if environment == "production" and not require_https:
        raise RuntimeError("PATHWAY_REQUIRE_HTTPS must be enabled in production.")

    return Settings(
        app_name=os.getenv("PATHWAY_APP_NAME", "Pathway Staff Portal"),
        environment=environment,
        debug=env_bool("PATHWAY_DEBUG", False),
        host=os.getenv("PATHWAY_HOST", "127.0.0.1"),
        port=int(os.getenv("PATHWAY_PORT", "8891")),
        secret_key=secret_key,
        session_hours=int(os.getenv("PATHWAY_SESSION_HOURS", "8")),
        require_https=require_https,
        require_mfa=env_bool("PATHWAY_REQUIRE_MFA", False),
        database_url=os.getenv(
            "PATHWAY_DATABASE_URL",
            "postgresql+psycopg://pathway_staff:pathway_staff@localhost:5432/pathway_staff_portal",
        ),
        storage_backend=os.getenv("PATHWAY_STORAGE_BACKEND", "local"),
        storage_root=Path(os.getenv("PATHWAY_STORAGE_ROOT", "/data/clients")),
        s3_bucket=os.getenv("PATHWAY_S3_BUCKET", ""),
        s3_region=os.getenv("PATHWAY_S3_REGION", ""),
        show_demo_credentials=env_bool("PATHWAY_SHOW_DEMO_CREDENTIALS", False),
        allow_dev_seed_data=env_bool("PATHWAY_ALLOW_DEV_SEED_DATA", environment != "production"),
        trusted_proxy_ips=_trusted_proxy_ips(environment),
        max_login_attempts=int(os.getenv("PATHWAY_MAX_LOGIN_ATTEMPTS", "5")),
        login_lockout_minutes=int(os.getenv("PATHWAY_LOGIN_LOCKOUT_MINUTES", "15")),
    )


def _trusted_proxy_ips(environment: str) -> tuple[str, ...]:
    entries = tuple(
        ip.strip()
        for ip in os.getenv("PATHWAY_TRUSTED_PROXY_IPS", TRUSTED_PROXY_IPS_DEFAULT).split(",")
        if ip.strip()
    )
    if environment == "production":
        for entry in entries:
            network = ipaddress.ip_network(entry, strict=False)
            if network.prefixlen != network.max_prefixlen:
                raise RuntimeError(
                    "Production PATHWAY_TRUSTED_PROXY_IPS entries must be individual IPs (/32 or /128)."
                )
    return entries

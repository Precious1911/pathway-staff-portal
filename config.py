from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    root: Path
    host: str
    port: int
    session_hours: int
    require_https: bool
    require_mfa_all_staff: bool
    secure_cookies: bool
    storage_root: Path
    trusted_proxy_header: str
    trusted_proxy_ips: tuple[str, ...]


def load_settings(root: Path) -> Settings:
    production = os.getenv("PATHWAY_ENV", "").strip().lower() == "production"
    require_https = _env_bool("PATHWAY_STAFF_REQUIRE_HTTPS", _env_bool("PATHWAY_REQUIRE_HTTPS", production))
    if production and not require_https:
        raise RuntimeError("HTTPS must be required in production.")
    trusted_proxy_ips = tuple(
        item.strip()
        for item in os.getenv("PATHWAY_TRUSTED_PROXY_IPS", "127.0.0.1,::1").split(",")
        if item.strip()
    )
    for item in trusted_proxy_ips:
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise RuntimeError(f"Invalid trusted proxy IP or CIDR: {item}") from exc
        if production and network.prefixlen != network.max_prefixlen:
            raise RuntimeError("Production trusted proxy entries must be individual IPs (/32 or /128).")
    return Settings(
        root=root,
        host=os.getenv("PATHWAY_STAFF_HOST", "127.0.0.1"),
        port=int(os.getenv("PATHWAY_STAFF_PORT", "8890")),
        session_hours=int(os.getenv("PATHWAY_STAFF_SESSION_HOURS", "10")),
        require_https=require_https,
        require_mfa_all_staff=_env_bool("PATHWAY_STAFF_REQUIRE_MFA", False),
        secure_cookies=_env_bool("PATHWAY_STAFF_SECURE_COOKIES", require_https),
        storage_root=Path(os.getenv("PATHWAY_STAFF_STORAGE_ROOT", str(root / "data" / "secure_storage"))),
        trusted_proxy_header=os.getenv("PATHWAY_STAFF_PROXY_HEADER", "X-Forwarded-Proto"),
        trusted_proxy_ips=trusted_proxy_ips,
    )

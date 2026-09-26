"""Application configuration, loaded from environment variables / .env.

Secrets are NEVER hardcoded. In production (``ENVIRONMENT=production``) a
``SECRET_KEY`` must be supplied or startup fails loudly; in development a
throwaway key is generated so the app is runnable out of the box.
"""
from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Core ---
    app_name: str = "SentinelX"
    environment: Literal["development", "test", "production"] = "development"
    api_v1_prefix: str = "/api/v1"

    # --- Security / auth ---
    secret_key: str = Field(default="")
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    jwt_algorithm: str = "HS256"
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    # --- Database ---
    # SQLite by default so the platform runs locally with no external services;
    # set DATABASE_URL to a PostgreSQL DSN in production (docker-compose does).
    database_url: str = "sqlite:///./sentinelx.db"

    # --- CORS ---
    cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # --- Background processing ---
    redis_url: str = ""
    # When Redis is not configured, Celery runs tasks eagerly (in-process) so
    # scans still work for local development and tests.
    celery_task_always_eager: bool = True

    # --- Scan safety / SSRF controls ---
    # Scanning is authorization-gated at the data layer. This flag additionally
    # governs whether targets that resolve to private/loopback/link-local IPs
    # may be scanned. Enable it ONLY for the local security lab / testbed.
    allow_private_scan_targets: bool = False
    scan_max_pages: int = 100
    scan_max_concurrency: int = 4
    scan_requests_per_second: float = 8.0
    scan_timeout_seconds: int = 20
    scan_hard_deadline_seconds: int = 900

    # --- Rate limiting (auth endpoints) ---
    rate_limit_login_per_minute: int = 10

    # --- AI analyst (optional, read-only) ---
    ai_enabled: bool = False
    ai_provider: Literal["none", "anthropic"] = "none"
    anthropic_api_key: str = ""
    ai_model: str = "claude-opus-4-8"

    # --- Bootstrap admin (first-run only; used by the seed script) ---
    first_superuser_email: str = "admin@sentinelx.local"
    first_superuser_password: str = ""

    @field_validator("secret_key", mode="after")
    @classmethod
    def _ensure_secret(cls, v: str, info) -> str:
        env = info.data.get("environment", "development")
        if v:
            return v
        if env == "production":
            raise ValueError(
                "SECRET_KEY must be set in production. Generate one with "
                "`python -c \"import secrets; print(secrets.token_urlsafe(48))\"`."
            )
        # Ephemeral key for dev/test only — tokens do not survive a restart.
        return secrets.token_urlsafe(48)

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

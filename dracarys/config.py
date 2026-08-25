"""Central configuration for the DRACARYS platform.

All configuration is environment-driven (12-factor). A safe local-only default
is provided so the platform runs out of the box without Docker, Postgres, Redis,
or any LLM API key. See ``.env.example`` for the documented surface.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DRACARYS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Core ---
    environment: str = Field(default="development")
    debug: bool = Field(default=True)

    # --- Database ---
    # Async SQLAlchemy URL. SQLite for zero-dependency local dev; swap for
    # postgresql+asyncpg://... in production (see docker-compose.yml).
    database_url: str = Field(default="sqlite+aiosqlite:///./dracarys.db")

    # --- API server ---
    api_host: str = Field(default="127.0.0.1")
    api_port: int = Field(default=8000)
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    # --- DRACARYS LAB (the deliberately vulnerable target) ---
    # The lab is launched as a local process. These are the ONLY hosts the
    # offensive tooling is allowed to reach by default (see PolicyEngine).
    lab_host: str = Field(default="127.0.0.1")
    lab_port: int = Field(default=8888)
    # Port used when a patched/disposable lab instance is spun up for retest.
    lab_patched_port: int = Field(default=8889)

    # --- Policy / safety envelope ---
    # Comma-separated hostnames the offensive tooling may target. Localhost only
    # by default. This is the primary guardrail against pointing DRACARYS at
    # arbitrary external systems.
    scope_allowlist: list[str] = Field(
        default_factory=lambda: ["127.0.0.1", "localhost", "::1"]
    )
    # Only these ports are ever reachable, regardless of host allowlisting.
    scope_allowed_ports: list[int] = Field(
        default_factory=lambda: [8888, 8889]
    )
    # Per-campaign hard caps.
    max_requests_per_campaign: int = Field(default=2000)
    max_concurrency: int = Field(default=8)
    tool_timeout_seconds: float = Field(default=10.0)
    campaign_budget_seconds: int = Field(default=600)

    # --- LLM planner (optional) ---
    # If unset, DRACARYS uses the deterministic HeuristicPlanner. Findings are
    # ALWAYS validated deterministically regardless of planner.
    llm_provider: str = Field(default="heuristic")  # "heuristic" | "anthropic"
    anthropic_api_key: str | None = Field(default=None)
    llm_model: str = Field(default="claude-sonnet-5")
    llm_max_tokens: int = Field(default=2048)

    @property
    def lab_base_url(self) -> str:
        return f"http://{self.lab_host}:{self.lab_port}"

    @property
    def lab_patched_base_url(self) -> str:
        return f"http://{self.lab_host}:{self.lab_patched_port}"


@lru_cache
def get_settings() -> Settings:
    return Settings()

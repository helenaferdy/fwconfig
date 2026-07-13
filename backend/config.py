"""Application configuration loaded from environment variables."""

from __future__ import annotations

from pathlib import Path
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(
            str(Path(__file__).resolve().parent / ".env"),
            str(Path(__file__).resolve().parent.parent / ".env"),
            ".env",
        ),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Firewall Migration Platform"
    app_version: str = "0.1.0"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8006

    # Absolute project root; defaults resolve relative to this file's parent parent.
    project_root: Path = Path(__file__).resolve().parent.parent
    data_dir: Path | None = None
    sessions_dir: Path | None = None

    # CORS – frontend origin(s)
    cors_origins: str = "http://localhost:8006,http://127.0.0.1:8006"

    # OpenCode / DeepSeek AI
    opencode_api_key: str = ""
    opencode_base_url: str = "https://opencode.ai/zen/go/v1"
    opencode_model: str = "deepseek-v4-flash"
    ai_enabled: bool = True
    ai_max_tokens: int = 2048
    ai_temperature: float = 0.15

    # Upload limits
    max_upload_bytes: int = 50 * 1024 * 1024  # 50 MB
    allowed_extensions: str = ".conf,.cfg,.txt,.xml,.json,.tgz,.tar,.gz,.zip,.csv"

    @property
    def resolved_data_dir(self) -> Path:
        return self.data_dir or (self.project_root / "data")

    @property
    def resolved_sessions_dir(self) -> Path:
        return self.sessions_dir or (self.resolved_data_dir / "sessions")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def allowed_extension_list(self) -> list[str]:
        return [e.strip().lower() for e in self.allowed_extensions.split(",") if e.strip()]


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.resolved_data_dir.mkdir(parents=True, exist_ok=True)
    settings.resolved_sessions_dir.mkdir(parents=True, exist_ok=True)
    return settings

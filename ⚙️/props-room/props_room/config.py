from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PROPS_ROOM_",
        extra="ignore",
    )

    host: str = "0.0.0.0"
    port: int = 8300
    data_dir: str = "./data"
    dstack_enabled: bool = False
    seal_key_hex: str = ""
    allow_host_subprocess: bool = False
    tv_repo_root: str = ""

    @property
    def resolved_data_dir(self) -> Path:
        return Path(self.data_dir).expanduser().resolve()

    @property
    def resolved_tv_repo_root(self) -> Path:
        if self.tv_repo_root:
            return Path(self.tv_repo_root).expanduser().resolve()
        return Path(__file__).resolve().parents[3] / "🔬" / "tv"


settings = Settings()

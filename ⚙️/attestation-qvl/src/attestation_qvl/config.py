"""Minimal environment configuration for the QVL process."""

from __future__ import annotations

import re

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


MAX_SERVER_PHASE_BUDGET_SECONDS = 25.0


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="QVL_",
        case_sensitive=False,
        extra="ignore",
    )

    release_policy_path: str
    auth_token: SecretStr
    pccs_url: str = "https://pccs.phala.network"
    max_concurrency: int = Field(default=4, ge=1, le=16)
    rate_capacity: int = Field(default=30, ge=1, le=600)
    rate_refill_per_second: float = Field(default=0.5, gt=0, le=100)
    challenge_ttl_seconds: int = Field(default=60, ge=10, le=120)
    challenge_capacity: int = Field(default=1_024, ge=16, le=65_536)
    request_body_timeout_seconds: float = Field(default=5.0, ge=0.5, le=15.0)
    verification_timeout_seconds: float = Field(default=20.0, ge=1.0, le=60.0)

    @model_validator(mode="after")
    def validate_server_phase_budget(self) -> Settings:
        phase_budget = (
            self.request_body_timeout_seconds + self.verification_timeout_seconds
        )
        if phase_budget > MAX_SERVER_PHASE_BUDGET_SECONDS:
            raise ValueError(
                "QVL request-body and verification timeouts exceed the server phase budget"
            )
        return self

    @field_validator("auth_token")
    @classmethod
    def validate_auth_token(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if (
            len(secret) < 32
            or len(secret) > 4096
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in secret)
        ):
            raise ValueError("QVL auth token is invalid")
        return value

    @field_validator("pccs_url")
    @classmethod
    def validate_pccs_url(cls, value: str) -> str:
        if value != "https://pccs.phala.network":
            raise ValueError("PCCS URL is not the compiled release endpoint")
        return value

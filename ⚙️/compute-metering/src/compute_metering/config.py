"""Minimal secret-safe environment configuration."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit
import re

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="METERING_",
        case_sensitive=False,
        extra="ignore",
    )

    policy_set_path: str
    rpc_url: SecretStr
    auth_token: SecretStr
    qvl_url: str
    qvl_auth_token: SecretStr
    qvl_verifier_address: str
    qvl_release_policy_hash: str
    cvm_id: str
    deployment_intent_sha256: str
    release_authority_sha256: str
    ceremony_nonce: str
    qvl_measurement_policy_sha256: str
    state_path: str
    rpc_timeout_seconds: float = Field(default=8.0, ge=1.0, le=30.0)
    max_concurrency: int = Field(default=4, ge=1, le=16)
    rate_capacity: int = Field(default=30, ge=1, le=600)
    rate_refill_per_second: float = Field(default=0.5, gt=0, le=100)
    request_body_timeout_seconds: float = Field(default=5.0, ge=0.5, le=15.0)

    @field_validator("auth_token", "qvl_auth_token")
    @classmethod
    def validate_auth_token(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if (
            len(secret) < 32
            or len(secret) > 4096
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in secret)
        ):
            raise ValueError("metering auth token is invalid")
        return value

    @field_validator("qvl_url")
    @classmethod
    def validate_qvl_url(cls, value: str) -> str:
        if len(value) > 2048 or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
            raise ValueError("QVL URL is invalid")
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/verify"
            or parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError("QVL URL must be an exact remote HTTPS /verify endpoint")
        return value

    @field_validator("qvl_verifier_address")
    @classmethod
    def validate_qvl_verifier_address(cls, value: str) -> str:
        normalized = value.lower()
        if not re.fullmatch(r"0x(?!0{40}$)[0-9a-f]{40}", normalized):
            raise ValueError("QVL verifier address is invalid")
        return normalized

    @field_validator("qvl_release_policy_hash")
    @classmethod
    def validate_qvl_release_policy_hash(cls, value: str) -> str:
        normalized = value.lower()
        if not re.fullmatch(r"0x(?!0{64}$)[0-9a-f]{64}", normalized):
            raise ValueError("QVL release policy hash is invalid")
        return normalized

    @field_validator("cvm_id")
    @classmethod
    def validate_cvm_id(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{7,127}", value):
            raise ValueError("metering CVM ID is invalid")
        return value

    @field_validator(
        "deployment_intent_sha256",
        "release_authority_sha256",
        "qvl_measurement_policy_sha256",
    )
    @classmethod
    def validate_release_sha256(cls, value: str) -> str:
        if not re.fullmatch(r"sha256:(?!0{64}$)[0-9a-f]{64}", value):
            raise ValueError("metering release digest is invalid")
        return value

    @field_validator("ceremony_nonce")
    @classmethod
    def validate_ceremony_nonce(cls, value: str) -> str:
        if not re.fullmatch(r"0x(?!0{64}$)[0-9a-f]{64}", value):
            raise ValueError("metering ceremony nonce is invalid")
        return value

    @field_validator("rpc_url")
    @classmethod
    def validate_rpc_url(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if len(secret) > 2048 or any(ord(character) < 0x21 or ord(character) > 0x7E for character in secret):
            raise ValueError("RPC URL is invalid")
        parsed = urlsplit(secret)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError("RPC URL must be HTTPS without userinfo or fragment")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("RPC URL port is invalid") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("RPC URL port is invalid")
        return value

    @field_validator("policy_set_path", "state_path")
    @classmethod
    def require_absolute_paths(cls, value: str) -> str:
        if "\x00" in value or not Path(value).is_absolute():
            raise ValueError("runtime paths must be absolute")
        return value

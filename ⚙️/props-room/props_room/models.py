from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import time


class DealStage(str, Enum):
    FUNDED = "funded"
    RAW_APPROVED = "raw_approved"
    RAW_INGESTED = "raw_ingested"
    TRAINING_APPROVED = "training_approved"
    INFERENCE_ACTIVE = "inference_active"
    RESOLVED = "resolved"


class JobStatus(str, Enum):
    PLANNED = "planned"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ControllerRecord:
    controller_id: str
    human_name: str
    source_kind: str
    policy_note: str
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "controller_id": self.controller_id,
            "human_name": self.human_name,
            "source_kind": self.source_kind,
            "policy_note": self.policy_note,
            "created_at": self.created_at,
        }


@dataclass
class PropsDeal:
    deal_id: str
    controller_id: str
    sponsor_id: str
    reserve_price: int
    budget_cap: int
    purpose: str
    allowed_outputs: list[str]
    stage: DealStage = DealStage.FUNDED
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "deal_id": self.deal_id,
            "controller_id": self.controller_id,
            "sponsor_id": self.sponsor_id,
            "reserve_price": self.reserve_price,
            "budget_cap": self.budget_cap,
            "purpose": self.purpose,
            "allowed_outputs": self.allowed_outputs,
            "stage": self.stage.value,
            "created_at": self.created_at,
        }


@dataclass
class RawScrapeApproval:
    approval_id: str
    deal_id: str
    controller_id: str
    source_label: str
    source_locator: str
    pipeline_id: str
    allowed_jobs: list[str]
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "approval_id": self.approval_id,
            "deal_id": self.deal_id,
            "controller_id": self.controller_id,
            "source_label": self.source_label,
            "source_locator": self.source_locator,
            "pipeline_id": self.pipeline_id,
            "allowed_jobs": self.allowed_jobs,
            "created_at": self.created_at,
        }


@dataclass
class RawIngestionJob:
    job_id: str
    approval_id: str
    deal_id: str
    mode: str
    description: str
    command: list[str]
    expected_outputs: list[str]
    status: JobStatus
    created_at: float = field(default_factory=time.time)
    exit_code: int | None = None
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    captured_asset_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "approval_id": self.approval_id,
            "deal_id": self.deal_id,
            "mode": self.mode,
            "description": self.description,
            "command": self.command,
            "expected_outputs": self.expected_outputs,
            "status": self.status.value,
            "created_at": self.created_at,
            "exit_code": self.exit_code,
            "stdout_excerpt": self.stdout_excerpt,
            "stderr_excerpt": self.stderr_excerpt,
            "captured_asset_ids": self.captured_asset_ids,
        }


@dataclass
class TrainingApproval:
    approval_id: str
    deal_id: str
    asset_ids: list[str]
    cohort_id: str
    training_backend: str
    intended_model: str
    participant_ids: list[str]
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "approval_id": self.approval_id,
            "deal_id": self.deal_id,
            "asset_ids": self.asset_ids,
            "cohort_id": self.cohort_id,
            "training_backend": self.training_backend,
            "intended_model": self.intended_model,
            "participant_ids": self.participant_ids,
            "created_at": self.created_at,
        }


@dataclass
class InferenceGrant:
    grant_id: str
    deal_id: str
    cohort_id: str
    participant_id: str
    model_ref: str
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "grant_id": self.grant_id,
            "deal_id": self.deal_id,
            "cohort_id": self.cohort_id,
            "participant_id": self.participant_id,
            "model_ref": self.model_ref,
            "created_at": self.created_at,
        }

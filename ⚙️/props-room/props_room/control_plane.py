"""NDAI + Props stub control plane for source approvals and raw ingest jobs."""

from __future__ import annotations

from pathlib import Path
import uuid

from .models import (
    ControllerRecord,
    DealStage,
    InferenceGrant,
    JobStatus,
    PropsDeal,
    RawIngestionJob,
    RawScrapeApproval,
    TrainingApproval,
)
from .sealed_store import SealedBlobStore
from .tv_adapter import TVIngestionAdapter, TVRawScrapeRequest


class PropsControlPlane:
    def __init__(self, store: SealedBlobStore, tv_adapter: TVIngestionAdapter) -> None:
        self.store = store
        self.tv_adapter = tv_adapter

        self.controllers: dict[str, ControllerRecord] = {}
        self.deals: dict[str, PropsDeal] = {}
        self.raw_approvals: dict[str, RawScrapeApproval] = {}
        self.jobs: dict[str, RawIngestionJob] = {}
        self.training_approvals: dict[str, TrainingApproval] = {}
        self.inference_grants: dict[str, InferenceGrant] = {}

    def register_controller(self, human_name: str, source_kind: str, policy_note: str) -> ControllerRecord:
        controller = ControllerRecord(
            controller_id=self._new_id("controller"),
            human_name=human_name,
            source_kind=source_kind,
            policy_note=policy_note,
        )
        self.controllers[controller.controller_id] = controller
        return controller

    def open_deal(
        self,
        controller_id: str,
        sponsor_id: str,
        reserve_price: int,
        budget_cap: int,
        purpose: str,
        allowed_outputs: list[str],
    ) -> PropsDeal:
        self._require_controller(controller_id)
        if budget_cap < reserve_price:
            raise ValueError("budget_cap must be >= reserve_price")

        deal = PropsDeal(
            deal_id=self._new_id("deal"),
            controller_id=controller_id,
            sponsor_id=sponsor_id,
            reserve_price=reserve_price,
            budget_cap=budget_cap,
            purpose=purpose,
            allowed_outputs=allowed_outputs,
        )
        self.deals[deal.deal_id] = deal
        return deal

    def approve_raw_scrape(
        self,
        deal_id: str,
        source_label: str,
        source_locator: str,
        pipeline_id: str,
        allowed_jobs: list[str],
    ) -> RawScrapeApproval:
        deal = self._require_deal(deal_id)
        approval = RawScrapeApproval(
            approval_id=self._new_id("raw"),
            deal_id=deal_id,
            controller_id=deal.controller_id,
            source_label=source_label,
            source_locator=source_locator,
            pipeline_id=pipeline_id,
            allowed_jobs=allowed_jobs,
        )
        self.raw_approvals[approval.approval_id] = approval
        deal.stage = DealStage.RAW_APPROVED
        return approval

    def submit_tv_job(
        self,
        approval_id: str,
        request: TVRawScrapeRequest,
        *,
        execute: bool,
        capture_outputs: bool,
    ) -> RawIngestionJob:
        approval = self._require_raw_approval(approval_id)
        if request.mode not in approval.allowed_jobs:
            raise PermissionError(
                f"Mode '{request.mode}' is not approved for approval {approval_id}"
            )

        plan = self.tv_adapter.plan_raw_scrape(request)
        job = RawIngestionJob(
            job_id=self._new_id("job"),
            approval_id=approval_id,
            deal_id=approval.deal_id,
            mode=plan.mode,
            description=plan.description,
            command=plan.argv,
            expected_outputs=plan.expected_outputs,
            status=JobStatus.PLANNED,
        )

        if execute:
            result = self.tv_adapter.execute(plan)
            job.exit_code = result.exit_code
            job.stdout_excerpt = result.stdout[-4000:]
            job.stderr_excerpt = result.stderr[-4000:]
            if result.exit_code == 0:
                job.status = JobStatus.COMPLETED
                self.deals[approval.deal_id].stage = DealStage.RAW_INGESTED
                if capture_outputs:
                    for output in plan.expected_outputs:
                        full_path = Path(plan.cwd) / output
                        if not full_path.exists():
                            continue
                        asset_id = self._new_id("asset")
                        record = self.store.put_path(
                            asset_id=asset_id,
                            source_path=full_path,
                            metadata={
                                "deal_id": approval.deal_id,
                                "approval_id": approval_id,
                                "job_id": job.job_id,
                                "mode": request.mode,
                                "pipeline_id": approval.pipeline_id,
                            },
                        )
                        job.captured_asset_ids.append(record.asset_id)
            else:
                job.status = JobStatus.FAILED

        self.jobs[job.job_id] = job
        return job

    def approve_training_use(
        self,
        deal_id: str,
        asset_ids: list[str],
        cohort_id: str,
        training_backend: str,
        intended_model: str,
        participant_ids: list[str],
    ) -> TrainingApproval:
        deal = self._require_deal(deal_id)
        if not asset_ids:
            raise ValueError("asset_ids cannot be empty")
        for asset_id in asset_ids:
            if self.store.get_record(asset_id) is None:
                raise ValueError(f"Unknown sealed asset: {asset_id}")

        approval = TrainingApproval(
            approval_id=self._new_id("train"),
            deal_id=deal_id,
            asset_ids=asset_ids,
            cohort_id=cohort_id,
            training_backend=training_backend,
            intended_model=intended_model,
            participant_ids=participant_ids,
        )
        self.training_approvals[approval.approval_id] = approval
        deal.stage = DealStage.TRAINING_APPROVED
        return approval

    def grant_inference_access(
        self,
        deal_id: str,
        cohort_id: str,
        participant_id: str,
        model_ref: str,
    ) -> InferenceGrant:
        deal = self._require_deal(deal_id)
        grant = InferenceGrant(
            grant_id=self._new_id("grant"),
            deal_id=deal_id,
            cohort_id=cohort_id,
            participant_id=participant_id,
            model_ref=model_ref,
        )
        self.inference_grants[grant.grant_id] = grant
        deal.stage = DealStage.INFERENCE_ACTIVE
        return grant

    def snapshot(self) -> dict:
        return {
            "controllers": [record.to_dict() for record in self.controllers.values()],
            "deals": [deal.to_dict() for deal in self.deals.values()],
            "raw_approvals": [approval.to_dict() for approval in self.raw_approvals.values()],
            "jobs": [job.to_dict() for job in self.jobs.values()],
            "sealed_assets": [record.to_dict() for record in self.store.list_records()],
            "training_approvals": [
                approval.to_dict() for approval in self.training_approvals.values()
            ],
            "inference_grants": [grant.to_dict() for grant in self.inference_grants.values()],
        }

    def _require_controller(self, controller_id: str) -> ControllerRecord:
        controller = self.controllers.get(controller_id)
        if controller is None:
            raise ValueError(f"Unknown controller: {controller_id}")
        return controller

    def _require_deal(self, deal_id: str) -> PropsDeal:
        deal = self.deals.get(deal_id)
        if deal is None:
            raise ValueError(f"Unknown deal: {deal_id}")
        return deal

    def _require_raw_approval(self, approval_id: str) -> RawScrapeApproval:
        approval = self.raw_approvals.get(approval_id)
        if approval is None:
            raise ValueError(f"Unknown raw scrape approval: {approval_id}")
        return approval

    @staticmethod
    def _new_id(prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex[:12]}"

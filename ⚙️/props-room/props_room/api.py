"""FastAPI surface for the Props Room stub."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .config import settings
from .control_plane import PropsControlPlane
from .crypto import TEEKeyPair
from .sealed_store import SealedBlobStore
from .tv_adapter import TVIngestionAdapter, TVRawScrapeRequest


store = SealedBlobStore(
    path=settings.resolved_data_dir,
    dstack_enabled=settings.dstack_enabled,
    key_hex=settings.seal_key_hex,
)
tv_adapter = TVIngestionAdapter(
    repo_root=settings.resolved_tv_repo_root,
    allow_subprocess=settings.allow_host_subprocess,
)
control_plane = PropsControlPlane(store=store, tv_adapter=tv_adapter)
tee_keys = TEEKeyPair()

app = FastAPI(title="Props Room", version="0.1.0")


class ControllerRequest(BaseModel):
    human_name: str
    source_kind: str
    policy_note: str = ""


class DealRequest(BaseModel):
    controller_id: str
    sponsor_id: str
    reserve_price: int
    budget_cap: int
    purpose: str
    allowed_outputs: list[str] = Field(default_factory=list)


class RawScrapeApprovalRequest(BaseModel):
    deal_id: str
    source_label: str
    source_locator: str
    pipeline_id: str
    allowed_jobs: list[str] = Field(default_factory=lambda: ["bible", "articles", "daily", "unstructured"])


class TVJobRequest(BaseModel):
    approval_id: str
    mode: str
    pilot: bool = False
    book: int | None = None
    publication_code: str | None = None
    docids: list[str] = Field(default_factory=list)
    library: bool = False
    library_category: str | None = None
    year: int | None = None
    start_date: str | None = None
    end_date: str | None = None
    run_name: str | None = None
    execute: bool = False
    capture_outputs: bool = False

    def to_internal(self) -> TVRawScrapeRequest:
        return TVRawScrapeRequest(
            mode=self.mode,
            pilot=self.pilot,
            book=self.book,
            publication_code=self.publication_code,
            docids=self.docids,
            library=self.library,
            library_category=self.library_category,
            year=self.year,
            start_date=self.start_date,
            end_date=self.end_date,
            run_name=self.run_name,
        )


class TrainingApprovalRequest(BaseModel):
    deal_id: str
    asset_ids: list[str]
    cohort_id: str
    training_backend: str
    intended_model: str
    participant_ids: list[str] = Field(default_factory=list)


class InferenceGrantRequest(BaseModel):
    deal_id: str
    cohort_id: str
    participant_id: str
    model_ref: str


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "data_dir": str(settings.resolved_data_dir),
        "tv_repo_root": str(settings.resolved_tv_repo_root),
        "dstack_enabled": settings.dstack_enabled,
        "allow_host_subprocess": settings.allow_host_subprocess,
    }


@app.get("/attestation")
async def attestation() -> dict:
    quote = None
    note = "not running in TEE"

    if settings.dstack_enabled:
        try:
            from dstack_sdk import DstackClient

            quote_value = DstackClient().get_quote()
            quote = quote_value.hex() if isinstance(quote_value, bytes) else str(quote_value)
            note = "quote returned by dstack"
        except Exception as exc:
            note = f"attestation unavailable: {exc}"

    return {
        "public_key_hex": tee_keys.public_key_bytes.hex(),
        "quote": quote,
        "note": note,
    }


@app.post("/controllers")
async def create_controller(req: ControllerRequest) -> dict:
    record = control_plane.register_controller(
        human_name=req.human_name,
        source_kind=req.source_kind,
        policy_note=req.policy_note,
    )
    return record.to_dict()


@app.post("/deals")
async def create_deal(req: DealRequest) -> dict:
    try:
        deal = control_plane.open_deal(
            controller_id=req.controller_id,
            sponsor_id=req.sponsor_id,
            reserve_price=req.reserve_price,
            budget_cap=req.budget_cap,
            purpose=req.purpose,
            allowed_outputs=req.allowed_outputs,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return deal.to_dict()


@app.post("/approvals/raw-scrape")
async def approve_raw_scrape(req: RawScrapeApprovalRequest) -> dict:
    try:
        approval = control_plane.approve_raw_scrape(
            deal_id=req.deal_id,
            source_label=req.source_label,
            source_locator=req.source_locator,
            pipeline_id=req.pipeline_id,
            allowed_jobs=req.allowed_jobs,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return approval.to_dict()


@app.post("/tv/jobs")
async def create_tv_job(req: TVJobRequest) -> dict:
    try:
        job = control_plane.submit_tv_job(
            approval_id=req.approval_id,
            request=req.to_internal(),
            execute=req.execute,
            capture_outputs=req.capture_outputs,
        )
    except (PermissionError, RuntimeError) as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return job.to_dict()


@app.get("/assets")
async def list_assets() -> dict:
    return {"assets": [record.to_dict() for record in store.list_records()]}


@app.post("/training/approvals")
async def approve_training(req: TrainingApprovalRequest) -> dict:
    try:
        approval = control_plane.approve_training_use(
            deal_id=req.deal_id,
            asset_ids=req.asset_ids,
            cohort_id=req.cohort_id,
            training_backend=req.training_backend,
            intended_model=req.intended_model,
            participant_ids=req.participant_ids,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return approval.to_dict()


@app.post("/inference/grants")
async def create_inference_grant(req: InferenceGrantRequest) -> dict:
    try:
        grant = control_plane.grant_inference_access(
            deal_id=req.deal_id,
            cohort_id=req.cohort_id,
            participant_id=req.participant_id,
            model_ref=req.model_ref,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return grant.to_dict()


@app.get("/snapshot")
async def snapshot() -> dict:
    return control_plane.snapshot()

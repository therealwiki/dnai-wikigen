"""WhatsApp Delegate — FastAPI endpoints.

Flow:
  1. POST /login/qr          — navigate to WhatsApp Web, get QR code for scanning
  2. GET  /login/qr          — get fresh QR code PNG (rotates every ~20s)
  3. POST /login             — fallback: enter phone number, get linking code
  4. GET  /login/status      — poll: has the phone linked yet?
  5. POST /login/wait        — blocking: wait up to N seconds for link
  6. POST /export            — scrape chats and seal them encrypted at rest
  7. GET  /status            — check whether sealed data exists
  8. POST /pipeline/approve  — owner approves a pipeline digest
  9. POST /pipeline/revoke   — owner revokes a pipeline
  10. GET  /pipeline/list    — list approved pipelines
  11. POST /pipeline/query   — approved pipeline queries bounded data
  12. DELETE /data           — owner destroys sealed data
  13. GET  /attestation      — TDX attestation quote (TEE only)
  14. GET  /health           — liveness
  15. GET  /screenshot       — debug screenshot of the browser
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

from .automation import (
    check_login_status,
    export_chats,
    get_qr_code,
    login_phone,
    login_qr,
    take_screenshot,
    wait_for_login,
)
from .config import settings
from .pipeline_gate import PipelineGate
from .sealed_store import SealedStore

# ─── Bootstrap ──────────────────────────────────────────────────────────

store = SealedStore(
    path=settings.data_dir,
    dstack_enabled=settings.dstack_enabled,
    key_hex=settings.seal_key_hex,
)
gate = PipelineGate(store)

# Pre-load approved pipelines from env (comma-separated digests)
if settings.approved_pipelines:
    for digest in settings.approved_pipelines.split(","):
        digest = digest.strip()
        if digest:
            gate.approve_pipeline(digest, description="pre-approved via env")

app = FastAPI(title="WhatsApp Delegate", version="0.1.0")

# ─── Request / Response models ──────────────────────────────────────────


class LoginRequest(BaseModel):
    phone_number: str  # e.g. "+15551234567"


class WaitRequest(BaseModel):
    timeout_seconds: int = 120


class ExportRequest(BaseModel):
    max_chats: int = 50


class ApproveRequest(BaseModel):
    image_digest: str  # sha256:...
    description: str = ""
    allowed_outputs: list[str] | None = None


class RevokeRequest(BaseModel):
    image_digest: str


class PipelineQueryRequest(BaseModel):
    pipeline_digest: str
    query_type: str  # aggregate_counts, activity_timeline, contact_summary, etc.
    params: dict | None = None


# ─── Health / status ────────────────────────────────────────────────────


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "cdp_url": settings.cdp_url,
        "dstack": settings.dstack_enabled,
    }


@app.get("/status")
async def status():
    return {
        "sealed_data_exists": store.exists(),
        "approved_pipelines": len(gate.list_approvals()),
    }


# ─── WhatsApp login flow ───────────────────────────────────────────────


@app.post("/login/qr")
async def api_login_qr():
    """Primary: Navigate to WhatsApp Web and get QR code for scanning.

    User scans QR with phone: WhatsApp → Linked Devices → Link device → camera.
    """
    result = await login_qr()
    if result["status"] == "error":
        raise HTTPException(status_code=400, detail=result["detail"])
    return result


@app.get("/login/qr")
async def api_get_qr():
    """Get fresh QR code as PNG image (WhatsApp rotates every ~20s)."""
    png = await get_qr_code()
    if png is None:
        raise HTTPException(status_code=404, detail="No QR code available — call POST /login/qr first")
    return Response(content=png, media_type="image/png")


@app.post("/login")
async def api_login(req: LoginRequest):
    """Fallback: Enter phone number, get 8-char linking code.

    Use POST /login/qr instead for the primary QR scan method.
    """
    result = await login_phone(req.phone_number)
    if result["status"] == "error":
        raise HTTPException(status_code=400, detail=result["detail"])
    return result


@app.get("/login/status")
async def api_login_status():
    """Check if the phone has linked (non-blocking poll)."""
    result = await check_login_status()
    return result


@app.post("/login/wait")
async def api_login_wait(req: WaitRequest):
    """Block until the phone links or timeout (default 120s)."""
    result = await wait_for_login(timeout_seconds=req.timeout_seconds)
    if result["status"] == "error":
        raise HTTPException(status_code=400, detail=result["detail"])
    if result["status"] == "timeout":
        raise HTTPException(status_code=408, detail=result["detail"])
    return result


@app.post("/export")
async def api_export(req: ExportRequest):
    """Step 3: Scrape chats from the logged-in session and seal them."""
    try:
        export = await export_chats(max_chats=req.max_chats)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))

    store.seal(export)

    return {
        "status": "sealed",
        "total_messages": export.total_messages,
        "total_chats": len(export.chats),
        "phone": export.phone,
    }


# ─── Pipeline management (owner operations) ────────────────────────────


@app.post("/pipeline/approve")
async def api_approve(req: ApproveRequest):
    """Owner approves a pipeline docker image digest for data access."""
    approval = gate.approve_pipeline(
        image_digest=req.image_digest,
        description=req.description,
        allowed_outputs=req.allowed_outputs,
    )
    return {
        "status": "approved",
        "image_digest": approval.image_digest,
        "allowed_outputs": approval.allowed_outputs,
    }


@app.post("/pipeline/revoke")
async def api_revoke(req: RevokeRequest):
    """Owner revokes a pipeline's access."""
    revoked = gate.revoke_pipeline(req.image_digest)
    if not revoked:
        raise HTTPException(status_code=404, detail="Pipeline not found in approved list")
    return {"status": "revoked", "image_digest": req.image_digest}


@app.get("/pipeline/list")
async def api_list_pipelines():
    """List all approved pipelines."""
    return {
        "pipelines": [
            {
                "image_digest": a.image_digest,
                "description": a.description,
                "allowed_outputs": a.allowed_outputs,
                "approved_at": a.approved_at,
            }
            for a in gate.list_approvals()
        ]
    }


# ─── Pipeline queries (bounded output) ─────────────────────────────────


@app.post("/pipeline/query")
async def api_pipeline_query(req: PipelineQueryRequest):
    """Approved pipeline queries sealed data — output is always bounded."""
    try:
        result = gate.query(
            pipeline_digest=req.pipeline_digest,
            query_type=req.query_type,
            params=req.params,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "pipeline_digest": result.pipeline_digest,
        "query": result.query,
        "result": result.result,
        "output_tokens": result.output_tokens,
        "bounded": result.bounded,
    }


# ─── Data destruction ──────────────────────────────────────────────────


@app.delete("/data")
async def api_delete_data():
    """Owner permanently destroys sealed data."""
    if not store.exists():
        raise HTTPException(status_code=404, detail="No sealed data to delete")
    store.delete()
    return {"status": "destroyed"}


# ─── Debug / TEE ────────────────────────────────────────────────────────


@app.get("/screenshot")
async def api_screenshot():
    """Debug: take a screenshot of the current browser state."""
    path = await take_screenshot()
    return FileResponse(path, media_type="image/png", filename="whatsapp.png")


@app.get("/attestation")
async def api_attestation():
    """Return TDX attestation quote (only meaningful in TEE)."""
    if not settings.dstack_enabled:
        return {"attestation": None, "note": "not running in TEE"}

    try:
        from dstack_sdk import DstackClient

        client = DstackClient()
        quote = client.get_quote()
        return {"attestation": quote.hex() if isinstance(quote, bytes) else str(quote)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attestation failed: {e}")

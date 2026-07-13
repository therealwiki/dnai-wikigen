"""Pipeline gate — owner-approved access to sealed WhatsApp data.

The sealed message data NEVER leaves the TEE raw. Instead:
  1. Data owner registers approved pipeline image digests
  2. A pipeline requests access by presenting its attestation (docker digest)
  3. The gate verifies the digest is in the approved set
  4. The pipeline receives a read-only handle with bounded output enforcement

Bounded outputs:
  - Aggregate counts (total messages, per-contact counts)
  - Sentiment scores (positive/negative/neutral bands)
  - Topic clusters (category labels, no raw text)
  - Time-series activity (messages per hour/day, no content)
  - Custom query results capped at MAX_OUTPUT_TOKENS

Raw message text NEVER appears in pipeline outputs.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum

from .sealed_store import SealedStore, WhatsAppExport


MAX_OUTPUT_TOKENS = 4096  # ~3K words — hard cap on any pipeline output


class OutputBand(str, Enum):
    """Coarse output bands to prevent exact data reconstruction."""

    NONE = "none"
    LOW = "low"          # 1-100 messages
    MEDIUM = "medium"    # 101-1000
    HIGH = "high"        # 1001-10000
    VERY_HIGH = "very_high"  # 10001+


def _message_count_band(count: int) -> OutputBand:
    if count == 0:
        return OutputBand.NONE
    elif count <= 100:
        return OutputBand.LOW
    elif count <= 1000:
        return OutputBand.MEDIUM
    elif count <= 10000:
        return OutputBand.HIGH
    else:
        return OutputBand.VERY_HIGH


@dataclass
class PipelineApproval:
    """Record of an owner-approved pipeline."""

    image_digest: str  # sha256:...
    description: str
    approved_at: float = field(default_factory=time.time)
    # What the pipeline is allowed to produce
    allowed_outputs: list[str] = field(default_factory=lambda: [
        "aggregate_counts",
        "activity_timeline",
        "contact_summary",
    ])


@dataclass
class BoundedResult:
    """A pipeline output that has been bounded / coarsened."""

    pipeline_digest: str
    query: str
    result: dict
    output_tokens: int
    bounded: bool = True  # always true — raw data never passes


class PipelineGate:
    """Controls access to sealed WhatsApp data.

    Only approved pipelines (identified by docker image digest) can
    request data access. All outputs are bounded.
    """

    def __init__(self, store: SealedStore):
        self._store = store
        self._approvals: dict[str, PipelineApproval] = {}

    # --- Owner operations ---

    def approve_pipeline(
        self,
        image_digest: str,
        description: str,
        allowed_outputs: list[str] | None = None,
    ) -> PipelineApproval:
        """Owner approves a pipeline image digest for data access."""
        approval = PipelineApproval(
            image_digest=image_digest,
            description=description,
            allowed_outputs=allowed_outputs or [
                "aggregate_counts",
                "activity_timeline",
                "contact_summary",
            ],
        )
        self._approvals[image_digest] = approval
        print(f"[pipeline_gate] approved pipeline {image_digest[:16]}... — {description}")
        return approval

    def revoke_pipeline(self, image_digest: str) -> bool:
        """Owner revokes a pipeline's access."""
        if image_digest in self._approvals:
            del self._approvals[image_digest]
            print(f"[pipeline_gate] revoked pipeline {image_digest[:16]}...")
            return True
        return False

    def list_approvals(self) -> list[PipelineApproval]:
        return list(self._approvals.values())

    # --- Pipeline operations (requires valid digest) ---

    def query(
        self,
        pipeline_digest: str,
        query_type: str,
        params: dict | None = None,
    ) -> BoundedResult:
        """Execute a bounded query against the sealed data.

        Args:
            pipeline_digest: The requesting pipeline's docker image digest
            query_type: One of the allowed output types
            params: Optional query parameters

        Returns:
            BoundedResult with coarsened output

        Raises:
            PermissionError: If pipeline not approved or query type not allowed
        """
        approval = self._approvals.get(pipeline_digest)
        if approval is None:
            raise PermissionError(
                f"Pipeline {pipeline_digest[:16]}... not approved by data owner"
            )

        if query_type not in approval.allowed_outputs:
            raise PermissionError(
                f"Query type '{query_type}' not in approved outputs: {approval.allowed_outputs}"
            )

        export = self._store.unseal()
        if export is None:
            return BoundedResult(
                pipeline_digest=pipeline_digest,
                query=query_type,
                result={"error": "no data available"},
                output_tokens=0,
            )

        # Dispatch to bounded query handlers
        handlers = {
            "aggregate_counts": self._aggregate_counts,
            "activity_timeline": self._activity_timeline,
            "contact_summary": self._contact_summary,
            "sentiment_bands": self._sentiment_bands,
            "topic_clusters": self._topic_clusters,
        }

        handler = handlers.get(query_type)
        if handler is None:
            raise ValueError(f"Unknown query type: {query_type}")

        result = handler(export, params or {})

        # Enforce output size cap
        result_json = json.dumps(result)
        output_tokens = len(result_json)  # Rough char-based estimate
        if output_tokens > MAX_OUTPUT_TOKENS:
            result = {"error": "output exceeds size cap", "cap": MAX_OUTPUT_TOKENS}
            output_tokens = len(json.dumps(result))

        return BoundedResult(
            pipeline_digest=pipeline_digest,
            query=query_type,
            result=result,
            output_tokens=output_tokens,
        )

    # --- Bounded query handlers ---

    @staticmethod
    def _aggregate_counts(export: WhatsAppExport, params: dict) -> dict:
        """Aggregate message counts — no raw text."""
        total = export.total_messages
        chat_count = len(export.chats)
        per_chat = [
            {
                "contact": c["name"],
                "message_band": _message_count_band(len(c.get("messages", []))).value,
            }
            for c in export.chats
        ]
        return {
            "total_message_band": _message_count_band(total).value,
            "chat_count": chat_count,
            "per_chat": per_chat,
        }

    @staticmethod
    def _activity_timeline(export: WhatsAppExport, params: dict) -> dict:
        """Messages per day/hour — no content, just counts.

        Returns hourly buckets (0-23) with message counts.
        """
        hourly: dict[str, int] = {}
        for chat in export.chats:
            for msg in chat.get("messages", []):
                ts = msg.get("timestamp", "")
                # WhatsApp timestamps are like "10:32 AM" or "22:15"
                # We only bucket by the hour portion
                hour = ts.split(":")[0].strip() if ":" in ts else "unknown"
                hourly[hour] = hourly.get(hour, 0) + 1

        return {"hourly_distribution": hourly}

    @staticmethod
    def _contact_summary(export: WhatsAppExport, params: dict) -> dict:
        """Per-contact summary — name + activity band, no messages."""
        contacts = []
        for chat in export.chats:
            msg_count = len(chat.get("messages", []))
            contacts.append({
                "name": chat["name"],
                "activity_band": _message_count_band(msg_count).value,
            })
        return {"contacts": contacts}

    @staticmethod
    def _sentiment_bands(export: WhatsAppExport, params: dict) -> dict:
        """Coarse sentiment distribution — requires an external model.

        This is a placeholder. In production, the approved pipeline would
        run its own sentiment model inside the TEE and return only bands.
        """
        # Placeholder: count messages by length as a proxy
        short = medium = long = 0
        for chat in export.chats:
            for msg in chat.get("messages", []):
                text = msg.get("text", "")
                if len(text) < 20:
                    short += 1
                elif len(text) < 100:
                    medium += 1
                else:
                    long += 1
        return {
            "note": "placeholder — real sentiment requires approved ML model",
            "short_messages": short,
            "medium_messages": medium,
            "long_messages": long,
        }

    @staticmethod
    def _topic_clusters(export: WhatsAppExport, params: dict) -> dict:
        """Topic labels only — no raw text excerpts.

        Placeholder: in production, an approved NLP pipeline runs
        topic modeling inside the TEE and returns only cluster labels.
        """
        return {
            "note": "placeholder — real topic modeling requires approved ML pipeline",
            "total_chats": len(export.chats),
            "total_messages_band": _message_count_band(export.total_messages).value,
        }

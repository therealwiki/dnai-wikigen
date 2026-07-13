# Props Room

`props-room` is the missing middle layer between the existing NDAI diligence room
and the `tv` corpus builder.

It is not another scrape demo and not another training demo. The job of this
service is to hold private source access inside a TEE, run raw acquisition jobs,
seal the resulting artifacts, and record the approvals required before anything
downstream happens.

## Why this exists

The repo already has the pieces in isolation:

- `⚙️/whatsapp-delegate`: browser-mediated private data acquisition + sealed storage
- `⚙️/tinker-delegate`: NDAI-style deal lifecycle + bounded outputs + Tinker session wrapper
- `🔬/tv`: raw scrape -> aligned corpus -> clean -> train pipeline for TVL/EN

`props-room` combines those ideas into one control plane:

1. A controller registers a private source.
2. A sponsor opens an NDAI-style access deal with reserve price and budget cap.
3. The controller approves a raw scrape scope.
4. A TEE job runs the raw scrape task.
5. Raw outputs are sealed at rest with a key derived inside the enclave.
6. Later approvals unlock cleaning, cohort training, and participant inference.

## Scope of this first stub

This first pass focuses on the earliest slice:

- NDAI metadata for deals
- controller approval records
- a generic sealed blob store
- a `tv` raw scrape adapter for the current corpus repo
- stub records for training approvals and inference grants

It does not yet include:

- real wallet / identity auth
- chain watcher integration
- attestation verification of downstream pipelines
- direct integration with the Thinking Machines runtime
- a WhatsApp source adapter

## Current architecture

```
controller -> props-room API -> NDAI deal + scrape approval
                               -> tv raw scrape command plan
                               -> sealed asset store
                               -> future training / inference approvals
```

Core modules:

- `props_room/sealed_store.py`
  Encrypts files, directories, or JSON manifests with AES-256-GCM.
- `props_room/tv_adapter.py`
  Builds and optionally executes `uv run python scripts/...` commands inside
  the `🔬/tv` repo for raw collection tasks.
- `props_room/control_plane.py`
  Holds the source-controller, deal, approval, ingestion-job, training, and
  inference records.
- `props_room/api.py`
  Thin FastAPI surface around the control plane.

## API sketch

The current stub exposes:

- `GET /health`
- `GET /attestation`
- `POST /controllers`
- `POST /deals`
- `POST /approvals/raw-scrape`
- `POST /tv/jobs`
- `GET /assets`
- `POST /training/approvals`
- `POST /inference/grants`
- `GET /snapshot`

## TV raw scrape modes

The `tv` adapter currently plans or executes these raw-ingest tasks:

- `bible`
- `articles`
- `daily`
- `unstructured`

Examples:

```bash
# Plan a Bible pilot scrape
curl -X POST http://localhost:8300/tv/jobs \
  -H 'Content-Type: application/json' \
  -d '{
    "approval_id": "approval_123",
    "mode": "bible",
    "pilot": true,
    "execute": false
  }'

# Execute an article scrape and seal the expected outputs
curl -X POST http://localhost:8300/tv/jobs \
  -H 'Content-Type: application/json' \
  -d '{
    "approval_id": "approval_123",
    "mode": "articles",
    "publication_code": "lv",
    "execute": true,
    "capture_outputs": true
  }'
```

## Local dev

```bash
cd "⚙️/props-room"
uv run python -m props_room.main serve --port 8300
```

Key env vars:

- `PROPS_ROOM_DATA_DIR=/data`
- `PROPS_ROOM_TV_REPO_ROOT=/workspace/tv`
- `PROPS_ROOM_ALLOW_HOST_SUBPROCESS=true`
- `PROPS_ROOM_DSTACK_ENABLED=true`

## Relationship to the future product

The intended production flow is:

1. Source controller delegates access to a private source inside a TEE.
2. Raw data is acquired and sealed.
3. NDAI-style economic negotiation gates downstream use.
4. Props-style source authenticity and controller approval gate transforms.
5. Encumbered training jobs produce cohort-approved model updates.
6. Contributors receive inference rights on the resulting model.

This folder starts at step 1 and gives the repo a concrete place to keep step 2
through step 4 logic.

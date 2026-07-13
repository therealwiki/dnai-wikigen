# TVL Props Data Room

## One-line idea

Build a TEE-protected data room for low-resource Tuvaluan language data where
private source access, economic negotiation, training approval, and participant
inference rights are all part of the same product.

## The problem

Tuvaluan is low-resource. The highest-value data is not only public text from
sites like JW.org and WOL. It is also private or semi-private conversational
data, community language use, and participant-owned artifacts that are too
sensitive to release into an ordinary scraping or model-training pipeline.

That creates two linked problems:

1. The people who control the data need strong guarantees before they let
   anyone touch it.
2. The people funding collection or training need a way to pay for access
   without forcing irreversible disclosure first.

NDAI solves the economic problem. Props solves the data pipeline problem.

## Why NDAI and Props fit together

NDAI is the negotiation layer.

- A sponsor posts a budget cap.
- A data controller or cohort has a reserve price.
- The TEE produces bounded outputs instead of raw disclosure.
- On-chain settlement decides whether the next step is funded.

Props is the authenticated private-data layer.

- Data is acquired from a real source inside a protected execution boundary.
- The controller approves which transform or downstream use is allowed.
- Derived outputs can be trusted as having come from the approved source path.
- Sensitive raw inputs do not need to leave the TEE.

Put together:

- NDAI decides whether a raw scrape, cleaning step, or training step is worth
  paying for.
- Props ensures that the approved step runs on authenticated source data under
  the controller's policy.

## Product thesis

The product is not "sell a dataset dump."

The product is:

1. A controller delegates source access to a TEE.
2. The TEE acquires and seals raw data.
3. A sponsor negotiates for specific downstream rights.
4. The controller approves only those rights.
5. Training runs inside an encumbered model runtime.
6. Contributors receive rights to inference on the resulting model.

This keeps the control point on the use of the data, not just possession of it.

## Concrete Tuvaluan version

### Phase 1: Raw source access

The first implementation slice should be the raw scrape task only.

Examples:

- WhatsApp Web message export for a participant who explicitly consents
- WOL / JW scraping for public TVL/EN text
- scanned dictionaries or newsletters processed through OCR

The scrape job runs inside a TEE CVM. The raw output is immediately sealed with
a key derived inside the enclave. The raw artifact is never exposed as a normal
filesystem export outside the trusted boundary.

### Phase 2: Approved transforms

After raw acquisition, the controller should approve specific transforms:

- alignment
- cleaning
- glossary extraction
- cohort inclusion checks
- quality scoring

Each transform is a distinct approved pipeline, not an implied right that comes
for free after the scrape.

### Phase 3: Cohort training

Once multiple participants opt into a cohort, the product can authorize a
training run for a TVL <-> EN translation model.

Important constraint:

- the model runtime is still encumbered
- training happens in a controlled environment
- outputs are governed by the same approval model

This is where the Thinking Machines system fits: it is the execution substrate
for the approved training job, not the place where raw participant data becomes
generally accessible.

### Phase 4: Participant inference rights

People who contributed to the training set should not only be paid once. They
should also be able to exercise rights on the trained model.

Examples:

- run inference on the translation model
- receive discounted or metered usage
- hold a revocable entitlement tied to cohort membership

That makes the product a data cooperative with cryptographic enforcement, not
just a one-time dataset sale.

## System model

### Actors

- Controller: the person or organization that can authorize source access
- Sponsor: the party paying for collection, cleaning, or training rights
- Pipeline operator: the approved code path running inside the TEE
- Runtime provider: the encumbered model-training/inference backend
- Participant: a contributor who later receives model-use rights

### Core assets

- raw source artifact
- sealed derived dataset
- approval ledger
- cohort definition
- training checkpoint / adapter
- participant inference grant

### Core policies

- who may initiate raw scrape
- which source path is allowed
- which transform digests are approved
- whether a sealed dataset may join a cohort
- which training backend may consume the cohort
- who may run inference after training

## First implementation slice

The first slice should stay narrow:

1. Port the existing `tv` raw scrape entrypoints into a TEE control plane.
2. Treat the scrape output as sealed data at rest.
3. Model controller approval records for those scrape jobs.
4. Keep cleaning and training as later, separately approved stages.

This is enough to prove the architecture without pretending the entire product
is done.

## Mapping to the current repo

- `⚙️/whatsapp-delegate` contributes:
  - browser-mediated private data acquisition
  - sealed-at-rest storage
  - bounded-output mindset

- `⚙️/tinker-delegate` contributes:
  - NDAI deal lifecycle
  - bounded outputs
  - attested ingress pattern
  - session isolation and compute metering

- `🔬/tv` contributes:
  - raw scrape entrypoints
  - aligned corpus contract
  - downstream clean/train split

The new service should sit between them.

## What success looks like

A real controller can say:

"You may scrape this source inside the TEE, seal it, and use it only for this
approved TVL <-> EN training cohort. If the deal terms are met, approved
participants may later run inference on the resulting model."

That is the combined NDAI + Props product.

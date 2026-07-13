# Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments

## Paper Metadata
- **arXiv:** 2506.23706v1
- **Date:** June 30, 2025
- **Authors:** Christoph Schnabl, Daniel Hugenroth, Bill Marino, Alastair R. Beresford (Department of Computer Science and Technology, University of Cambridge)
- **Venue:** Proceedings of the 42nd International Conference on Machine Learning (ICML), Vancouver, Canada. PMLR 267, 2025.
- **Categories:** Artificial Intelligence (cs.AI)

---

## Abstract

Benchmarks are important measures to evaluate safety and compliance of AI models at scale. However, they typically do not offer verifiable results and lack confidentiality for model IP and benchmark datasets. The paper proposes **Attestable Audits**, which run inside Trusted Execution Environments (TEEs) and enable users to verify interaction with a compliant AI model. The work protects sensitive data **even when the model provider and auditor do not trust each other**. This addresses verification challenges raised in recent AI governance frameworks. The authors build a prototype demonstrating feasibility on typical audit benchmarks against Llama-3.1.

---

## 1. Problem: Verify Compliance Without Access

Audits are essential as models become more capable and potentially more dangerous, and several AI regulations (EU AI Act, US executive orders) mandate them. But current audits rely on contracts or manual processes, and verification remains hard because of **restricted model access and data-privacy concerns**. Misaligned incentives between stakeholders can produce audits that do not serve the public interest, including:

- **Data exfiltration** by involved actors (the auditor learning the model IP, or the provider learning the private benchmark).
- **Sandbagging** — models that intentionally underperform during evaluations.

The core question the paper answers: *how can users verify they are interacting with a compliant AI system when model providers do not share weights, auditors only share code and data with regulators, and everything runs on untrusted third-party infrastructure?*

---

## 2. Confidential Computing Background

Confidential Computing (CC) protects data **in transit, at rest, and in use** using TEEs — privileged, hardware-backed execution modes that encrypt all memory and prevent interference by the host/hypervisor, defending even against physical attacks. This makes CC attractive on untrusted cloud providers, *as long as the hardware vendor is trusted*.

Second-generation TEEs (AMD SEV-SNP, Intel TDX, AWS Nitro) support full VMs, overcoming the memory limits that made ML workloads infeasible on first-generation process-based TEEs (Intel SGX, Arm TrustZone). Beyond confidentiality, the work leans on TEE **integrity** guarantees, which can provide "zero-knowledge-proof-like" assurances.

**Remote Attestation (RA):** the secure chip signs a chain of measurements — Platform Configuration Registers (PCRs) — with a non-extractable key. PCRs cover the Trusted Computing Base (firmware + enclave base image), so a verifier can compare PCRs against known-good images and check the vendor signature. The prototype uses AWS Nitro Enclaves, but the protocol is compatible with Intel TDX and AMD SEV-SNP.

---

## 3. The Attestable Audit Design

A **three-step protocol**:

1. **Prepare (optional).** The provider quantizes their model `M` inside a confidential TEE, producing an attestation `A[M→Mq]` that binds the full model hash to the quantized hash. This lets a provider deploy the full `M` while convincing others that an audit of the smaller `Mq` is a valid approximation (some audit TEEs can only host the smaller model).
2. **Audit.** The auditor and provider each encrypt and upload — to a *fresh* TEE — the audit code `AC` + dataset `AD` and the model `Mq`. The TEE runs `AC` against `Mq` over `AD` inside a **sandbox**, producing a single **aggregated result `R`**, and publishes attestation `A[Mq, AC+AD → R]` binding the input hashes to `R` on a transparency log `L`.
3. **Inference.** A user sends an encrypted prompt to the audited model in a TEE and receives output `x` plus attestation `A[M, p→x, R]` proving the reply came from the audited model with score `R`. The user can later disclose `(p, x, A, R)` to a regulator to demonstrate audit deficits.

### 3.1 Security Goals (G1–G6)
- **G1 Model verifiability** — attestation includes hashes of model weights and code.
- **G2 Audit verifiability** — outputs are bound to an approved audit version.
- **G3 Confidentiality** — of model weights (IP) and audit data (prevents "cheating"/overfitting to the benchmark).
- **G4 Transparency** — base image, model, and audit digests are published with verifiable build steps (anyone can rebuild and inspect the exact eval environment, à la Apple's Private Cloud Compute).
- **G5 Statelessness** — each session runs in a fresh VM-enclave with zeroized RAM and no persistent storage, eliminating prompt residue and covert channels.
- **G6 Output verifiability** — model responses during interaction are authenticated.

### 3.2 Threat Model
- **A1 Network adversaries** — can intercept, tamper, or spoof between components (DoS excluded).
- **A2 Physical/privileged adversaries** — RAM snapshots, VM rollbacks, side-channel attacks.

### 3.3 Cryptographic Requirements
Three standard primitives (available in libraries like LIBSODIUM; prototype uses SHA + EC25519 + AES-GCM, with post-quantum alternatives possible):
- a **pre-image and collision-resistant hash** `HASH`;
- an **IND-CCA KEM** (`KEYGEN`/`ENCAPSULATE`/`DECAPSULATE`) to share a symmetric key;
- an **IND-CCA AEAD** scheme for authenticated encryption.

Plus TEE **attestation** `({d,...}, PCR, σ) ← ATTEST({d,...})`. Attestations are written `A[in→out]` binding `in = HASH(input)` to `out = HASH(output)`. Model code runs in a sandbox; where the model architecture is public, only the weights need to stay confidential and the code can live in the attested open-source base image.

---

## 4. Protocols (Appendix Algorithms 1–3)

- **PREPARE (Alg. 1):** TEE boots from a secure image, generates a fresh KEM keypair, attests to boot image + public key; provider encrypts `M` to that key; TEE decrypts, quantizes to `Mq`, hashes both, publishes `A[M→Mq]`, returns encrypted `Mq`.
- **ATTESTABLE AUDIT (Alg. 2):** TEE publishes an attestation with a KEM public key; provider uploads encrypted `Mq`, auditor uploads encrypted `AC+AD`; TEE creates a sandbox, executes `AC` against `Mq` over `AD`, gets aggregated `R`, publishes `R` and `A[Mq, AC+AD → R]`.
- **INFERENCE (Alg. 3):** TEE downloads the prior attestations and includes them in its own; provider loads `M`, TEE **aborts if `HASH(M)` ≠ the attested model hash**; user sends encrypted prompt `p`; TEE runs inference in a sandbox and returns `(x, A[M, p→x, R])` encrypted to the user.

The protocols omit real-world details like replay prevention and key rotation.

---

## 5. Evaluation

Rust implementation via bindings to `llama.cpp`, running **Llama-3.1-8B-Instruct quantized to 4-bit** on AWS Nitro Enclaves, over three representative AI-safety benchmarks: **MMLU** (discrete-label classification), **XSum** (summarization / text-similarity), and **ToxicChat** (classifier-judged toxicity). 500 prompts per benchmark.

**Feasibility:** the quantized enclave model gives adequate results — zero-shot MMLU 51.4% (57.4% excluding unparsable), vs. 54.6–58.9% non-quantized; summarization mean BERTScore ≈0.47 vs ≈0.58 non-quantized; toxicity 2.4% vs 2.6%. 4-bit quantization only slightly degrades performance.

**Trade-offs:** CPU inference costs **21.7× a GPU baseline** and runs ~100× slower; using enclaves costs ~2× (larger instance / fewer cores). Memory constraints force smaller/quantized models. A production build on CC-compatible GPUs (e.g. NVIDIA H100) is expected to cut overhead to as little as ~5×.

| Metric | (I) enclave | (II) compute-const | (III) cost-const | (IV) L40S GPU |
| --- | --- | --- | --- | --- |
| Price/hr ($) | 0.38 | 0.19 | 0.38 | 0.89 |
| Price/100k token ($) | 5.80 | 2.61 | 3.01 | 0.12 |
| Token/s | 1.84 | 2.04 | 3.54 | 202.00 |
| BERTScore | 0.47 | 0.50 | 0.49 | 0.58 |
| Toxicity rate (%) | 2.40 | 2.00 | 1.70 | 2.60 |
| Accuracy (%) | 51.40 | 52.60 | 48.60 | 58.90 |

**Security mapping:** G1/G2 from RA binding hashes of `Mq`, `AC`, `AD` to PCRs; G3 from end-to-end ephemeral-key AEAD; A1 defeated by the attestation-bound channel, A2 by VM isolation + full-memory encryption; G4 from publishing base image, build scripts, hashes, and attestations; G5 from fresh zeroized enclaves; G6 from the per-prompt attestation `A[M,p→x,R]`. **Residual gap:** prompt-based model exfiltration during the interaction step (Carlini et al., 2024).

---

## 6. Related Work

- **Hardware-attested integrity:** DeepAttest binds models/code to TEEs but lacks audit traceability; Nevo et al. protect weights only; OpenMined uses TEEs for eval but lacks generality/reproducibility. This work extends attestation to audit **datasets and code** in a transparent, regulator-facing pipeline.
- **Cryptographic private inference:** zkML (SNARKs) is orders of magnitude slower; FHE-LoRA uses homomorphic encryption; SONNI / Proof-of-Training focus on weight/data lineage. This work instead verifies **runtime behavior**.
- **Audit frameworks & governance:** Audit Cards, layered taxonomies, fairwashing risks — mostly without cryptographic guarantees; this work provides **pre-deployment** guarantees.

---

## 7. Discussion & Limitations

- High runtime/cost overhead, dominated by CPU inference (CC-GPU expected to reduce this).
- Requires trusting the **hardware vendor** (AWS here). Running independently on **multiple** CC technologies lets parties pick which attestation to trust — this raises integrity (trust-any) but *lowers* confidentiality, since a single broken TEE can leak the sensitive data.
- Prototype needs a quantized model due to memory limits; CC-GPU could run native Llama-3.
- Generalizes beyond LLMs (e.g. a self-driving-car operator proving in court that the audited model was the one driving), and gives reproducibility for scientific benchmarking.

**Thesis:** by shifting AI governance from *ex post* enforcement to *ex ante* certifiable deployment, Attestable Audits reduce the compliance and transaction costs of governing AI systems, without exposing private model weights or proprietary data.

---

## Relevance to dnai-wikigen

This is the closest published analogue to the project's verification chain. It is the "trust the mechanism, not the data" pattern in full:

- **Data + code commitment.** The attestation `A[Mq, AC+AD → R]` binds *input hashes* (model, audit code, dataset) to an *aggregated result* — exactly the missing piece that upgrades our `git SHA → docker digest → compose hash → TDX quote` chain into a proof that a specific reward function ran over a specifically committed dataset. Their `AC`+`AD` map onto our reward code + sealed reward data; their `R` maps onto our bounded reward band.
- **Mutual distrust.** Confidentiality holds even when provider and auditor distrust each other — the seller/buyer adversarial case in the diligence room.
- **Aggregated, bounded output.** `AC` emits a *single aggregated result `R`*, not per-record scores — the same bounded-egress discipline as `denoising_core.band_to_scalar`.
- **Statelessness (G5)** and the **sandbox** are the mitigations for the candidate-as-exfiltrator threat named in `docs/BIO_VALIDATION.md`.
- **Named residual gaps we must state plainly:** trusted hardware root (mitigate via multi-vendor attestation, with the confidentiality/integrity trade-off they flag) and prompt/candidate-based exfiltration through the interaction channel.

See also `📄/dstack/paper.md` (the TEE substrate) and `📄/ladder/paper.md` (bounding adaptive-query overfitting on the sealed holdout).

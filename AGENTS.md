# dnai-wikigen

Attested Diligence Room implementing the NDAI paper (arXiv:2502.07924). Seller uploads private artifact to TEE, buyer's evaluator agent inspects it inside the boundary, bounded outputs only.

## Skills — Use These Instead of Raw Commands
- `/forge-init` — scaffold new Foundry project or Solidity contracts for Base/Base Sepolia
- `/forge-build` — compile Solidity contracts, inspect ABIs, check sizes
- `/forge-test` — run unit tests, fuzz tests, invariant tests, gas reports, coverage
- `/forge-deploy` — deploy contracts to Base Sepolia or mainnet (ALWAYS use `--account dev`, never raw private keys)
- `/forge-verify` — verify deployed contracts on BaseScan
- `/cast-wallet` — generate keypairs, import to encrypted keystore, list accounts
- `/cast-interact` — call contract functions, send transactions, check balances, decode data
- `/anvil-local` — start local dev chain, fork Base Sepolia/mainnet for testing
- `/phala-auth` — login to Phala Cloud, check auth status, switch profiles
- `/phala-deploy` — deploy docker-compose apps as Confidential VMs (CVMs) on Phala Cloud TEE
- `/phala-access` — SSH into CVMs, stream logs, copy files to/from CVMs
- `/phala-cvms` — list, start, stop, restart, resize, delete CVMs, get attestation quotes
- `/phala-simulator` — run local TEE simulator for dev/test without deploying to cloud

IMPORTANT: Always prefer the skill over manual commands. The skills contain detailed workflows, flags, and safety checks.

## Env Vars Required Per Workflow
Populate `.env` from `example.env` before starting. Key groups:
- **Foundry/contracts**: `ETHERSCAN_API_KEY`, `BASE_SEPOLIA_RPC_URL`, `FOUNDRY_KEYSTORE_ACCOUNT=dev`
- **Phala/TEE**: `PHALA_CLOUD_API_KEY` (prefixed `phak_`)
- **LLM (evaluator agent)**: `OPENROUTER_API_KEY`
- **Docker registry**: `DOCKER_REGISTRY_USERNAME`, `DOCKER_IMAGE`, `GITHUB_TOKEN`
- **App services**: `PORT=3000`, `AGENT_PORT=3001`, `JUDGE_PORT=3003`
- **After deployment**: update `ESCROW_ADDRESS`, `JUDGE_ADDRESS`, `PHALA_CVM_ID`
- **TEE dev mode**: `DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090`

## Boundaries
- NEVER use React — always use SolidJS for frontend UI
- NEVER use pip or poetry — always `uv` with `pyproject.toml`
- NEVER modify anything in `📄/` or `🔬/` — read-only research papers and reference submodules
- NEVER commit `.env` or secrets — only `example.env` is tracked
- NEVER use `--private-key` flag or raw keys — use Foundry keystore via `/cast-wallet` then `--account dev`
- NEVER self-host TEE infrastructure — use `/phala-deploy` to Phala Cloud
- NEVER expose raw artifact content outside the TEE — agent outputs must be bounded (score bands, yes/no, offer within cap)

## Architecture
- Escrow contract state machine: Created → Evaluated → Accepted/Rejected/Expired
- Evaluator agent runs INSIDE the dstack CVM (Phala Cloud Intel TDX), not outside
- Reserve price (seller) and budget cap (buyer) are first-class UI controls
- Verification chain: git SHA → docker digest → compose hash → TDX quote
- Docker images for TEE MUST use reproducible builds (pin base image by digest, normalize timestamps)
- TEE attestation SDK: JS `@phala/dstack-sdk`, Python `dstack-sdk` — use `/phala-simulator` for local dev

## Gotchas
- Emoji dir names need quoting in shell: `cd "📄/"` or `ls "🔬/amiller/"`
- Andrew Miller's submodules are branch-heavy — check specific branches per `🔬/README.md`
- `.env` starts empty — copy from `example.env` and fill in secrets
- Skills are mirrored in `.claude/skills/` and `.codex/skills/` — keep in sync when editing
- `🔬/amiller/skill-verifier` is closest reference to what we're building (inspection certificates + escrow)
- Local TEE dev: start simulator with `/phala-simulator` before running docker-compose locally
- Contract interactions: use `/cast-interact` with RPC URLs from `.env`, don't hardcode URLs

## When Blocked
- Need a wallet: `/cast-wallet` → generate → import to keystore → use `--account dev`
- Contract won't compile: `/forge-build` for detailed errors
- Deploy failing: check `.env` has `BASE_SEPOLIA_RPC_URL` and `ETHERSCAN_API_KEY`; use `/forge-deploy`
- TEE deploy failing: `/phala-auth` to verify login, then `/phala-cvms` to check CVM status
- Need to debug running CVM: `/phala-access` for SSH and logs
- Empty submodule dir: `git submodule update --init --recursive`
- Docker build not reproducible: pin base image by digest, not tag — see `🔬/amiller/devproof-apps-guide`
- Unsure about paper concepts: read `📄/ndai/paper.md` — focus on secure threshold and agent error sections

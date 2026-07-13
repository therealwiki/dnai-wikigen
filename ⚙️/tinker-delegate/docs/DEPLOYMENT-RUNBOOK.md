# Deployment Runbook

Last updated: 2026-07-08

This file records Base Sepolia and Phala deployment evidence for the tinker
delegate stack. It is a runbook, not a trust source by itself. The
machine-readable deployment ledger is:

```text
deployments/base-sepolia.json
```

The previous Base Sepolia contracts below still have bytecode, but they are now
classified as **legacy deployed code** for this branch because the current
operator deployer is:

```text
0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD
```

and the historical contracts are not controlled by that deployer. Fresh
current-operator deployments should be broadcast with:

```bash
cd "⚙️/tinker-delegate/contracts"
./scripts/deploy-base-sepolia.sh
```

The helper uses Foundry `--account "$FOUNDRY_KEYSTORE_ACCOUNT"` and therefore
prompts for the encrypted keystore password. It does not use or require a raw
private key.

## Base Sepolia

### Historical DiligenceRoom

- Contract: `DiligenceRoom`
- Address: `0xe51A3C5fd564c625C9D72D2283878Ab4296b3844`
- Network: Base Sepolia (`chainId = 84532`)
- BaseScan: `https://sepolia.basescan.org/address/0xe51A3C5fd564c625C9D72D2283878Ab4296b3844`
- Deployment tx: `0x9407f7989c11ac1161397c85aa41bf3752ebca8124e5ecb7fafe05c6dbd899e4`
- Deployment block: `38837040`
- Deployer / developer fee recipient: `0x111dB654eCD8756188e03746C1bcff74FD749791`
- Current-operator controlled: no
- Compiler: `solc 0.8.28`
- Optimizer runs: `200`
- Verification: passed on BaseScan
- Current on-chain `dealCount()`: `0`

#### Security changes made before deployment

The original escrow contract was not safe enough to deploy unchanged. The deployed version includes these hardening changes:

1. Settlement now uses pull payments.
   - `acceptDeal`, `rejectDeal`, and `expireDeal` credit balances into `pendingWithdrawals`.
   - Recipients withdraw via `withdraw()`.
   - A reverting seller, buyer, or developer can no longer brick settlement.

2. TEE result submission is budget-checked.
   - `submitResult()` now reverts with `ComputeCostOverBudget()` if `computeCost + fee > budgetCap`.
   - This prevents `rejectDeal()` and `expireDeal()` from becoming permanently uncallable.

3. Deal creation now validates critical inputs.
   - `expiry` must be in the future.
   - `artifactHash` must be non-zero.
   - `teeIdentity` must be non-zero.

#### Contract interface snapshot

- `createDeal(uint256 reservePrice, uint256 expiry, bytes32 artifactHash, address teeIdentity)`
- `fundDeal(uint256 dealId)` payable
- `submitResult(uint256 dealId, ScoreBand scoreBand, uint256 computeCost, bytes32 resultHash, bytes32 composeHash, uint256 authorizationExpiry, bytes verifierSignature)`
- `acceptDeal(uint256 dealId, uint256 dealPayment)`
- `rejectDeal(uint256 dealId)`
- `expireDeal(uint256 dealId)`
- `withdraw()`
- `pendingWithdrawals(address account) -> uint256`
- `getDeal(uint256 dealId) -> Deal`

#### Test status at deploy time

- Command: `forge test --gas-report`
- Result: `39` tests passed, `0` failed
- Includes:
  - unit coverage for all lifecycle transitions
  - fuzz coverage for settlement conservation
  - adversarial test proving a reverting seller cannot block `acceptDeal`
  - budget safety test proving over-budget compute is rejected

### Historical EmailOracleAuth

- Contract: `EmailOracleAuth`
- Address: `0xd21706E1AfF482F1d23664be5768ceaD63ccdBfF`
- Network: Base Sepolia (`chainId = 84532`)
- BaseScan: `https://sepolia.basescan.org/address/0xd21706E1AfF482F1d23664be5768ceaD63ccdBfF`
- Owner: `0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38`
- Current-operator controlled: no
- Oracle upgrade delay: `172800` seconds (`2 days`)
- `allowAnyDevice()`: `true`
- `oracleCodeFrozen()`: `false`
- `consumerRegistryFrozen()`: `false`

#### Purpose

`EmailOracleAuth` governs two different trust domains:

1. Oracle boot authorization.
   - Which oracle compose hashes may boot and receive KMS material.

2. OTP consumer authorization.
   - Which consumer app IDs and compose hashes may request OTPs from the oracle.

#### Operational note

The oracle contract is still mutable. Before production freeze:

1. Register the final oracle compose hash.
2. Register the final approved consumer app ID and compose hash.
3. Call `freezeOracleCodeAuth()`.
4. Optionally call `freezeConsumerRegistry()`.

Because the historical owner is not the current operator deployer, do not use
the historical `EmailOracleAuth` as the production policy root for this branch.
Deploy a fresh instance from the current Foundry `dev` keystore account, then
register the final oracle and consumer compose hashes once the current Phala CVM
has been rebuilt and verified.

## Phala

### Historical CVM Record

- CVM name: `tinker-email-oracle`
- CVM id: `cvm_j2kD1EZn`
- App id: `29d78795d77408a705d2c77c42d1bc10c59d0671`
- Status reported by Phala: `running`
- Compose hash: `97818b3dbac8227ea3016e26c16886083f2fe25592fc0f33900e037c6003acd6`
- Instance type: `tdx.medium`
- Node: `prod5`
- dstack OS: `0.5.7`
- Gateway base domain: `dstack-pha-prod5.phala.network`

### Historical endpoints

- Oracle API: `https://29d78795d77408a705d2c77c42d1bc10c59d0671-8000.dstack-pha-prod5.phala.network`
- Delegate API: `https://29d78795d77408a705d2c77c42d1bc10c59d0671-8080.dstack-pha-prod5.phala.network`
- Chrome CDP: `https://29d78795d77408a705d2c77c42d1bc10c59d0671-9222.dstack-pha-prod5.phala.network`
- Neko UI: `https://29d78795d77408a705d2c77c42d1bc10c59d0671-52000.dstack-pha-prod5.phala.network`

### Historical images

- Oracle image: `ttl.sh/therealwiki-tinker-oracle-20260313-8b76c1d@sha256:6d521ae4da405250adbab51a8597ac83fdff4addfe930921293ccadad6d12352`
- Delegate image: `ttl.sh/therealwiki-tinker-delegate-20260313-8b76c1d-r6@sha256:6563c94382f82dc43dfe4de1f615189c8c3a6806061bb366c0efd0403017e115`
- Delegate browser sidecar: `mcr.microsoft.com/playwright:v1.58.0-noble@sha256:e3dca7b3c921ce1ebf45a50a6ac77982532c987e5926eb06535b5f56b363b94f`

### Historical live state

- Oracle API is live and healthy at the public `:8000` endpoint.
- The delegate stack now boots with registry images instead of local `build:` contexts.
- The delegate service no longer needs to crash the whole CVM if bootstrap fails; `/health` exposes runtime bootstrap status.

### Important current blocker

The recorded March 2026 blocker was Tinker auth automation, not Phala
deployment. This record must be revalidated with the current Phala profile and
current image digests before being treated as a live deployment.

On March 17, 2026, direct tests showed:

1. A headed local Chrome session reaches the Tinker `magic-code` page with a `gmail.com` control.
2. The deployed delegate path, which currently uses a headless Playwright browser server, is blocked with:
   - `Access blocked, please contact support.`
3. The Tinker auth page now ships explicit bot-check machinery:
   - hidden `signals` / bot token handling in the server-rendered form
   - `Fingerprint`
   - `BotCheckClient`
   - `BotCheckTokenInput`

This means the previous assumption that `cock.email` alone explained the failure is stale. The email domain is not the primary blocker now; the deployed browser posture is.

### What remains to finish fully automatic bootstrap

1. Replace the current headless Playwright sidecar with a headed browser path that survives Phala packaging.
2. Re-validate signup against the live Tinker auth flow from inside the CVM.
3. Once signup succeeds, verify:
   - OTP retrieval from the email oracle
   - onboarding completion
   - API key creation and encrypted storage at `/data/tinker_api_key.enc`
4. Freeze docs around the new browser requirement and stop claiming `cock.email` alone is sufficient.

## Commands used

### Test and build

```bash
cd "⚙️/tinker-delegate/contracts"
set -a; . ../../../.env; set +a
forge build
forge test --gas-report
```

### Compose hash verification

```bash
cd "⚙️/tinker-delegate"
uv run python -m tinker_delegate.main verify-compose-hash \
  --compose docker-compose.all.phala.yaml \
  --phala-raw-compose \
  --expected-hash EXPECTED_PHALA_COMPOSE_HASH
```

For deploy-critical TEE images, keep digest-pinned image refs literal in the
Phala compose. Do not treat encrypted-env image substitutions as quote-bound
deployment evidence unless a separate verifier proves the encrypted env values
that Phala applied.

### Deploy DiligenceRoom

```bash
cd "⚙️/tinker-delegate/contracts"
./scripts/deploy-base-sepolia.sh
```

The helper builds, tests, dry-runs, broadcasts `DiligenceRoom` and
`EmailOracleAuth`, performs on-chain reads, and writes
`deployments/base-sepolia.json`. If contract verification is needed, use the
recorded addresses and constructor arguments from the manifest and Foundry
broadcast JSON. Do not use `--private-key`.

### Useful verification reads

```bash
cast call 0xe51A3C5fd564c625C9D72D2283878Ab4296b3844 "developer()(address)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call 0xe51A3C5fd564c625C9D72D2283878Ab4296b3844 "dealCount()(uint256)" --rpc-url "$BASE_SEPOLIA_RPC_URL"

cast call 0xd21706E1AfF482F1d23664be5768ceaD63ccdBfF "owner()(address)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call 0xd21706E1AfF482F1d23664be5768ceaD63ccdBfF "ORACLE_UPGRADE_DELAY()(uint256)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call 0xd21706E1AfF482F1d23664be5768ceaD63ccdBfF "allowAnyDevice()(bool)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
```

## Rollback And Recovery

Rollback is policy-specific because deployed contracts and CVM attestations are
part of the verification chain.

Safe to redeploy during test phases:

- `DiligenceRoom` while no production deals depend on the previous address.
- `EmailOracleAuth` while oracle code authorization is not frozen and no
  production KMS/app policy depends on the previous address.
- Phala CVMs that have not been advertised as the final endpoint or policy root.
- Frontend/static verifier pages, as long as the deployment manifest is updated.

Must not be silently rolled back:

- A frozen `EmailOracleAuth` oracle compose-hash policy.
- A consumer registry that reviewers or users have already relied on.
- Any deployed `DiligenceRoom` with funded or evaluated deals.
- A Phala CVM/image/compose hash that has been published as the attested
  production boundary.
- Any funding, Tinker API-key, email, or private-artifact sealed state.

Rollback procedure:

1. Pause new room creation and Tinker execution at the API/UI layer if those
   controls are available.
2. Record the failing address, CVM ID, compose hash, image digest, transaction
   hash, or endpoint in `deployments/base-sepolia.json` before replacing it.
3. Deploy the replacement from a Foundry keystore account, never a raw private
   key.
4. Verify bytecode, owner/developer addresses, compose hash, image digest, and
   TDX quote evidence before routing users to the replacement.
5. Leave old contracts callable for withdrawals or expiries when funds are
   present. Do not strand user funds by hiding the old address.
6. Notify users/reviewers when a published trust root, compose hash, image
   digest, app ID, endpoint, or contract address changes.
7. Update `ARCHITECTURE.md`, `STATUS.md`, and the deployment manifest in the
   same change so docs do not imply the old trust root is still current.

Emergency-only actions:

- Revoke oracle consumers if OTP or account-custody policy is suspect.
- Freeze oracle code authorization only after the intended compose hash is
  verified, because this cannot be undone.
- Stop or delete a CVM only after sealed data migration or intentional data
  destruction has been decided and recorded.

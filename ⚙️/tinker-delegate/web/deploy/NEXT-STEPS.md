# Pick up here — TEE hosting for The Gate: Health

Saved 2026-07-07. Everything below is optional — **the app is fully functional as-is**
without any of it.

## Current state (done + verified)

- The full `web/` publication is built and passing (`npm run build`, 17 gate tests).
- The **Live TEE** section fetches a **real Intel TDX quote** from amiller's
  dstack-webhost reference daemon (CORS-open, no token) — verified live in-browser.
- It is **wired to self-verify**: a build with `VITE_TEE_DAEMON_URL` / `VITE_TEE_PROJECT`
  (or served same-origin from a daemon) targets its own attestation and **auto-verifies
  on load**. `deploy-gate.sh` bakes those in.
- Deploy scripts (`provision-daemon.sh`, `deploy-gate.sh`) are written and **dry-run
  tested**. Not run against real infra.

Default behavior with no daemon: the Live TEE section shows the reference demo
(`timelock`), which is a genuine quote you can fetch live. Nothing more is required
for the app to work.

## To pick up — two ways

### Option A — real TEE on Phala (paid)

Turns the app's own "attested" from illustration into a verifiable claim (its `dist/`
`tree_hash` binds into a real TDX quote it can fetch about itself).

Prereqs (as of 2026-07-07 both are OUTSTANDING):
1. `phala` auth — **not authenticated**. Run: `phala login` (or `! phala login` in Claude Code).
2. Willingness to run a **paid** `tdx.medium` CVM on Phala, billed while up.

Then:
```bash
cd "⚙️/tinker-delegate/web/deploy"
cp webhost.env.example webhost.env
./provision-daemon.sh          # Phase A: brings up the tee-daemon (confirms before spending)
./deploy-gate.sh --promote     # Phase B: build (self-wired) → deploy → promote to attested
# verify: curl "$CVM_URL/_api/verification/wikigen-gate" | jq .
```
Tear down when done to stop billing: `phala cvms` (delete the CVM), or
`curl -X DELETE $CVM_URL/_api/projects/wikigen-gate -H "Authorization: Bearer $TEE_DAEMON_TOKEN"`.

### Option B — free, local (no cloud, no cost)

A dev-mode daemon in Docker. No real TDX quote (no enclave), but the deploy/host flow
works end to end for development.

```bash
# clone the daemon (or reuse deploy/.daemon-src if provision-daemon.sh already cloned it)
git clone https://github.com/amiller/dstack-webhost /tmp/dstack-webhost
cd /tmp/dstack-webhost
echo "TEE_DAEMON_TOKEN=$(openssl rand -hex 32)" > .env
docker compose up            # serves the tee-daemon on http://localhost:8080

# in another shell, deploy the gate onto it (DEV mode — promotion needs a real enclave)
cd "⚙️/tinker-delegate/web/deploy"
CVM_URL=http://localhost:8080 TEE_DAEMON_TOKEN=<the token above> ./deploy-gate.sh
# app at http://localhost:8080/wikigen-gate/
```

### Option C — do nothing

The published app already demonstrates the privacy layer against amiller's live
reference daemon. Fine to leave it here.

## Files

- `deploy/deploy-gate.sh` · `deploy/provision-daemon.sh` · `deploy/webhost.env.example` · `deploy/README.md`
- App wiring: `src/lib/dstackVerifier.ts` (targets), `src/components/LiveAttestation.tsx`, `src/data/attestationFixture.ts`

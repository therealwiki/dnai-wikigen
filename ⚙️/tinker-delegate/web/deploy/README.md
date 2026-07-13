# Deploy the gate onto a real TEE

These scripts host **The Gate: Health** inside a Trusted Execution Environment via
[amiller/dstack-webhost](https://github.com/amiller/dstack-webhost) (a "personal
Vercel for attestable web apps") on **Phala Cloud**, using tinker-delegate's Phala
credentials. Once promoted, the gate's built `dist/` source hash binds into a real
Intel TDX quote — turning this app's own "attested" from illustration into a
verifiable claim, fetchable from its own **Live TEE** section.

Two phases:

| Phase | Script | What it does | Cost |
|---|---|---|---|
| A | `provision-daemon.sh` | Deploy a `tee-daemon` CVM on Phala, mint its admin token | **paid CVM** |
| B | `deploy-gate.sh` | Build the gate, upload `dist/` to the daemon, promote to attested | free |

## Prerequisites

- `phala` CLI (v1.x), `docker`, `curl`, `jq`, `openssl`, `node`/`npm` — all present in this environment.
- Phala auth: `phala login` (in Claude Code, run `! phala login`).
- `PHALA_CLOUD_API_KEY` — auto-read from the repo-root `.env` if not set.

```bash
cd deploy
cp webhost.env.example webhost.env      # gitignored; scripts source it
```

## Phase A — provision the daemon (one time)

```bash
./provision-daemon.sh --dry-run          # print the plan, no cloud calls
./provision-daemon.sh                     # confirms before deploying a PAID CVM
```

It clones dstack-webhost at a pinned ref, generates a `TEE_DAEMON_TOKEN`, runs
`phala deploy --name wikigen-tee-daemon -c docker-compose.yaml -e .daemon.env --kms phala --wait --json`,
and writes `CVM_URL` + `TEE_DAEMON_TOKEN` into `webhost.env`. If it can't auto-derive
the gateway URL, it prints `phala cvms list` output — copy the `…-8080.<node>.phala.network`
URL into `webhost.env` as `CVM_URL`.

> The daemon needs the dstack broker socket to attest; on Phala dstack CVMs the
> compose mounts `/var/run/dstack.sock`. Locally (`docker compose up` in the
> checkout) you get dev mode without real quotes.

## Phase B — deploy + promote the gate

```bash
./deploy-gate.sh --dry-run               # build + package, print the curl calls
./deploy-gate.sh                          # deploy in DEV mode → $CVM_URL/wikigen-gate/
./deploy-gate.sh --promote                # deploy + promote → real TDX quote
```

`--promote` is a release action (deliberate, not automatic): it records the source
hash, opens the audit log, and binds the hash into the quote. After it, the public
verifier endpoints work with **no token**:

```bash
curl -fsS "$CVM_URL/_api/verification/wikigen-gate" | jq .   # bundle: quote + source + audit
curl -fsS "$CVM_URL/_api/attest/wikigen-gate"                # raw TDX quote
```

Other Phase-B flags: `--redeploy` (tear down + redeploy), `--skip-build` (upload the current `dist/`).

## Point the app at its own attestation

Once promoted, wire the **Live TEE** section to the self-hosted daemon instead of
amiller's demo: set `DAEMON_BASE` and add `wikigen-gate` in
`../src/lib/dstackVerifier.ts` (or thread them as build-time env). The section then
fetches the gate's **own** real quote.

## Security

- `webhost.env`, `.daemon.env`, `.daemon-deploy.json`, `.daemon-src/`, and `*.tgz` are gitignored — they hold the admin token and deploy state.
- The admin token gates all write endpoints (`POST /_api/projects`, `promote`, `redeploy`, `DELETE`). Verifier reads are public by design (RFC 0015).
- Never commit `webhost.env`. Rotate the token with a fresh `provision-daemon.sh` run if it leaks.

## Reference — daemon API (from `proxy/ingress.py`)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/_api/projects` | Bearer | deploy (json git source, or multipart tarball) |
| POST | `/_api/projects/<name>/promote` | Bearer | dev → attested |
| POST | `/_api/projects/<name>/redeploy` | Bearer | re-pull / re-upload |
| DELETE | `/_api/projects/<name>` | Bearer | tear down |
| GET | `/_api/verification/<name>` | public\* | quote + source + audit bundle |
| GET | `/_api/attest/<name>` | public\* | raw TDX quote |
| GET | `/_api/substrate` | public | effective OCI runtime (e.g. `runsc`) |

\* public only once the project is `attested`.

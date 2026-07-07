#!/usr/bin/env bash
#
# deploy-gate.sh — Phase B.
# Build "The Gate: Health" and deploy its static bundle onto a dstack-webhost
# tee-daemon, then (optionally) promote it to `attested` so its source hash
# binds into a real TDX quote.
#
# Prereqs: a running tee-daemon (see provision-daemon.sh) and its admin token.
# Config:  ./webhost.env  (copy from webhost.env.example)
#
# Usage:
#   ./deploy-gate.sh                 # build + deploy in DEV mode
#   ./deploy-gate.sh --promote       # build + deploy + promote to attested
#   ./deploy-gate.sh --redeploy      # tear down existing, then deploy fresh
#   ./deploy-gate.sh --skip-build    # deploy the current dist/ as-is
#   ./deploy-gate.sh --dry-run       # print what it would do, touch no network
#   CVM_URL=... TEE_DAEMON_TOKEN=... ./deploy-gate.sh   # config via env
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- config ------------------------------------------------------------------
# shellcheck disable=SC1091
[ -f "$SCRIPT_DIR/webhost.env" ] && source "$SCRIPT_DIR/webhost.env"

PROJECT_NAME="${PROJECT_NAME:-wikigen-gate}"
CVM_URL="${CVM_URL:-}"
TEE_DAEMON_TOKEN="${TEE_DAEMON_TOKEN:-}"

PROMOTE=0
REDEPLOY=0
SKIP_BUILD=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --promote)    PROMOTE=1 ;;
    --redeploy)   REDEPLOY=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --dry-run)    DRY_RUN=1 ;;
    -h|--help)    sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }
say() { printf '\033[36m▸ %s\033[0m\n' "$*"; }
CVM_URL="${CVM_URL%/}"

# --- preflight ---------------------------------------------------------------
command -v curl >/dev/null || die "curl not found"
command -v jq   >/dev/null || die "jq not found"
if [ "$DRY_RUN" -eq 0 ]; then
  [ -n "$CVM_URL" ] || die "CVM_URL is empty. Set it in webhost.env or the environment (run provision-daemon.sh first)."
  [ -n "$TEE_DAEMON_TOKEN" ] || die "TEE_DAEMON_TOKEN is empty. Set it in webhost.env or the environment."
fi

AUTH=(-H "Authorization: Bearer ${TEE_DAEMON_TOKEN}")

# --- build -------------------------------------------------------------------
# Bake the daemon URL + project into the bundle so the app's Live TEE section
# verifies ITSELF once hosted (falls back to same-origin auto-detect if empty).
if [ "$SKIP_BUILD" -eq 0 ]; then
  say "Building the gate (npm run build) — wiring Live TEE to $([ -n "$CVM_URL" ] && echo "$CVM_URL" || echo "same-origin") / $PROJECT_NAME …"
  ( cd "$WEB_DIR" && VITE_TEE_DAEMON_URL="${CVM_URL}" VITE_TEE_PROJECT="${PROJECT_NAME}" npm run build )
else
  say "Skipping build (--skip-build) — Live TEE wiring uses whatever the current dist/ was built with."
fi
[ -f "$WEB_DIR/dist/index.html" ] || die "no build found at $WEB_DIR/dist/index.html — run without --skip-build."

# --- package -----------------------------------------------------------------
TARBALL="$(mktemp -t wikigen-gate.XXXXXX).tgz"
trap 'rm -f "$TARBALL"' EXIT
tar czf "$TARBALL" -C "$WEB_DIR/dist" .
say "Packaged dist/ → $TARBALL ($(du -h "$TARBALL" | cut -f1))"

MANIFEST=$(printf '{"name":"%s","runtime":"static","mode":"dev"}' "$PROJECT_NAME")

if [ "$DRY_RUN" -eq 1 ]; then
  echo
  say "DRY RUN — the calls that would be made:"
  cat <<EOF

  # deploy (static bundle, dev mode)
  curl -fsS -X POST "\$CVM_URL/_api/projects" \\
    -H "Authorization: Bearer \$TEE_DAEMON_TOKEN" \\
    -F 'manifest=${MANIFEST};type=application/json' \\
    -F "files=@${TARBALL}"

  # → served at \$CVM_URL/${PROJECT_NAME}/
$( [ "$PROMOTE" -eq 1 ] && cat <<EOP

  # promote to attested (binds source hash into the TDX quote)
  curl -fsS -X POST "\$CVM_URL/_api/projects/${PROJECT_NAME}/promote" -H "Authorization: Bearer \$TEE_DAEMON_TOKEN"

  # verify (public, no token)
  curl -fsS "\$CVM_URL/_api/verification/${PROJECT_NAME}" | jq .
EOP
)
EOF
  exit 0
fi

# --- (optional) tear down for a clean redeploy -------------------------------
if [ "$REDEPLOY" -eq 1 ]; then
  say "Tearing down existing '$PROJECT_NAME' (--redeploy) …"
  curl -fsS -X DELETE "$CVM_URL/_api/projects/$PROJECT_NAME" "${AUTH[@]}" >/dev/null 2>&1 || true
fi

# --- deploy ------------------------------------------------------------------
say "Deploying '$PROJECT_NAME' to $CVM_URL …"
HTTP_BODY="$(mktemp)"; trap 'rm -f "$TARBALL" "$HTTP_BODY"' EXIT
code=$(curl -sS -o "$HTTP_BODY" -w '%{http_code}' -X POST "$CVM_URL/_api/projects" \
  "${AUTH[@]}" \
  -F "manifest=${MANIFEST};type=application/json" \
  -F "files=@${TARBALL}")
if [ "$code" -lt 200 ] || [ "$code" -ge 300 ]; then
  echo "deploy failed (HTTP $code):" >&2
  cat "$HTTP_BODY" >&2; echo >&2
  if grep -qi "exists\|already" "$HTTP_BODY"; then
    die "project already exists — re-run with --redeploy to replace it."
  fi
  exit 1
fi
jq -r '"  runtime=\(.runtime // "static") mode=\(.mode // "dev")"' "$HTTP_BODY" 2>/dev/null || true
say "Deployed. App URL: $CVM_URL/$PROJECT_NAME/"

# --- promote + verify --------------------------------------------------------
if [ "$PROMOTE" -eq 1 ]; then
  say "Promoting '$PROJECT_NAME' to attested (this is a release — deliberate) …"
  curl -fsS -X POST "$CVM_URL/_api/projects/$PROJECT_NAME/promote" "${AUTH[@]}" >/dev/null
  say "Fetching the public verification bundle …"
  if curl -fsS "$CVM_URL/_api/verification/$PROJECT_NAME" \
      | jq '{project: .app.project, source: .app.source, image_digest: .app.image_digest, has_tdx_quote: (.platform_quote.quote | length > 0), binding_pubkey: .app.binding_quote.pubkey}'; then
    echo
    say "Attested. The gate's own tree_hash now binds into a real TDX quote."
    echo "  Public verifier:  $CVM_URL/_api/verification/$PROJECT_NAME"
    echo "  Raw TDX quote:    $CVM_URL/_api/attest/$PROJECT_NAME"
    echo "  Point the app's Live TEE section at CVM_URL=$CVM_URL, project=$PROJECT_NAME."
  fi
else
  echo
  say "Deployed in DEV mode. To make 'attested' real, run:"
  echo "  ./deploy-gate.sh --promote"
fi

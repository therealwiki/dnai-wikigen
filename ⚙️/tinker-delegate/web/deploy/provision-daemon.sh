#!/usr/bin/env bash
#
# provision-daemon.sh — Phase A.
# Bring up a dstack-webhost `tee-daemon` on Phala Cloud using tinker-delegate's
# Phala credentials, then record its URL + admin token in webhost.env so that
# deploy-gate.sh (Phase B) can host the gate on it.
#
#  ⚠️  THIS CREATES A PAID CVM on Phala Cloud. It is guarded by a confirmation
#      prompt (skip with --yes) and is never run automatically.
#
# Prereqs: `phala` CLI (v1.x), logged in (`phala login`), and PHALA_CLOUD_API_KEY
#          (auto-read from the repo-root .env if not set).
#
# Usage:
#   ./provision-daemon.sh              # interactive: confirms before deploying
#   ./provision-daemon.sh --yes        # non-interactive
#   ./provision-daemon.sh --dry-run    # print the plan + the phala command only
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$WEB_DIR/../../.." && pwd)"   # …/tinker-deligate (git root)

# shellcheck disable=SC1091
[ -f "$SCRIPT_DIR/webhost.env" ] && source "$SCRIPT_DIR/webhost.env"

DAEMON_CVM_NAME="${DAEMON_CVM_NAME:-wikigen-tee-daemon}"
PHALA_INSTANCE_TYPE="${PHALA_INSTANCE_TYPE:-tdx.medium}"
PHALA_KMS_TYPE="${PHALA_KMS_TYPE:-phala}"
DSTACK_WEBHOST_REPO="${DSTACK_WEBHOST_REPO:-https://github.com/amiller/dstack-webhost}"
DSTACK_WEBHOST_REF="${DSTACK_WEBHOST_REF:-main}"

ASSUME_YES=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --yes|-y)  ASSUME_YES=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }
say() { printf '\033[36m▸ %s\033[0m\n' "$*"; }

SRC_DIR="$SCRIPT_DIR/.daemon-src"
DAEMON_ENV="$SCRIPT_DIR/.daemon.env"

if [ "$DRY_RUN" -eq 1 ]; then
  say "DRY RUN — plan (no cloud calls, no side effects):"
  echo "  cvm name:      $DAEMON_CVM_NAME"
  echo "  instance-type: $PHALA_INSTANCE_TYPE   kms: $PHALA_KMS_TYPE"
  echo "  daemon source: $DSTACK_WEBHOST_REPO @ $DSTACK_WEBHOST_REF"
  echo "  would run:"
  echo "    phala deploy --name $DAEMON_CVM_NAME -c $SRC_DIR/docker-compose.yaml \\"
  echo "      -e $DAEMON_ENV --kms $PHALA_KMS_TYPE --instance-type $PHALA_INSTANCE_TYPE --wait --json"
  exit 0
fi

command -v phala >/dev/null || die "phala CLI not found. Install it (see tinker-delegate quickstart)."
command -v git   >/dev/null || die "git not found"

# --- API key: prefer env/webhost.env, else pull from the repo-root .env ------
if [ -z "${PHALA_CLOUD_API_KEY:-}" ] && [ -f "$REPO_ROOT/.env" ]; then
  PHALA_CLOUD_API_KEY="$(grep -E '^PHALA_CLOUD_API_KEY=' "$REPO_ROOT/.env" | head -1 | cut -d= -f2- || true)"
fi
[ -n "${PHALA_CLOUD_API_KEY:-}" ] || die "PHALA_CLOUD_API_KEY not set (webhost.env, env, or $REPO_ROOT/.env)."
export PHALA_CLOUD_API_KEY

say "Checking Phala auth …"
phala status >/dev/null 2>&1 || die "not authenticated. Run:  phala login   (or:  ! phala login  in Claude Code)"

# --- generate the daemon admin token (once) ----------------------------------
if [ -z "${TEE_DAEMON_TOKEN:-}" ]; then
  TEE_DAEMON_TOKEN="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  say "Generated a new TEE_DAEMON_TOKEN (kept out of the logs)."
else
  say "Reusing TEE_DAEMON_TOKEN from webhost.env."
fi

# --- fetch dstack-webhost at a pinned ref ------------------------------------
if [ ! -d "$SRC_DIR/.git" ]; then
  say "Cloning $DSTACK_WEBHOST_REPO @ $DSTACK_WEBHOST_REF …"
  git clone --depth 1 --branch "$DSTACK_WEBHOST_REF" "$DSTACK_WEBHOST_REPO" "$SRC_DIR"
else
  say "Using existing checkout at $SRC_DIR (delete it to re-clone)."
fi
[ -f "$SRC_DIR/docker-compose.yaml" ] || die "docker-compose.yaml not found in $SRC_DIR"

# --- env file the CVM boots with ---------------------------------------------
umask 077
{
  echo "TEE_DAEMON_TOKEN=$TEE_DAEMON_TOKEN"
  # Optional broker-only hardening vars (see the compose comments); leave empty
  # to use defaults.
  echo "DAEMON_VOLUME_NAME="
  echo "BROKER_VOLUME_NAME="
} > "$DAEMON_ENV"
say "Wrote daemon env → $DAEMON_ENV (chmod 600)"

DEPLOY_CMD=(phala deploy
  --name "$DAEMON_CVM_NAME"
  -c "$SRC_DIR/docker-compose.yaml"
  -e "$DAEMON_ENV"
  --kms "$PHALA_KMS_TYPE"
  --instance-type "$PHALA_INSTANCE_TYPE"
  --wait --json)

# --- confirm (this spends money) ---------------------------------------------
if [ "$ASSUME_YES" -eq 0 ]; then
  echo
  echo "About to deploy a PAID Phala CVM:"
  echo "  name:          $DAEMON_CVM_NAME"
  echo "  instance-type: $PHALA_INSTANCE_TYPE"
  echo "  kms:           $PHALA_KMS_TYPE"
  echo "  compose:       $SRC_DIR/docker-compose.yaml"
  read -r -p "Proceed? [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]] || { echo "aborted."; exit 0; }
fi

say "Deploying tee-daemon to Phala (this can take a few minutes) …"
DEPLOY_JSON="$SCRIPT_DIR/.daemon-deploy.json"
"${DEPLOY_CMD[@]}" | tee "$DEPLOY_JSON"

# --- best-effort: derive the gateway URL -------------------------------------
# The daemon listens on 8080; Phala's gateway exposes it at
#   https://<app-id>-8080.<node-domain>/
APP_ID="$(jq -r '(.app_id // .id // .cvm.app_id // .instance_id // empty)' "$DEPLOY_JSON" 2>/dev/null | head -1)"
GW_URL="$(jq -r '(.gateway_url // .app_url // .url // (.urls[]? ) // empty)' "$DEPLOY_JSON" 2>/dev/null | grep -Eo 'https://[^" ]+' | head -1 || true)"

CVM_URL=""
if [ -n "$GW_URL" ]; then
  CVM_URL="${GW_URL%/}"
elif [ -n "$APP_ID" ]; then
  echo
  say "Deployed (app_id=$APP_ID). Finding the gateway URL …"
  phala cvms list 2>/dev/null | grep -i "$APP_ID" || true
  echo "  → Copy the CVM's '-8080' gateway URL into $SCRIPT_DIR/webhost.env as CVM_URL."
fi

# --- persist config for deploy-gate.sh ---------------------------------------
ENV_OUT="$SCRIPT_DIR/webhost.env"
[ -f "$ENV_OUT" ] || cp "$SCRIPT_DIR/webhost.env.example" "$ENV_OUT"
upsert() { # upsert KEY VALUE into webhost.env
  local k="$1" v="$2"
  if grep -qE "^$k=" "$ENV_OUT"; then
    # portable in-place edit
    tmp="$(mktemp)"; sed "s|^$k=.*|$k=$v|" "$ENV_OUT" > "$tmp" && mv "$tmp" "$ENV_OUT"
  else
    echo "$k=$v" >> "$ENV_OUT"
  fi
}
upsert TEE_DAEMON_TOKEN "$TEE_DAEMON_TOKEN"
[ -n "$CVM_URL" ] && upsert CVM_URL "$CVM_URL"
chmod 600 "$ENV_OUT"

echo
say "Done."
if [ -n "$CVM_URL" ]; then
  echo "  Daemon:  $CVM_URL"
  echo "  Next:    ./deploy-gate.sh --promote"
else
  echo "  Set CVM_URL in $ENV_OUT (from 'phala cvms list'), then: ./deploy-gate.sh --promote"
fi

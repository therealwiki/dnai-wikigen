#!/usr/bin/env bash

# Resolve the immutable fresh-deployment receipt and the mutable ceremony
# ledger only after the caller has sourced .env. No repository ledger is a
# fallback for a post-authority ceremony.
operator_policy_resolve_release_ceremony_paths() {
  if [ -z "${DEPLOYMENT_MANIFEST_PATH:-}" ]; then
    echo "DEPLOYMENT_MANIFEST_PATH must name the explicit immutable 0444 fresh-deployment receipt." >&2
    return 1
  fi
  if [ -z "${RELEASE_CEREMONY_LEDGER_PATH:-}" ]; then
    echo "RELEASE_CEREMONY_LEDGER_PATH must name the explicit external 0600 working ledger." >&2
    return 1
  fi
  if [ -z "${RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT:-}" ]; then
    echo "RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT must name the explicit external ceremony evidence directory." >&2
    return 1
  fi

  FRESH_DEPLOYMENT_MANIFEST_PATH="$DEPLOYMENT_MANIFEST_PATH"
  MANIFEST_PATH="$RELEASE_CEREMONY_LEDGER_PATH"

  local historical_path="$ROOT_DIR/deployments/base-sepolia.json"
  if [ "$FRESH_DEPLOYMENT_MANIFEST_PATH" = "$historical_path" ] \
    || [ "$MANIFEST_PATH" = "$historical_path" ]; then
    echo "The historical deployments/base-sepolia.json ledger is never ceremony authority." >&2
    return 1
  fi
  if [ "$FRESH_DEPLOYMENT_MANIFEST_PATH" = "$MANIFEST_PATH" ]; then
    echo "The immutable fresh-deployment receipt and mutable ceremony ledger must be distinct paths." >&2
    return 1
  fi
}

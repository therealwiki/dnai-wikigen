#!/usr/bin/env bash

# Resolve the immutable fresh-deployment receipt and the mutable ceremony
# ledger only after the guarded data-only deployment environment is loaded.
# No repository ledger is a fallback for a post-authority ceremony.
operator_policy_resolve_release_ceremony_paths() {
  local fresh_parent_input
  local fresh_parent
  local fresh_basename
  local canonical_fresh_path

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

  if [[ "$FRESH_DEPLOYMENT_MANIFEST_PATH" != /* ]] \
    || [[ "$FRESH_DEPLOYMENT_MANIFEST_PATH" == */ ]]; then
    echo "DEPLOYMENT_MANIFEST_PATH must be a canonical absolute file path outside the source checkout." >&2
    return 1
  fi
  fresh_parent_input="${FRESH_DEPLOYMENT_MANIFEST_PATH%/*}"
  [ -n "$fresh_parent_input" ] || fresh_parent_input=/
  fresh_basename="${FRESH_DEPLOYMENT_MANIFEST_PATH##*/}"
  case "$fresh_basename" in
    .|..)
      echo "DEPLOYMENT_MANIFEST_PATH must be a canonical absolute file path outside the source checkout." >&2
      return 1
      ;;
  esac
  fresh_parent="$(builtin cd -P -- "$fresh_parent_input" && builtin pwd -P)" || {
    echo "DEPLOYMENT_MANIFEST_PATH parent could not be resolved canonically." >&2
    return 1
  }
  if [ "$fresh_parent" = / ]; then
    canonical_fresh_path="/$fresh_basename"
  else
    canonical_fresh_path="$fresh_parent/$fresh_basename"
  fi
  if [ "$canonical_fresh_path" != "$FRESH_DEPLOYMENT_MANIFEST_PATH" ]; then
    echo "DEPLOYMENT_MANIFEST_PATH must be canonical and contain no symlinked parent component." >&2
    return 1
  fi
  case "$FRESH_DEPLOYMENT_MANIFEST_PATH" in
    "$ROOT_DIR"|"$ROOT_DIR"/*)
      echo "DEPLOYMENT_MANIFEST_PATH must remain outside the source checkout." >&2
      return 1
      ;;
  esac

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

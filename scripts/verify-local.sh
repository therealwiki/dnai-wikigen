#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-all}"

run_secret_scan() {
  "$ROOT_DIR/scripts/ci-secret-scan.sh"
}

run_foundry() {
  echo "== Foundry contracts =="
  pushd "$ROOT_DIR/⚙️/tinker-delegate/contracts" >/dev/null
  forge build --sizes
  # Several deployment-script tests exercise vm.env* by setting process-wide
  # variables through vm.setEnv. Foundry workers share that process environment,
  # so parallel suites can race on purpose-specific role values. Keep the
  # release gate deterministic until those script fixtures no longer use env.
  forge test --threads 1
  ./scripts/test-deployment-safety.sh
  ./scripts/test-local-release-rehearsal-safety.sh
  ./scripts/test-challenge-registry-release-safety.sh
  ./scripts/test-compute-release-safety.sh
  ./scripts/test-diligence-release-safety.sh
  ./scripts/test-email-oracle-release-safety.sh
  ./scripts/test-execution-policy-anchor-release-safety.sh
  ./scripts/test-tinker-release-safety.sh
  popd >/dev/null
}

run_python_package() {
  local package_dir="$1"
  local compile_paths="$2"
  local test_dir="${3:-}"

  echo "== Python package: $package_dir =="
  pushd "$ROOT_DIR/$package_dir" >/dev/null
  if [ "$package_dir" = "⚙️/tinker-delegate" ]; then
    # The production Compute/Tinker boundary lives in the locked agent extra.
    # Release verification must exercise the real SDK capability audit instead
    # of silently skipping it after a default-only sync removes that dependency.
    uv sync --frozen --extra agent --group dev
  else
    uv sync --frozen
  fi
  # Intentional word splitting: compile paths are repo-local paths without spaces.
  # shellcheck disable=SC2086
  uv run python -m compileall $compile_paths ${test_dir:+"$test_dir"}
  if [ -n "$test_dir" ]; then
    if [ "$package_dir" = "⚙️/tinker-delegate" ]; then
      uv run --frozen python -m pytest "$test_dir"
    else
      uv run python -m unittest discover -s "$test_dir"
    fi
  fi
  popd >/dev/null
}

run_pytest_package() {
  local package_dir="$1"
  local compile_paths="$2"

  echo "== Python package: $package_dir =="
  pushd "$ROOT_DIR/$package_dir" >/dev/null
  uv sync --frozen
  # Intentional word splitting: compile paths are repo-local paths without spaces.
  # shellcheck disable=SC2086
  uv run python -m compileall $compile_paths tests
  uv run --frozen python -m pytest
  popd >/dev/null
}

run_python() {
  run_python_package "⚙️/tinker-delegate" "tinker_delegate" "tests"
  run_python_package "⚙️/tee-email-oracle" "email_oracle captcha-solver/captcha_solver" "tests"
  run_pytest_package "⚙️/attestation-qvl" "src/attestation_qvl"
  run_pytest_package "⚙️/compute-metering" "src/compute_metering"
  run_python_package "⚙️/props-room" "props_room"
  run_python_package "⚙️/whatsapp-delegate" "whatsapp_delegate"
  run_python_package "⚙️/cdp-playground" "app"
}

case "$MODE" in
  all)
    run_secret_scan
    run_foundry
    run_python
    ;;
  secrets)
    run_secret_scan
    ;;
  foundry)
    run_foundry
    ;;
  python)
    run_python
    ;;
  *)
    echo "Usage: $0 [all|secrets|foundry|python]" >&2
    exit 2
    ;;
esac

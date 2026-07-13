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
  forge test
  popd >/dev/null
}

run_python_package() {
  local package_dir="$1"
  local compile_paths="$2"
  local test_dir="${3:-}"

  echo "== Python package: $package_dir =="
  pushd "$ROOT_DIR/$package_dir" >/dev/null
  uv sync --frozen
  # Intentional word splitting: compile paths are repo-local paths without spaces.
  # shellcheck disable=SC2086
  uv run python -m compileall $compile_paths ${test_dir:+"$test_dir"}
  if [ -n "$test_dir" ]; then
    uv run python -m unittest discover -s "$test_dir"
  fi
  popd >/dev/null
}

run_python() {
  run_python_package "⚙️/tinker-delegate" "tinker_delegate" "tests"
  run_python_package "⚙️/tee-email-oracle" "email_oracle captcha-solver/captcha_solver" "tests"
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

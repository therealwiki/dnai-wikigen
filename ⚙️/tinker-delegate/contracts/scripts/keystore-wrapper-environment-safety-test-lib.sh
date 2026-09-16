#!/usr/bin/env bash

# Focused integration KAT for every post-deploy wrapper that can reach the
# encrypted Foundry account. This source-only test library never invokes Forge,
# Cast, Node, a wallet, or an RPC; fake tools prove failures precede that edge.

assert_keystore_wrapper_environment_safety() (
  set -euo pipefail
  umask 077

  local wrapper="$1"
  shift
  local expected_switches="$*"
  local script_dir
  local production_helper
  local helper_source_line
  local dotenv_load_line
  local finalize_line
  local next_authority_line
  local test_root
  local test_wrapper
  local test_helper
  local test_home
  local fixture_root=""
  local external_root=""
  local fake_bin
  local tool_sentinel
  local hook_sentinel
  local custody_sentinel
  local status

  script_dir="$(cd "$(dirname "$wrapper")" && pwd)"
  production_helper="$script_dir/keystore-deployment-environment.sh"
  if [ ! -f "$production_helper" ]; then
    echo "Missing shared keystore deployment environment helper." >&2
    exit 1
  fi
  /bin/bash -n "$production_helper"
  /bin/bash -n "$wrapper"

  if [ "$(sed -n '1p' "$wrapper")" != '#!/bin/bash -p' ] \
    || ! grep -Fq 'ROOT_DIR="$(builtin cd -P -- "$DNAI_RELEASE_WRAPPER_DIR/../../../.." && builtin pwd -P)"' "$wrapper" \
    || ! grep -Fxq '. /dev/fd/9' "$wrapper" \
    || ! grep -Fq 'DNAI_KEYSTORE_HELPER_FD_IDENTITY=' "$wrapper" \
    || ! grep -Fxq 'dnai_load_keystore_deployment_dotenv "$ROOT_DIR/.env"' "$wrapper" \
    || ! grep -Fxq "dnai_finalize_keystore_deployment_environment $expected_switches" "$wrapper" \
    || grep -Fq '. "$ROOT_DIR/.env"' "$wrapper" \
    || grep -Eq -- '(^|[[:space:]])--private-key([[:space:]]|$)' "$wrapper" \
    || ! grep -Eq -- '--account[[:space:]]+dev([[:space:]\\]|$)' "$wrapper"; then
    echo "Release wrapper does not enforce the protected-shell, data-only dotenv, encrypted-keystore boundary: $wrapper" >&2
    exit 1
  fi

  helper_source_line="$(grep -n -m1 '^\. /dev/fd/9$' "$wrapper" | cut -d: -f1)"
  dotenv_load_line="$(grep -n -m1 '^dnai_load_keystore_deployment_dotenv "\$ROOT_DIR/\.env"$' "$wrapper" | cut -d: -f1)"
  finalize_line="$(grep -n -m1 '^dnai_finalize_keystore_deployment_environment ' "$wrapper" | cut -d: -f1)"
  next_authority_line="$(grep -n -m1 '^\. "\$CONTRACTS_DIR/scripts/release-ceremony-paths\.sh"$' "$wrapper" | cut -d: -f1 || true)"
  if [ -z "$next_authority_line" ]; then
    next_authority_line="$(grep -n -m1 '^for required in forge cast jq git node; do$' "$wrapper" | cut -d: -f1)"
  fi
  if [ -z "$helper_source_line" ] \
    || [ -z "$dotenv_load_line" ] \
    || [ -z "$finalize_line" ] \
    || [ -z "$next_authority_line" ] \
    || [ "$helper_source_line" -ge "$dotenv_load_line" ] \
    || [ "$finalize_line" -le "$dotenv_load_line" ] \
    || [ "$finalize_line" -ge "$next_authority_line" ]; then
    echo "Keystore capture, data-only dotenv loading, and finalization are not ordered before authority actions: $wrapper" >&2
    exit 1
  fi

  test_root="$(mktemp -d "${TMPDIR:-/tmp}/dnai-keystore-wrapper-kat.XXXXXX")"
  trap 'rm -rf -- "$test_root"; if [ -n "$external_root" ]; then rm -rf -- "$external_root"; fi' EXIT HUP INT TERM
  test_wrapper="$test_root/⚙️/tinker-delegate/contracts/scripts/$(basename "$wrapper")"
  test_helper="${test_wrapper%/*}/keystore-deployment-environment.sh"
  test_home="$test_root/home"
  fake_bin="$test_root/bin"
  tool_sentinel="$test_root/forbidden-tool-invocation"
  hook_sentinel="$test_root/startup-hook-invocation"
  custody_sentinel="$test_root/custody-bypass-invocation"
  mkdir -p "${test_wrapper%/*}" "$test_home" "$fake_bin"
  cp "$wrapper" "$test_wrapper"
  cp "$production_helper" "$test_helper"

  for tool_name in bash dirname forge cast node; do
    printf '%s\n' \
      '#!/bin/bash' \
      ': > "$DNAI_FORBIDDEN_TOOL_SENTINEL"' \
      'exit 97' > "$fake_bin/$tool_name"
    chmod 0700 "$fake_bin/$tool_name"
  done

  run_helper_switch_probe() {
    local label="$1"
    local file_value="$2"
    local expected_value="$3"
    local actual_value
    shift 3

    : > "$test_root/.env"
    if [ "$file_value" != "unset" ]; then
      printf 'BROADCAST=%s\n' "$file_value" > "$test_root/.env"
    fi
    actual_value="$(env -i \
      PATH="/usr/bin:/bin" \
      HOME="$test_home" \
      "$@" \
      /bin/bash -p -c '
        set -euo pipefail
        . "$1"
        dnai_load_keystore_deployment_dotenv "$2"
        dnai_finalize_keystore_deployment_environment BROADCAST
        printf "%s" "$BROADCAST"
      ' _ "$test_helper" "$test_root/.env")"
    if [ "$actual_value" != "$expected_value" ]; then
      echo "Release-wrapper BROADCAST precedence KAT failed: $label $wrapper" >&2
      exit 1
    fi
  }

  run_helper_switch_probe caller_true_over_file_false false true BROADCAST=true
  run_helper_switch_probe caller_false_over_file_true true false BROADCAST=false
  run_helper_switch_probe unset_caller_inherits_file true true
  run_helper_switch_probe no_file_value_defaults_false unset false

  printf '%s\n' \
    'TINKER_ARENA_CANDIDATE_INGRESS_PRIVATE_KEY_HEX=file-purpose-value' \
    'TINKER_COMPUTE_WORKLOAD_INGRESS_PRIVATE_KEY_HEX=file-purpose-value' > "$test_root/.env"
  env -i \
    PATH="/usr/bin:/bin" \
    HOME="$test_home" \
    TINKER_ARENA_CANDIDATE_INGRESS_PRIVATE_KEY_HEX=caller-purpose-value \
    TINKER_COMPUTE_WORKLOAD_INGRESS_PRIVATE_KEY_HEX=caller-purpose-value \
    /bin/bash -p -c '
      set -euo pipefail
      . "$1"
      dnai_load_keystore_deployment_dotenv "$2"
      [ "${TINKER_ARENA_CANDIDATE_INGRESS_PRIVATE_KEY_HEX+x}" != x ]
      [ "${TINKER_COMPUTE_WORKLOAD_INGRESS_PRIVATE_KEY_HEX+x}" != x ]
    ' _ "$test_helper" "$test_root/.env"

  if [ "$expected_switches" = "BROADCAST VERIFY" ]; then
    run_helper_verify_probe() {
      local label="$1"
      local file_value="$2"
      local expected_value="$3"
      local actual_value
      shift 3

      : > "$test_root/.env"
      if [ "$file_value" != "unset" ]; then
        printf 'VERIFY=%s\n' "$file_value" > "$test_root/.env"
      fi
      actual_value="$(env -i PATH="/usr/bin:/bin" HOME="$test_home" "$@" \
        /bin/bash -p -c '
          set -euo pipefail
          . "$1"
          dnai_load_keystore_deployment_dotenv "$2"
          dnai_finalize_keystore_deployment_environment VERIFY
          printf "%s" "$VERIFY"
        ' _ "$test_helper" "$test_root/.env")"
      if [ "$actual_value" != "$expected_value" ]; then
        echo "Fresh-wrapper VERIFY precedence KAT failed: $label $wrapper" >&2
        exit 1
      fi
    }
    run_helper_verify_probe caller_true_over_file_false false true VERIFY=true
    run_helper_verify_probe caller_false_over_file_true true false VERIFY=false
    run_helper_verify_probe unset_caller_inherits_file true true
    run_helper_verify_probe no_file_value_defaults_false unset false

    printf 'BROADCAST=false\nVERIFY=false\n' > "$test_root/.env"
    set +e
    env -i PATH="/usr/bin:/bin" HOME="$test_home" VERIFY= \
      /bin/bash -p -c '
        set -euo pipefail
        . "$1"
        dnai_load_keystore_deployment_dotenv "$2"
        dnai_finalize_keystore_deployment_environment BROADCAST VERIFY
      ' _ "$test_helper" "$test_root/.env" >/dev/null 2>"$test_root/empty-verify.err"
    status=$?
    set -e
    if [ "$status" -eq 0 ] || ! grep -Fxq 'VERIFY must be true or false.' "$test_root/empty-verify.err"; then
      echo "Explicit empty VERIFY did not fail closed: $wrapper" >&2
      exit 1
    fi

    : > "$test_root/.env"
    set +e
    env -i PATH="$fake_bin:/usr/bin:/bin" HOME="$test_home" DNAI_FORBIDDEN_TOOL_SENTINEL="$tool_sentinel" \
      "$test_wrapper" >/dev/null 2>"$test_root/manifest-default.err"
    status=$?
    set -e
    if [ "$status" -eq 0 ] \
      || ! grep -Fxq 'DEPLOYMENT_MANIFEST_PATH is required and must name a new external immutable receipt.' "$test_root/manifest-default.err" \
      || [ -e "$tool_sentinel" ]; then
      echo "Fresh deployment did not reject an empty manifest path before tools: $wrapper" >&2
      exit 1
    fi

    fixture_root="$(builtin cd -P -- "$test_root" && builtin pwd -P)"
    printf 'DEPLOYMENT_MANIFEST_PATH=%s\n' "$fixture_root/inside-manifest.json" > "$test_root/.env"
    set +e
    env -i PATH="$fake_bin:/usr/bin:/bin" HOME="$test_home" DNAI_FORBIDDEN_TOOL_SENTINEL="$tool_sentinel" \
      "$test_wrapper" >/dev/null 2>"$test_root/manifest-inside.err"
    status=$?
    set -e
    if [ "$status" -eq 0 ] \
      || ! grep -Fxq 'DEPLOYMENT_MANIFEST_PATH must be outside the release source checkout.' "$test_root/manifest-inside.err" \
      || [ -e "$tool_sentinel" ]; then
      echo "Fresh deployment did not reject an in-checkout manifest path before tools: $wrapper" >&2
      exit 1
    fi

    external_root="$(mktemp -d "${TMPDIR:-/tmp}/dnai-external-manifest-kat.XXXXXX")"
    external_root="$(builtin cd -P -- "$external_root" && builtin pwd -P)"
    chmod 0700 "$external_root"
    printf 'DEPLOYMENT_MANIFEST_PATH=%s\n' "$external_root/base-sepolia.json" > "$test_root/.env"
    set +e
    env -i PATH="$fake_bin:/usr/bin:/bin" HOME="$test_home" DNAI_FORBIDDEN_TOOL_SENTINEL="$tool_sentinel" \
      "$test_wrapper" >/dev/null 2>"$test_root/manifest-external.err"
    status=$?
    set -e
    if [ "$status" -eq 0 ] \
      || ! grep -Fxq 'BASE_SEPOLIA_RPC_URL is required; no deployment identity or trust root is inferred.' "$test_root/manifest-external.err" \
      || [ -e "$tool_sentinel" ] \
      || [ -e "$external_root/base-sepolia.json" ] \
      || [ -e "$fixture_root/inside-manifest.json" ]; then
      echo "Fresh deployment did not accept a private external create-only manifest path cleanly: $wrapper" >&2
      exit 1
    fi

    printf 'DEPLOYMENT_MANIFEST_PATH=\n' > "$test_root/.env"
    set +e
    env -i PATH="$fake_bin:/usr/bin:/bin" HOME="$test_home" DNAI_FORBIDDEN_TOOL_SENTINEL="$tool_sentinel" \
      DEPLOYMENT_MANIFEST_PATH="$external_root/caller-authoritative.json" \
      "$test_wrapper" >/dev/null 2>"$test_root/manifest-caller-authoritative.err"
    status=$?
    set -e
    if [ "$status" -eq 0 ] \
      || ! grep -Fxq 'BASE_SEPOLIA_RPC_URL is required; no deployment identity or trust root is inferred.' "$test_root/manifest-caller-authoritative.err" \
      || [ -e "$tool_sentinel" ] \
      || [ -e "$external_root/caller-authoritative.json" ]; then
      echo "Explicit caller manifest path did not override an empty dotenv record before tools: $wrapper" >&2
      exit 1
    fi

    printf 'DEPLOYMENT_MANIFEST_PATH=%s\n' "$external_root/file-default.json" > "$test_root/.env"
    set +e
    env -i PATH="$fake_bin:/usr/bin:/bin" HOME="$test_home" DNAI_FORBIDDEN_TOOL_SENTINEL="$tool_sentinel" \
      DEPLOYMENT_MANIFEST_PATH= \
      "$test_wrapper" >/dev/null 2>"$test_root/manifest-caller-empty.err"
    status=$?
    set -e
    if [ "$status" -eq 0 ] \
      || ! grep -Fxq 'DEPLOYMENT_MANIFEST_PATH is required and must name a new external immutable receipt.' "$test_root/manifest-caller-empty.err" \
      || [ -e "$tool_sentinel" ] \
      || [ -e "$external_root/file-default.json" ]; then
      echo "Explicit empty caller manifest path did not fail closed over a dotenv default: $wrapper" >&2
      exit 1
    fi
  fi

  printf 'BROADCAST=false\n' > "$test_root/.env"
  set +e
  env -i PATH="/usr/bin:/bin" HOME="$test_home" BROADCAST= \
    /bin/bash -p -c '
      set -euo pipefail
      . "$1"
      dnai_load_keystore_deployment_dotenv "$2"
      dnai_finalize_keystore_deployment_environment BROADCAST
    ' _ "$test_helper" "$test_root/.env" >/dev/null 2>"$test_root/empty.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] || ! grep -Fxq 'BROADCAST must be true or false.' "$test_root/empty.err"; then
    echo "Explicit empty BROADCAST did not fail closed: $wrapper" >&2
    exit 1
  fi

  : > "$test_root/.env"
  set +e
  env -i \
    PATH="$fake_bin:/usr/bin:/bin" \
    HOME="$test_home" \
    DNAI_FORBIDDEN_TOOL_SENTINEL="$tool_sentinel" \
    PRIVATE_KEY=forbidden-probe-value \
    "$test_wrapper" >/dev/null 2>"$test_root/caller-key.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] \
    || ! grep -Fxq 'PRIVATE_KEY is forbidden for Base Sepolia release operations; use only the encrypted Foundry account dev.' "$test_root/caller-key.err" \
    || grep -Fq 'forbidden-probe-value' "$test_root/caller-key.err" \
    || [ -e "$tool_sentinel" ]; then
    echo "Caller raw-key input did not fail before PATH tools: $wrapper" >&2
    exit 1
  fi

  for raw_case_name in private_key Private_Key judge_private_key kms_private_key Wallet_Private_Key QVL_PRIVATE_KEY DEPLOYMENT_MNEMONIC_FILE; do
    set +e
    env -i \
      PATH="$fake_bin:/usr/bin:/bin" \
      HOME="$test_home" \
      DNAI_FORBIDDEN_TOOL_SENTINEL="$tool_sentinel" \
      "$raw_case_name=forbidden-probe-value" \
      "$test_wrapper" >/dev/null 2>"$test_root/case-$raw_case_name.err"
    status=$?
    set -e
    if [ "$status" -eq 0 ] \
      || ! grep -Fxq "$raw_case_name is forbidden for Base Sepolia release operations; use only the encrypted Foundry account dev." "$test_root/case-$raw_case_name.err" \
      || grep -Fq 'forbidden-probe-value' "$test_root/case-$raw_case_name.err" \
      || [ -e "$tool_sentinel" ]; then
      echo "Case-variant raw-key input did not fail before PATH tools: $raw_case_name $wrapper" >&2
      exit 1
    fi
  done

  mkdir -p "$test_root/perl-hook"
  printf '%s\n' \
    'BEGIN { open(my $fh, ">", $ENV{DNAI_PERL_HOOK_SENTINEL}) or die; close($fh); }' \
    '1;' > "$test_root/perl-hook/DnaiProbe.pm"
  set +e
  env -i \
    PATH="$fake_bin:/usr/bin:/bin" \
    HOME="$test_home" \
    PERL5LIB="$test_root/perl-hook" \
    PERL5OPT=-MDnaiProbe \
    DNAI_PERL_HOOK_SENTINEL="$custody_sentinel" \
    PRIVATE_KEY=forbidden-probe-value \
    "$test_wrapper" >/dev/null 2>"$test_root/perl-hook.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] \
    || [ -e "$custody_sentinel" ] \
    || ! grep -Fxq 'PRIVATE_KEY is forbidden for Base Sepolia release operations; use only the encrypted Foundry account dev.' "$test_root/perl-hook.err"; then
    echo "Helper identity probes did not scrub Perl startup authority before raw-key rejection: $wrapper" >&2
    exit 1
  fi

  printf 'MNEMONIC=%s\n' forbidden-probe-value > "$test_root/.env"
  set +e
  env -i \
    PATH="$fake_bin:/usr/bin:/bin" \
    HOME="$test_home" \
    DNAI_FORBIDDEN_TOOL_SENTINEL="$tool_sentinel" \
    "$test_wrapper" >/dev/null 2>"$test_root/file-mnemonic.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] \
    || ! grep -Fxq 'MNEMONIC is forbidden for Base Sepolia release operations; use only the encrypted Foundry account dev.' "$test_root/file-mnemonic.err" \
    || grep -Fq 'forbidden-probe-value' "$test_root/file-mnemonic.err" \
    || [ -e "$tool_sentinel" ]; then
    echo ".env mnemonic input did not fail before PATH tools: $wrapper" >&2
    exit 1
  fi

  printf 'private_key=%s\n' forbidden-probe-value > "$test_root/.env"
  set +e
  env -i PATH="$fake_bin:/usr/bin:/bin" HOME="$test_home" DNAI_FORBIDDEN_TOOL_SENTINEL="$tool_sentinel" \
    "$test_wrapper" >/dev/null 2>"$test_root/file-case-key.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] \
    || ! grep -Fxq 'private_key is forbidden for Base Sepolia release operations; use only the encrypted Foundry account dev.' "$test_root/file-case-key.err" \
    || [ -e "$tool_sentinel" ]; then
    echo "Case-variant .env raw key did not fail before PATH tools: $wrapper" >&2
    exit 1
  fi

  printf '%s\n' \
    'PRIVATE_KEY=$(forge --version)' \
    'unset PRIVATE_KEY' > "$test_root/.env"
  set +e
  env -i \
    PATH="$fake_bin:/usr/bin:/bin" \
    HOME="$test_home" \
    DNAI_FORBIDDEN_TOOL_SENTINEL="$tool_sentinel" \
    "$test_wrapper" >/dev/null 2>"$test_root/transient-key.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] \
    || ! grep -Fxq 'PRIVATE_KEY is forbidden for Base Sepolia release operations; use only the encrypted Foundry account dev.' "$test_root/transient-key.err" \
    || [ -e "$tool_sentinel" ]; then
    echo "Transient/self-erasing .env raw-key syntax was not rejected as data before tools: $wrapper" >&2
    exit 1
  fi

  mkdir -p "$test_root/attacker-contracts/scripts"
  printf '%s\n' '#!/bin/bash' ': > "$DNAI_CUSTODY_SENTINEL"' > "$test_root/attacker-contracts/scripts/release-ceremony-paths.sh"
  printf 'CONTRACTS_DIR=%s\n' "$test_root/attacker-contracts" > "$test_root/.env"
  set +e
  env -i PATH="$fake_bin:/usr/bin:/bin" HOME="$test_home" DNAI_CUSTODY_SENTINEL="$custody_sentinel" \
    "$test_wrapper" >/dev/null 2>"$test_root/internal-clobber.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] \
    || [ -e "$custody_sentinel" ] \
    || ! grep -Fxq 'CONTRACTS_DIR is not an approved deployment .env input and would overwrite wrapper state.' "$test_root/internal-clobber.err"; then
    echo "Data-only dotenv allowed bootstrap path clobber: $wrapper" >&2
    exit 1
  fi

  printf ': > "$DNAI_STARTUP_HOOK_SENTINEL"\nunset PRIVATE_KEY\n' > "$test_root/bash-env-hook"
  set +e
  env -i \
    PATH="$fake_bin:/usr/bin:/bin" \
    HOME="$test_home" \
    BASH_ENV="$test_root/bash-env-hook" \
    DNAI_STARTUP_HOOK_SENTINEL="$hook_sentinel" \
    PRIVATE_KEY=forbidden-probe-value \
    "$test_wrapper" >/dev/null 2>"$test_root/protected-bash-env.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] \
    || [ -e "$hook_sentinel" ] \
    || ! grep -Fxq 'Shell startup, imported-function, and native-loader control variables are forbidden for release wrappers.' "$test_root/protected-bash-env.err"; then
    echo "Protected direct entry did not ignore and reject BASH_ENV: $wrapper" >&2
    exit 1
  fi

  set +e
  env -i \
    PATH="$fake_bin:/usr/bin:/bin" \
    HOME="$test_home" \
    DNAI_STARTUP_HOOK_SENTINEL="$hook_sentinel" \
    'BASH_FUNC_dirname%%=() { : > "$DNAI_STARTUP_HOOK_SENTINEL"; /usr/bin/dirname "$@"; }' \
    "$test_wrapper" >/dev/null 2>"$test_root/imported-function.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] \
    || [ -e "$hook_sentinel" ] \
    || ! grep -Fxq 'Shell startup, imported-function, and native-loader control variables are forbidden for release wrappers.' "$test_root/imported-function.err"; then
    echo "Imported dirname function ran before the protected entry guard: $wrapper" >&2
    exit 1
  fi

  set +e
  env -i \
    PATH="$fake_bin:/usr/bin:/bin" \
    HOME="$test_home" \
    SHELLOPTS=xtrace \
    DNAI_TRACE_SECRET=must-not-appear-in-trace \
    "$test_wrapper" >/dev/null 2>"$test_root/inherited-xtrace.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] \
    || grep -Fq 'must-not-appear-in-trace' "$test_root/inherited-xtrace.err" \
    || ! grep -Fxq 'Shell startup, imported-function, and native-loader control variables are forbidden for release wrappers.' "$test_root/inherited-xtrace.err"; then
    echo "Inherited xtrace was not ignored and rejected without value disclosure: $wrapper" >&2
    exit 1
  fi

  # This negative control documents the trusted parent-process boundary: plain
  # /bin/bash reads BASH_ENV before wrapper code. The wrapper rejects non-p mode,
  # but it cannot undo a pre-entry hook. Only direct or /bin/bash -p entry is safe.
  set +e
  env -i \
    PATH="/usr/bin:/bin" \
    HOME="$test_home" \
    BASH_ENV="$test_root/bash-env-hook" \
    DNAI_STARTUP_HOOK_SENTINEL="$hook_sentinel" \
    /bin/bash "$test_wrapper" >/dev/null 2>"$test_root/plain-bash.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] \
    || [ ! -e "$hook_sentinel" ] \
    || ! grep -Fq 'plain bash invocation is unsupported' "$test_root/plain-bash.err"; then
    echo "Plain-bash negative control no longer demonstrates the documented parent boundary: $wrapper" >&2
    exit 1
  fi

  : > "$test_root/.env"
  mv "$test_helper" "$test_helper.trusted"
  printf '%s\n' ': > "$DNAI_CUSTODY_SENTINEL"' > "$test_helper.malicious"
  ln -s "${test_helper##*/}.malicious" "$test_helper"
  set +e
  env -i PATH="$fake_bin:/usr/bin:/bin" HOME="$test_home" DNAI_CUSTODY_SENTINEL="$custody_sentinel" \
    "$test_wrapper" >/dev/null 2>"$test_root/helper-symlink.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] || [ -e "$custody_sentinel" ] \
    || ! grep -Fxq 'The keystore environment helper must be the canonical readable non-symlink regular file.' "$test_root/helper-symlink.err"; then
    echo "Helper symlink custody KAT failed: $wrapper" >&2
    exit 1
  fi
  rm "$test_helper"
  mv "$test_helper.trusted" "$test_helper"

  mv "$test_helper" "$test_helper.trusted"
  ln "$test_helper.trusted" "$test_helper"
  set +e
  env -i PATH="$fake_bin:/usr/bin:/bin" HOME="$test_home" "$test_wrapper" >/dev/null 2>"$test_root/helper-hardlink.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] \
    || ! grep -Fxq 'The keystore environment helper must be owned by the invoking user, have one link, and not be group/world writable.' "$test_root/helper-hardlink.err"; then
    echo "Helper hardlink custody KAT failed: $wrapper" >&2
    exit 1
  fi
  rm "$test_helper"
  mv "$test_helper.trusted" "$test_helper"

  chmod 0664 "$test_helper"
  set +e
  env -i PATH="$fake_bin:/usr/bin:/bin" HOME="$test_home" "$test_wrapper" >/dev/null 2>"$test_root/helper-mode.err"
  status=$?
  set -e
  chmod 0600 "$test_helper"
  if [ "$status" -eq 0 ] \
    || ! grep -Fxq 'The keystore environment helper must be owned by the invoking user, have one link, and not be group/world writable.' "$test_root/helper-mode.err"; then
    echo "Helper writable-mode custody KAT failed: $wrapper" >&2
    exit 1
  fi

  chmod 0777 "${test_wrapper%/*}"
  set +e
  env -i PATH="$fake_bin:/usr/bin:/bin" HOME="$test_home" "$test_wrapper" >/dev/null 2>"$test_root/helper-parent-mode.err"
  status=$?
  set -e
  chmod 0700 "${test_wrapper%/*}"
  if [ "$status" -eq 0 ] \
    || ! grep -Fxq 'The keystore helper directory must be canonical, invoking-user-owned, and not group/world writable.' "$test_root/helper-parent-mode.err"; then
    echo "Helper parent-directory custody KAT failed: $wrapper" >&2
    exit 1
  fi

  printf 'BROADCAST=false\n' > "$test_root/.env"
  chmod 0644 "$test_root/.env"
  set +e
  env -i PATH="$fake_bin:/usr/bin:/bin" HOME="$test_home" "$test_wrapper" >/dev/null 2>"$test_root/dotenv-mode.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] \
    || ! grep -Fxq '.env must be owned by the invoking user, have one link, and have exact mode 0600.' "$test_root/dotenv-mode.err"; then
    echo "Dotenv exact-mode custody KAT failed: $wrapper" >&2
    exit 1
  fi

  rm "$test_root/.env"
  ln -s "$test_root/missing-dotenv-target" "$test_root/.env"
  set +e
  env -i PATH="$fake_bin:/usr/bin:/bin" HOME="$test_home" "$test_wrapper" >/dev/null 2>"$test_root/dangling-dotenv.err"
  status=$?
  set -e
  if [ "$status" -eq 0 ] \
    || ! grep -Fxq '.env must not be a symbolic link, including a dangling link.' "$test_root/dangling-dotenv.err"; then
    echo "Dangling dotenv symlink KAT failed: $wrapper" >&2
    exit 1
  fi
)

#!/bin/bash -p
set +x
set -euo pipefail

case "$-" in
  *p*) ;;
  *)
    printf '%s\n' "release gates require the privileged-mode /bin/bash launcher" >&2
    exit 64
    ;;
esac

assert_plain_shell_startup_environment() {
  local name
  while IFS= read -r name; do
    case "$name" in
      BASH_ENV|ENV|BASHOPTS|SHELLOPTS|CDPATH|GLOBIGNORE|PS4|BASH_XTRACEFD|PROMPT_COMMAND|BASH_FUNC_*|NPM_CONFIG_*|npm_config_*|npm_execpath|npm_node_execpath|INIT_CWD|PERL5OPT|PERL5LIB|NODE_OPTIONS|NODE_PATH|NODE_USE_ENV_PROXY|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|SSL_CERT_FILE|SSL_CERT_DIR|SSLKEYLOGFILE|LD_*|DYLD_*|GLIBC_TUNABLES)
        printf '%s\n' "release gates reject observable shell, interpreter, Node, TLS, and native-loader hooks: $name" >&2
        return 64
        ;;
    esac
  done < <(compgen -e)
}

assert_plain_shell_startup_environment
hash -r

# A native constructor injected by a hostile parent process can run before any
# shell source line and erase its loader variable. Generic CI therefore relies
# on the reviewed GitHub runner launch boundary to start this script without
# native-loader injection; the in-script checks reject every observable hook.

NAMED_SCRIPT_PATH="${BASH_SOURCE[0]}"
HEAD_MATERIALIZED_LAUNCH=false
MATERIALIZED_ROOT_ARGUMENT=""
MATERIALIZED_HEAD_ARGUMENT=""
MATERIALIZED_SOURCE_TEMP=""
if [[ "${1:-}" == "--head-materialized-root" ]]; then
  if [[ "$#" -ne 4 \
    || ! "${3:-}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "head-materialized release gate usage requires ROOT EXACT_HEAD MODE" >&2
    exit 64
  fi
  HEAD_MATERIALIZED_LAUNCH=true
  MATERIALIZED_ROOT_ARGUMENT="$2"
  MATERIALIZED_HEAD_ARGUMENT="$3"
  MODE="$4"
else
  MODE="${1:-all}"
fi
if [[ -L "$NAMED_SCRIPT_PATH" ]]; then
  echo "release gate wrapper must not be invoked through a symlink" >&2
  exit 64
fi
CANONICAL_SCRIPT_PATH="$(/usr/bin/env -i \
  PATH=/usr/bin:/bin \
  LANG=C \
  LC_ALL=C \
  /bin/realpath "$NAMED_SCRIPT_PATH")"
SCRIPT_PLATFORM="$(/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/uname -s)"
SCRIPT_EXPECTED_UID="$(/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/id -u)"
case "$SCRIPT_PLATFORM" in
  Darwin)
    SCRIPT_METADATA="$(/usr/bin/env -i PATH=/usr/bin:/bin \
      /usr/bin/stat -f '%l:%u:%Lp' "$CANONICAL_SCRIPT_PATH")"
    ;;
  Linux)
    SCRIPT_METADATA="$(/usr/bin/env -i PATH=/usr/bin:/bin \
      /usr/bin/stat -Lc '%h:%u:%a' -- "$CANONICAL_SCRIPT_PATH")"
    ;;
  *)
    echo "release gate wrapper requires the reviewed Darwin or Linux host family" >&2
    exit 64
    ;;
esac
if [[ ! -f "$CANONICAL_SCRIPT_PATH" || -L "$CANONICAL_SCRIPT_PATH" \
  || "$SCRIPT_METADATA" != "1:${SCRIPT_EXPECTED_UID}:755" ]]; then
  echo "release gate wrapper is not one canonical protected regular file" >&2
  exit 64
fi
if [[ "$HEAD_MATERIALIZED_LAUNCH" == "true" ]]; then
  ORIGINAL_SOURCE_ROOT="$(/usr/bin/env -i \
    PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    /bin/realpath "$MATERIALIZED_ROOT_ARGUMENT")"
  if [[ "$ORIGINAL_SOURCE_ROOT" != "$MATERIALIZED_ROOT_ARGUMENT" \
    || ! -d "$ORIGINAL_SOURCE_ROOT" || -L "$ORIGINAL_SOURCE_ROOT" ]]; then
    echo "head-materialized release gate requires one canonical source root" >&2
    exit 64
  fi
  MATERIALIZED_ACTUAL_HEAD="$(/usr/bin/env -i \
    HOME="$ORIGINAL_SOURCE_ROOT" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 GIT_PAGER=cat \
    /usr/bin/git --no-replace-objects \
      -c core.hooksPath=/dev/null -c core.worktree="$ORIGINAL_SOURCE_ROOT" \
      -C "$ORIGINAL_SOURCE_ROOT" rev-parse --verify HEAD)"
  MATERIALIZED_WRAPPER_TREE="$(/usr/bin/env -i \
    HOME="$ORIGINAL_SOURCE_ROOT" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 GIT_PAGER=cat \
    /usr/bin/git --no-replace-objects \
      -c core.hooksPath=/dev/null -c core.worktree="$ORIGINAL_SOURCE_ROOT" \
      -C "$ORIGINAL_SOURCE_ROOT" ls-tree "$MATERIALIZED_HEAD_ARGUMENT" -- \
        scripts/verify-local.sh)"
  MATERIALIZED_WRAPPER_OID="$(/usr/bin/env -i \
    HOME="$ORIGINAL_SOURCE_ROOT" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git --no-replace-objects \
      -c core.hooksPath=/dev/null -C "$ORIGINAL_SOURCE_ROOT" \
      hash-object --no-filters -- "$CANONICAL_SCRIPT_PATH")"
  if [[ "$MATERIALIZED_ACTUAL_HEAD" != "$MATERIALIZED_HEAD_ARGUMENT" \
    || ! "$MATERIALIZED_WRAPPER_TREE" \
      =~ ^100755\ blob\ ([0-9a-f]{40})$'\t'scripts/verify-local\.sh$ \
    || "$MATERIALIZED_WRAPPER_OID" != "${BASH_REMATCH[1]:-}" ]]; then
    echo "head-materialized wrapper bytes do not match the exact source commit" >&2
    exit 64
  fi

  # The caller checkout is only an object source. Before any repository
  # consumer executes, clone exactly the reviewed commit into a fresh private
  # root with global/system configuration, hooks, and the working tree
  # excluded. This prevents ignored credentials, forged index metadata, and
  # post-checkout mutations from becoming inputs to any gate mode.
  MATERIALIZED_SOURCE_WORKTREE_CONFIG="$(/usr/bin/env -i \
    HOME="$ORIGINAL_SOURCE_ROOT" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null \
      -C "$ORIGINAL_SOURCE_ROOT" rev-parse --git-path config.worktree)"
  if [[ "$MATERIALIZED_SOURCE_WORKTREE_CONFIG" != /* ]]; then
    MATERIALIZED_SOURCE_WORKTREE_CONFIG="$ORIGINAL_SOURCE_ROOT/$MATERIALIZED_SOURCE_WORKTREE_CONFIG"
  fi
  MATERIALIZED_SOURCE_CONFIG_SCOPES=(--local)
  if [[ -e "$MATERIALIZED_SOURCE_WORKTREE_CONFIG" \
    || -L "$MATERIALIZED_SOURCE_WORKTREE_CONFIG" ]]; then
    if [[ ! -f "$MATERIALIZED_SOURCE_WORKTREE_CONFIG" \
      || -L "$MATERIALIZED_SOURCE_WORKTREE_CONFIG" ]]; then
      echo "head-materialized release gate rejects an aliased worktree config" >&2
      exit 65
    fi
    MATERIALIZED_SOURCE_CONFIG_SCOPES+=(--worktree)
  fi
  for config_scope in "${MATERIALIZED_SOURCE_CONFIG_SCOPES[@]}"; do
    if ! /usr/bin/env -i \
        HOME="$ORIGINAL_SOURCE_ROOT" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 \
        /usr/bin/git -C "$ORIGINAL_SOURCE_ROOT" config "$config_scope" \
          --no-includes --name-only --null --list \
      | while IFS= read -r -d '' config_name; do
          config_name_lower="$(/usr/bin/printf '%s' "$config_name" \
            | /usr/bin/tr '[:upper:]' '[:lower:]')"
          case "$config_name_lower" in
            include.*|includeif.*|core.fsmonitor|core.worktree|core.hookspath|core.attributesfile|core.sshcommand|core.alternaterefscommand|filter.*|diff.external|diff.*.command|merge.*.driver|uploadpack.*|receive.*|remote.*.uploadpack|remote.*.promisor|remote.*.partialclonefilter|extensions.partialclone|protocol.*|http.*.extraheader|http.*.proxy|credential.*|url.*.insteadof)
              exit 1
              ;;
          esac
        done; then
      echo "head-materialized release gate rejects unsafe source Git configuration" >&2
      exit 65
    fi
  done
  MATERIALIZED_SOURCE_ALTERNATES="$(/usr/bin/env -i \
    HOME="$ORIGINAL_SOURCE_ROOT" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 \
    /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null \
      -C "$ORIGINAL_SOURCE_ROOT" rev-parse --git-path \
        objects/info/alternates)"
  if [[ "$MATERIALIZED_SOURCE_ALTERNATES" != /* ]]; then
    MATERIALIZED_SOURCE_ALTERNATES="$ORIGINAL_SOURCE_ROOT/$MATERIALIZED_SOURCE_ALTERNATES"
  fi
  if [[ -e "$MATERIALIZED_SOURCE_ALTERNATES" \
    || -L "$MATERIALIZED_SOURCE_ALTERNATES" ]]; then
    echo "head-materialized release gate rejects alternate source objects" >&2
    exit 65
  fi

  MATERIALIZED_SOURCE_TEMP="$(/bin/realpath \
    "$(/usr/bin/mktemp -d "/tmp/dnai-exact-head-source.XXXXXX")")"
  /bin/chmod 0700 "$MATERIALIZED_SOURCE_TEMP"
  /bin/mkdir -m 0700 \
    "$MATERIALIZED_SOURCE_TEMP/home" \
    "$MATERIALIZED_SOURCE_TEMP/tmp"
  trap '/bin/rm -rf -- "$MATERIALIZED_SOURCE_TEMP"' EXIT
  ROOT_DIR="$MATERIALIZED_SOURCE_TEMP/source"
  /usr/bin/env -i \
    HOME="$MATERIALIZED_SOURCE_TEMP/home" \
    PATH=/usr/bin:/bin \
    TMPDIR="$MATERIALIZED_SOURCE_TEMP/tmp" \
    LANG=C \
    LC_ALL=C \
    TZ=UTC \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 \
    GIT_NO_REPLACE_OBJECTS=1 \
    GIT_NO_LAZY_FETCH=1 \
    /usr/bin/git --no-replace-objects \
      -c core.hooksPath=/dev/null \
      -c protocol.file.allow=always \
      -c protocol.ext.allow=never \
      clone --no-local --no-hardlinks --no-checkout \
        --depth=1 --no-tags --single-branch -- \
        "$ORIGINAL_SOURCE_ROOT" "$ROOT_DIR"
  /bin/chmod 0700 "$ROOT_DIR"
  /usr/bin/env -i \
    HOME="$MATERIALIZED_SOURCE_TEMP/home" \
    PATH=/usr/bin:/bin \
    TMPDIR="$MATERIALIZED_SOURCE_TEMP/tmp" \
    LANG=C \
    LC_ALL=C \
    TZ=UTC \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 \
    GIT_NO_REPLACE_OBJECTS=1 \
    GIT_NO_LAZY_FETCH=1 \
    /usr/bin/git --no-replace-objects \
      -c core.fsmonitor=false \
      -c core.untrackedCache=false \
      -c core.hooksPath=/dev/null \
      -C "$ROOT_DIR" checkout --detach --force "$MATERIALIZED_HEAD_ARGUMENT"
  /usr/bin/env -i \
    HOME="$MATERIALIZED_SOURCE_TEMP/home" PATH=/usr/bin:/bin \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 \
    /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null \
      -C "$ROOT_DIR" remote remove origin
  MATERIALIZED_SOURCE_REFS="$(/usr/bin/env -i \
    HOME="$MATERIALIZED_SOURCE_TEMP/home" PATH=/usr/bin:/bin \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 \
    /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null \
      -C "$ROOT_DIR" for-each-ref --format='%(refname) %(objectname)')"
  while IFS=' ' read -r materialized_ref materialized_ref_sha; do
    [[ -n "$materialized_ref" ]] || continue
    if [[ "$materialized_ref" != refs/* \
      || "$materialized_ref_sha" != "$MATERIALIZED_HEAD_ARGUMENT" ]]; then
      echo "head-materialized source retained an unexpected ref" >&2
      exit 64
    fi
    /usr/bin/env -i \
      HOME="$MATERIALIZED_SOURCE_TEMP/home" PATH=/usr/bin:/bin \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 \
      /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null \
        -C "$ROOT_DIR" update-ref -d \
          "$materialized_ref" "$MATERIALIZED_HEAD_ARGUMENT"
  done <<< "$MATERIALIZED_SOURCE_REFS"
  if [[ -e "$ROOT_DIR/.git/objects/info/alternates" \
    || "$ROOT_DIR" != "$(/bin/realpath "$ROOT_DIR")" \
    || "$MATERIALIZED_HEAD_ARGUMENT" != "$(/usr/bin/env -i \
      HOME="$MATERIALIZED_SOURCE_TEMP/home" PATH=/usr/bin:/bin \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 \
      /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null \
        -C "$ROOT_DIR" rev-parse --verify HEAD)" \
    || "$(/usr/bin/env -i \
      HOME="$MATERIALIZED_SOURCE_TEMP/home" PATH=/usr/bin:/bin \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 \
      /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null \
        -C "$ROOT_DIR" rev-parse --is-shallow-repository)" != "true" \
    || "$(/usr/bin/env -i \
      HOME="$MATERIALIZED_SOURCE_TEMP/home" PATH=/usr/bin:/bin \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 \
      /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null \
        -C "$ROOT_DIR" rev-list --count HEAD)" != "1" \
    || -n "$(/usr/bin/env -i \
      HOME="$MATERIALIZED_SOURCE_TEMP/home" PATH=/usr/bin:/bin \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 \
      /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null \
        -C "$ROOT_DIR" for-each-ref --format='%(refname)')" \
    || ! -f "$ROOT_DIR/scripts/verify-local.sh" \
    || -L "$ROOT_DIR/scripts/verify-local.sh" ]]; then
    echo "head-materialized source is not one exact private commit tree" >&2
    exit 64
  fi
  if ! /usr/bin/cmp -s \
      "$CANONICAL_SCRIPT_PATH" "$ROOT_DIR/scripts/verify-local.sh"; then
    echo "head-materialized source is not one exact private commit tree" >&2
    exit 64
  fi
  BOOTSTRAP_HEAD_PROJECTOR="$ROOT_DIR/scripts/test-harness/exact-head-worktree-authority.mjs"
  case "$SCRIPT_PLATFORM" in
    Darwin)
      BOOTSTRAP_GATE_NODE="/opt/homebrew/Cellar/node/24.9.0/bin/node"
      if [[ ! -f "$BOOTSTRAP_GATE_NODE" || -L "$BOOTSTRAP_GATE_NODE" \
        || "$BOOTSTRAP_GATE_NODE" != "$(/bin/realpath "$BOOTSTRAP_GATE_NODE")" \
        || "$(/usr/bin/stat -f '%z:%l:%u:%Lp' "$BOOTSTRAP_GATE_NODE")" \
          != "64221968:1:${SCRIPT_EXPECTED_UID}:555" \
        || "$(/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
          /usr/bin/shasum -a 256 "$BOOTSTRAP_GATE_NODE")" \
          != "3e7673f6552cffd3f9eaa3bcb910198a4d0786e99bb861d24eb81cc3fce563e7  $BOOTSTRAP_GATE_NODE" ]]; then
        echo "head-materialized source projection requires the pinned Darwin Node" >&2
        exit 64
      fi
      BOOTSTRAP_PROJECTOR_SHA="$(/usr/bin/env -i \
        PATH=/usr/bin:/bin LANG=C LC_ALL=C \
        /usr/bin/shasum -a 256 "$BOOTSTRAP_HEAD_PROJECTOR")"
      BOOTSTRAP_PROJECTOR_SHA="${BOOTSTRAP_PROJECTOR_SHA%% *}"
      BOOTSTRAP_PROJECTOR_METADATA="$(/usr/bin/stat -f '%l:%u:%Lp' \
        "$BOOTSTRAP_HEAD_PROJECTOR")"
      ;;
    Linux)
      hash -r
      BOOTSTRAP_GATE_NODE="$(type -P node)"
      if [[ "$BOOTSTRAP_GATE_NODE" != /* \
        || ! -f "$BOOTSTRAP_GATE_NODE" || -L "$BOOTSTRAP_GATE_NODE" \
        || "$BOOTSTRAP_GATE_NODE" != "$(/usr/bin/readlink -f -- "$BOOTSTRAP_GATE_NODE")" \
        || "$(/usr/bin/stat -Lc '%h:%u:%a' -- "$BOOTSTRAP_GATE_NODE")" \
          != "1:${SCRIPT_EXPECTED_UID}:755" \
        || "$(/usr/bin/sha256sum -- "$BOOTSTRAP_GATE_NODE")" \
          != "3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327  $BOOTSTRAP_GATE_NODE" ]]; then
        echo "head-materialized source projection requires the pinned Linux Node" >&2
        exit 64
      fi
      BOOTSTRAP_PROJECTOR_SHA="$(/usr/bin/sha256sum -- \
        "$BOOTSTRAP_HEAD_PROJECTOR")"
      BOOTSTRAP_PROJECTOR_SHA="${BOOTSTRAP_PROJECTOR_SHA%% *}"
      BOOTSTRAP_PROJECTOR_METADATA="$(/usr/bin/stat -Lc '%h:%u:%a' -- \
        "$BOOTSTRAP_HEAD_PROJECTOR")"
      ;;
  esac
  if [[ ! -f "$BOOTSTRAP_HEAD_PROJECTOR" \
    || -L "$BOOTSTRAP_HEAD_PROJECTOR" \
    || "$BOOTSTRAP_HEAD_PROJECTOR" != "$(/bin/realpath "$BOOTSTRAP_HEAD_PROJECTOR")" \
    || "$BOOTSTRAP_PROJECTOR_METADATA" != "1:${SCRIPT_EXPECTED_UID}:644" \
    || "$BOOTSTRAP_PROJECTOR_SHA" \
      != "54c88fc8667310ad4b46f67488d8ee5926b6972c42d34fcad20dce199f2ec367" ]]; then
    echo "head-materialized exact source projector bytes drifted" >&2
    exit 64
  fi
  BOOTSTRAP_SOURCE_PROJECTION="$(/usr/bin/env -i \
    HOME="$MATERIALIZED_SOURCE_TEMP/home" \
    PATH=/usr/bin:/bin \
    TMPDIR="$MATERIALIZED_SOURCE_TEMP/tmp" \
    LANG=C \
    LC_ALL=C \
    TZ=UTC \
    "$BOOTSTRAP_GATE_NODE" "$BOOTSTRAP_HEAD_PROJECTOR" \
      "$ROOT_DIR" "$MATERIALIZED_HEAD_ARGUMENT" none)"
  if [[ ! "$BOOTSTRAP_SOURCE_PROJECTION" \
    =~ ^HEAD\ $MATERIALIZED_HEAD_ARGUMENT\ [1-9][0-9]*\ none$ ]]; then
    echo "head-materialized source failed its immutable HEAD projection" >&2
    exit 64
  fi
else
  if [[ "$CANONICAL_SCRIPT_PATH" != */scripts/verify-local.sh ]]; then
    echo "direct release gate wrapper path is not the canonical repository entrypoint" >&2
    exit 64
  fi
  ROOT_DIR="${CANONICAL_SCRIPT_PATH%/scripts/verify-local.sh}"
fi

case "$MODE" in
  all|foundry|foundry-ci|operator-host|portable-ci|python|secrets|web-ci) ;;
  *)
    echo "Usage: $0 --head-materialized-root ROOT EXACT_HEAD [all|secrets|foundry|foundry-ci|operator-host|portable-ci|web-ci|python]" >&2
    exit 2
    ;;
esac

GENERIC_CI_NODE_EXECUTABLE=""
GENERIC_CI_NPM_CLI=""
GENERIC_CI_HOME=""
GENERIC_CI_FORGE_EXECUTABLE=""
GENERIC_CI_CAST_EXECUTABLE=""
OPERATOR_NODE_EXECUTABLE=""
TRUSTED_GENERIC_CI_TOOL_SHIM=""
AUTHENTICATED_GATE_NODE_EXECUTABLE=""
LAST_EXACT_HEAD_WORKTREE_HEAD=""

assert_head_materialized_launch() {
  if [[ "$HEAD_MATERIALIZED_LAUNCH" != "true" ]]; then
    echo "release authority gates require a wrapper materialized from the exact HEAD blob" >&2
    return 64
  fi
}

assert_pinned_generic_ci_node_authority() {
  local candidate
  local canonical
  local node_before
  local node_after
  local node_sha
  local npm_link
  local npm_target
  local npm_cli
  local npm_before
  local npm_after
  local npm_sha
  local npm_authority_helper
  local npm_authority_core
  local authority_source
  local authority_source_before
  local authority_source_after
  local authority_source_sha
  local authority_source_expected_sha
  local expected_uid
  local passwd_line
  local system_home

  if [[ "$(/usr/bin/uname -s)" != "Linux" ]]; then
    echo "portable CI requires the pinned generic-Linux Node authority" >&2
    return 64
  fi
  hash -r
  candidate="$(type -P node)"
  if [[ "$candidate" != /* || ! -f "$candidate" || -L "$candidate" ]]; then
    echo "portable CI Node must be one canonical regular executable" >&2
    return 64
  fi
  canonical="$(/usr/bin/readlink -f -- "$candidate")"
  if [[ "$canonical" != "$candidate" ]]; then
    echo "portable CI Node path is aliased" >&2
    return 64
  fi
  expected_uid="$(/usr/bin/id -u)"
  if [[ "$(/usr/bin/stat -Lc '%h:%u:%a' -- "$candidate")" != "1:${expected_uid}:755" ]]; then
    echo "portable CI Node owner, link count, or mode drifted" >&2
    return 64
  fi
  node_before="$(/usr/bin/stat -Lc '%d:%i:%s:%h:%u:%g:%a:%Y:%Z' -- "$candidate")"
  node_sha="$(/usr/bin/sha256sum -- "$candidate")"
  node_sha="${node_sha%% *}"
  node_after="$(/usr/bin/stat -Lc '%d:%i:%s:%h:%u:%g:%a:%Y:%Z' -- "$candidate")"
  if [[ "$node_before" != "$node_after" \
    || "$node_sha" != "3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327" ]]; then
    echo "portable CI Node bytes drifted from v22.23.2 Linux x64" >&2
    return 64
  fi

  passwd_line="$(/usr/bin/getent passwd "$expected_uid")"
  IFS=: read -r _ _ _ _ _ system_home _ <<< "$passwd_line"
  if [[ -z "$system_home" || "${HOME:-}" != "$system_home" \
    || ! -d "$system_home" || -L "$system_home" ]]; then
    echo "portable CI HOME must match the canonical system account home" >&2
    return 64
  fi

  npm_link="${candidate%/*}/npm"
  npm_cli="${candidate%/bin/node}/lib/node_modules/npm/bin/npm-cli.js"
  if [[ ! -L "$npm_link" \
    || "$(/usr/bin/readlink -- "$npm_link")" != "../lib/node_modules/npm/bin/npm-cli.js" \
    || "$(/usr/bin/readlink -f -- "$npm_link")" != "$npm_cli" \
    || ! -f "$npm_cli" || -L "$npm_cli" \
    || "$(/usr/bin/stat -c '%h:%u:%a' -- "$npm_link")" != "1:${expected_uid}:777" \
    || "$(/usr/bin/stat -Lc '%h:%u:%a' -- "$npm_cli")" != "1:${expected_uid}:755" ]]; then
    echo "portable CI npm 10.9.8 launcher structure drifted" >&2
    return 64
  fi
  npm_before="$(/usr/bin/stat -Lc '%d:%i:%s:%h:%u:%g:%a:%Y:%Z' -- "$npm_cli")"
  npm_sha="$(/usr/bin/sha256sum -- "$npm_cli")"
  npm_sha="${npm_sha%% *}"
  npm_after="$(/usr/bin/stat -Lc '%d:%i:%s:%h:%u:%g:%a:%Y:%Z' -- "$npm_cli")"
  if [[ "$npm_before" != "$npm_after" \
    || "$npm_sha" != "8e5f6f3429f8cdbe693cdc29904e9d5a7b127a494bd15c804bd54c7403bfcbe7" ]]; then
    echo "portable CI npm launcher bytes drifted" >&2
    return 64
  fi
  npm_authority_helper="$ROOT_DIR/scripts/test-harness/generic-ci-npm-runtime-authority.mjs"
  npm_authority_core="$ROOT_DIR/web/scripts/release-runtime-pins-core.mjs"
  for authority_source in "$npm_authority_helper" "$npm_authority_core"; do
    if [[ "$authority_source" == "$npm_authority_helper" ]]; then
      authority_source_expected_sha="000144c70f7e3c3bcd3495ceda1b2541572e8f5895f30c9d51c2cb66cce5e750"
    else
      authority_source_expected_sha="1923c498ff6f742b6f66ee0c623502adde3934bc2ceeb0f256a4822122cd3243"
    fi
    if [[ ! -f "$authority_source" || -L "$authority_source" \
      || "$(/usr/bin/readlink -f -- "$authority_source")" != "$authority_source" \
      || "$(/usr/bin/stat -Lc '%h:%u:%a' -- "$authority_source")" \
        != "1:${expected_uid}:644" ]]; then
      echo "portable CI npm authority source is not one canonical regular file" >&2
      return 64
    fi
    authority_source_before="$(/usr/bin/stat -Lc '%d:%i:%s:%h:%u:%g:%a:%Y:%Z' -- "$authority_source")"
    authority_source_sha="$(/usr/bin/sha256sum -- "$authority_source")"
    authority_source_sha="${authority_source_sha%% *}"
    authority_source_after="$(/usr/bin/stat -Lc '%d:%i:%s:%h:%u:%g:%a:%Y:%Z' -- "$authority_source")"
    if [[ "$authority_source_before" != "$authority_source_after" \
      || "$authority_source_sha" != "$authority_source_expected_sha" ]]; then
      echo "portable CI npm authority source bytes drifted" >&2
      return 64
    fi
  done
  if ! /usr/bin/env -i \
      HOME="$system_home" \
      PATH=/usr/bin:/bin \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      "$candidate" "$npm_authority_helper"; then
    echo "portable CI npm runtime tree drifted from the exact 10.9.8 manifest" >&2
    return 64
  fi
  GENERIC_CI_NODE_EXECUTABLE="$candidate"
  GENERIC_CI_NPM_CLI="$npm_cli"
  GENERIC_CI_HOME="$system_home"
  AUTHENTICATED_GATE_NODE_EXECUTABLE="$candidate"
}

assert_pinned_generic_ci_foundry_authority() {
  local executable
  local canonical
  local before
  local after
  local actual_sha
  local expected_sha
  local expected_uid
  local tool

  expected_uid="$(/usr/bin/id -u)"
  for tool in forge cast; do
    hash -r
    executable="$(type -P "$tool")"
    if [[ "$tool" == "forge" ]]; then
      expected_sha="a39fc1913b53dde6a35b603756f65d799e13817ef694107ec0d3704c20435cce"
    else
      expected_sha="7b25a9c61dac49a0718ba3c2d37ba638014f3baf35739777b2d809780914e91d"
    fi
    if [[ "$executable" != /* || ! -f "$executable" || -L "$executable" ]]; then
      echo "portable CI $tool must be one canonical regular executable" >&2
      return 64
    fi
    canonical="$(/usr/bin/readlink -f -- "$executable")"
    if [[ "$canonical" != "$executable" \
      || "$(/usr/bin/stat -Lc '%h:%u:%a' -- "$executable")" \
        != "1:${expected_uid}:755" ]]; then
      echo "portable CI $tool path, owner, link count, or mode drifted" >&2
      return 64
    fi
    before="$(/usr/bin/stat -Lc '%d:%i:%s:%h:%u:%g:%a:%Y:%Z' -- "$executable")"
    actual_sha="$(/usr/bin/sha256sum -- "$executable")"
    actual_sha="${actual_sha%% *}"
    after="$(/usr/bin/stat -Lc '%d:%i:%s:%h:%u:%g:%a:%Y:%Z' -- "$executable")"
    if [[ "$before" != "$after" || "$actual_sha" != "$expected_sha" ]]; then
      echo "portable CI $tool bytes drifted from Foundry v1.5.1" >&2
      return 64
    fi
    if [[ "$tool" == "forge" ]]; then
      GENERIC_CI_FORGE_EXECUTABLE="$executable"
    else
      GENERIC_CI_CAST_EXECUTABLE="$executable"
    fi
  done
  if [[ "${GENERIC_CI_FORGE_EXECUTABLE%/*}" \
    != "${GENERIC_CI_CAST_EXECUTABLE%/*}" ]]; then
    echo "portable CI Foundry executables must share one reviewed tool root" >&2
    return 64
  fi
  if [[ "$GENERIC_CI_CAST_EXECUTABLE" \
    != "$GENERIC_CI_HOME/.foundry/bin/cast" ]]; then
    echo "portable CI cast must be the pinned binary in the system account home" >&2
    return 64
  fi
}

assert_pinned_operator_node_authority() {
  local path_node
  local node_before
  local node_after
  local node_sha
  local expected_uid
  local pinned="/opt/homebrew/Cellar/node/24.9.0/bin/node"

  if [[ "$(/usr/bin/uname -s)" != "Darwin" ]]; then
    echo "operator-host Node authority requires frozen Darwin" >&2
    return 64
  fi
  hash -r
  path_node="$(type -P node)"
  if [[ -z "$path_node" || "$(/bin/realpath "$path_node")" != "$pinned" \
    || ! -f "$pinned" || -L "$pinned" ]]; then
    echo "operator-host PATH does not resolve the pinned Node executable" >&2
    return 64
  fi
  expected_uid="$(/usr/bin/id -u)"
  if [[ "$(/usr/bin/stat -f '%z:%l:%u:%Lp' "$pinned")" \
    != "64221968:1:${expected_uid}:555" ]]; then
    echo "operator-host Node owner, link count, mode, or size drifted" >&2
    return 64
  fi
  node_before="$(/usr/bin/stat -f '%d:%i:%z:%l:%u:%g:%Lp:%m:%c' "$pinned")"
  node_sha="$(/usr/bin/env -i \
    PATH=/usr/bin:/bin \
    LANG=C \
    LC_ALL=C \
    /usr/bin/shasum -a 256 "$pinned")"
  node_sha="${node_sha%% *}"
  node_after="$(/usr/bin/stat -f '%d:%i:%z:%l:%u:%g:%Lp:%m:%c' "$pinned")"
  if [[ "$node_before" != "$node_after" \
    || "$node_sha" != "3e7673f6552cffd3f9eaa3bcb910198a4d0786e99bb861d24eb81cc3fce563e7" ]]; then
    echo "operator-host Node bytes drifted from v24.9.0" >&2
    return 64
  fi
  OPERATOR_NODE_EXECUTABLE="$pinned"
  AUTHENTICATED_GATE_NODE_EXECUTABLE="$pinned"
}

assert_exact_head_worktree_authority() {
  local workspace_root="$1"
  local expected_head="${2:-}"
  local extra_profile="${3:-none}"
  local helper="$ROOT_DIR/scripts/test-harness/exact-head-worktree-authority.mjs"
  local helper_after
  local helper_before
  local helper_digest
  local helper_metadata
  local projection
  local expected_uid

  if [[ -z "$AUTHENTICATED_GATE_NODE_EXECUTABLE" \
    || ! -f "$AUTHENTICATED_GATE_NODE_EXECUTABLE" \
    || -L "$AUTHENTICATED_GATE_NODE_EXECUTABLE" ]]; then
    echo "exact HEAD worktree projection requires authenticated Node" >&2
    return 64
  fi
  expected_uid="$(/usr/bin/id -u)"
  case "$SCRIPT_PLATFORM" in
    Darwin)
      helper_metadata="$(/usr/bin/stat -f '%l:%u:%Lp' "$helper")"
      helper_before="$(/usr/bin/stat -f '%d:%i:%z:%l:%u:%g:%Lp:%m:%c' "$helper")"
      helper_digest="$(/usr/bin/env -i \
        PATH=/usr/bin:/bin LANG=C LC_ALL=C \
        /usr/bin/shasum -a 256 "$helper")"
      helper_digest="${helper_digest%% *}"
      helper_after="$(/usr/bin/stat -f '%d:%i:%z:%l:%u:%g:%Lp:%m:%c' "$helper")"
      ;;
    Linux)
      helper_metadata="$(/usr/bin/stat -Lc '%h:%u:%a' -- "$helper")"
      helper_before="$(/usr/bin/stat -Lc '%d:%i:%s:%h:%u:%g:%a:%Y:%Z' -- "$helper")"
      helper_digest="$(/usr/bin/sha256sum -- "$helper")"
      helper_digest="${helper_digest%% *}"
      helper_after="$(/usr/bin/stat -Lc '%d:%i:%s:%h:%u:%g:%a:%Y:%Z' -- "$helper")"
      ;;
    *)
      echo "exact HEAD worktree projection requires Darwin or Linux" >&2
      return 64
      ;;
  esac
  if [[ ! -f "$helper" || -L "$helper" \
    || "$(/bin/realpath "$helper")" != "$helper" \
    || "$helper_metadata" != "1:${expected_uid}:644" \
    || "$helper_before" != "$helper_after" \
    || "$helper_digest" \
      != "54c88fc8667310ad4b46f67488d8ee5926b6972c42d34fcad20dce199f2ec367" ]]; then
    echo "exact HEAD worktree projector source or metadata drifted" >&2
    return 64
  fi
  projection="$(/usr/bin/env -i \
    HOME="$workspace_root" \
    PATH=/usr/bin:/bin \
    LANG=C \
    LC_ALL=C \
    TZ=UTC \
    "$AUTHENTICATED_GATE_NODE_EXECUTABLE" "$helper" \
      "$workspace_root" "${expected_head:--}" "$extra_profile")"
  if [[ ! "$projection" =~ ^HEAD\ ([0-9a-f]{40})\ ([1-9][0-9]*)\ (none|web-generated|foundry-generated)$ \
    || "${BASH_REMATCH[3]:-}" != "$extra_profile" ]]; then
    echo "exact HEAD worktree projector returned an invalid receipt" >&2
    return 64
  fi
  LAST_EXACT_HEAD_WORKTREE_HEAD="${BASH_REMATCH[1]}"
}

make_trusted_generic_ci_tool_shim() {
  local private_root="$1"
  local expected_uid
  local shim
  local target
  local tool

  expected_uid="$(/usr/bin/id -u)"
  if [[ "$private_root" != /* || -L "$private_root" || ! -d "$private_root" \
    || "$(/usr/bin/readlink -f -- "$private_root")" != "$private_root" \
    || "$(/usr/bin/stat -Lc '%h:%u:%a' -- "$private_root")" \
      != "1:${expected_uid}:700" ]]; then
    echo "trusted tool shim requires a canonical private root" >&2
    return 64
  fi
  shim="$private_root/tool-bin"
  /bin/mkdir -m 0700 "$shim"
  for tool in node npm forge cast; do
    case "$tool" in
      node) target="$GENERIC_CI_NODE_EXECUTABLE" ;;
      npm) target="$GENERIC_CI_NPM_CLI" ;;
      forge) target="$GENERIC_CI_FORGE_EXECUTABLE" ;;
      cast) target="$GENERIC_CI_CAST_EXECUTABLE" ;;
    esac
    if [[ "$target" != /* || ! -f "$target" || -L "$target" ]]; then
      echo "trusted tool shim target is not an authenticated regular file: $tool" >&2
      return 64
    fi
    /bin/ln -s "$target" "$shim/$tool"
  done
  if [[ "$(/usr/bin/stat -Lc '%h:%u:%a' -- "$shim")" \
      != "1:${expected_uid}:700" ]]; then
    echo "trusted tool shim metadata drifted" >&2
    return 64
  fi
  TRUSTED_GENERIC_CI_TOOL_SHIM="$shim"
}

run_secret_scan() {
  assert_plain_web_ci_environment "secret scan"
  assert_head_materialized_launch
  /usr/bin/env -i \
    HOME="$MATERIALIZED_SOURCE_TEMP/home" \
    PATH=/usr/bin:/bin \
    TMPDIR="$MATERIALIZED_SOURCE_TEMP/tmp" \
    LANG=C \
    LC_ALL=C \
    TZ=UTC \
    CI=true \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 \
    GIT_NO_REPLACE_OBJECTS=1 \
    /bin/bash -p "$ROOT_DIR/scripts/ci-secret-scan.sh"
}

assert_unhooked_node_authority() {
  if [ -n "${NODE_OPTIONS:-}" ] \
    || [ -n "${NODE_PATH:-}" ] \
    || [ -n "${NODE_USE_ENV_PROXY:-}" ] \
    || [ -n "${NODE_EXTRA_CA_CERTS:-}" ] \
    || [ -n "${NODE_TLS_REJECT_UNAUTHORIZED:-}" ] \
    || [ -n "${SSL_CERT_FILE:-}" ] \
    || [ -n "${SSL_CERT_DIR:-}" ] \
    || [ -n "${SSLKEYLOGFILE:-}" ] \
    || [ -n "${LD_PRELOAD:-}" ] \
    || [ -n "${LD_AUDIT:-}" ] \
    || [ -n "${LD_LIBRARY_PATH:-}" ] \
    || [ -n "${LD_PROFILE:-}" ] \
    || [ -n "${GLIBC_TUNABLES:-}" ] \
    || [ -n "${DYLD_INSERT_LIBRARIES:-}" ] \
    || [ -n "${DYLD_LIBRARY_PATH:-}" ] \
    || [ -n "${DYLD_FRAMEWORK_PATH:-}" ] \
    || [ -n "${DYLD_FALLBACK_LIBRARY_PATH:-}" ] \
    || [ -n "${DYLD_FALLBACK_FRAMEWORK_PATH:-}" ] \
    || [ -n "${DNAI_PORTABLE_CI_AUTHORITY:-}" ]; then
    echo "release gates reject observable Node, TLS, native-loader hooks and portable-authority sentinels" >&2
    return 64
  fi
  local name
  while IFS= read -r name; do
    case "$name" in
      LD_*|DYLD_*)
        if [ -n "${!name:-}" ]; then
          echo "release gates reject observable native-loader hook: $name" >&2
          return 64
        fi
        ;;
    esac
  done < <(compgen -e)
}

assert_plain_web_ci_environment() {
  local boundary_label="${1:-web portable CI}"
  assert_unhooked_node_authority
  local name
  local project_credential_prefix='^(ACTIVATION|ANVIL|AWS|BASE|CF|CLOUDFLARE|COMPUTE|DEV|DILIGENCE|DOCKER|EMAIL|ESCROW|ETHERSCAN|EXECUTION|FOUNDRY|JUDGE|JWT|KMS|METERING|NEKO|OPENROUTER|ORACLE|PG|PHALA|QVL|RELEASE|ROYALTY|TELEGRAM|TINKER)_'
  local credential_suffix='(API_KEY|AUTH_KEY(_B64|_PATH)?|AUTH_TAG|AUTH_TOKEN|B64|BASE_URL(_SECONDARY)?|BOT_TOKEN|CLIENT_SECRET|CREDENTIALS?(_KEY_PATH|_SIGNING_KEY)?|INTEGRITY_KEY(_PATH)?|KEY(_B64|_FILE|_HEX|_PATH)?|KEYSTORE(_ACCOUNT)?|MNEMONIC|PASSWORD(_ADMIN)?|PRIVATE_KEY(_HEX)?|RPC_URL(_SECONDARY)?|SECRET|SIGNER_KEY_PATH|SIGNING_KEY|TOKEN)$'
  while IFS= read -r name; do
    [ -n "${!name:-}" ] || continue
    case "$name" in
      VITE_*|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|CF_API_KEY|CF_API_TOKEN|CF_PAGES_UPLOAD_JWT|CLOUDFLARE_API_KEY|CLOUDFLARE_API_TOKEN|CLOUDFLARE_EMAIL|GH_TOKEN|GITHUB_TOKEN|NODE_AUTH_TOKEN|NPM_TOKEN)
        echo "$boundary_label rejects authority or credential environment: $name" >&2
        return 65
        ;;
    esac
    if [[ "$name" =~ $project_credential_prefix ]] \
      && [[ "$name" =~ $credential_suffix ]]; then
      echo "$boundary_label rejects authority or credential environment: $name" >&2
      return 65
    fi
  done < <(compgen -e)
}

assert_plain_foundry_ci_environment() {
  local name
  while IFS= read -r name; do
    case "$name" in
      FOUNDRY_*|DAPP_*)
        if [[ -n "${!name:-}" ]]; then
          echo "foundry portable CI rejects caller-controlled Foundry configuration: $name" >&2
          return 65
        fi
        ;;
    esac
  done < <(compgen -e)
}

assert_clean_release_test_workspace() {
  local boundary_label="$1"
  local require_detached="${2:-false}"
  local workspace_root="${3:-$ROOT_DIR}"
  local expected_head="${4:-}"
  local extra_profile="${5:-none}"
  local candidate
  local config_name
  local config_name_lower
  local config_scopes
  local config_scope
  local config_status
  local index_entry
  local pattern
  local remote_config
  local remote_entry
  local remote_url
  local worktree_config

  for pattern in \
    "$workspace_root/.env" "$workspace_root/.env.*" \
    "$workspace_root/web/.env" "$workspace_root/web/.env.*" \
    "$workspace_root/.dev.vars" "$workspace_root/web/.dev.vars" \
    "$workspace_root/.release"; do
    while IFS= read -r candidate; do
      if [[ -e "$candidate" || -L "$candidate" ]]; then
        echo "$boundary_label requires a release worktree without repo-local credential files" >&2
        return 65
      fi
    done < <(compgen -G "$pattern" || true)
  done
  # Inspect the literal local config before any worktree operation. Git
  # porcelain can execute configured fsmonitor or clean-filter programs. The
  # explicit `--no-includes` plus empty global/system configuration keeps this
  # inspection from following caller-controlled config include paths.
  worktree_config="$(/usr/bin/env -i \
    HOME="$workspace_root" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git --no-replace-objects -c core.hooksPath=/dev/null \
      -C "$workspace_root" rev-parse --git-path config.worktree)"
  if [[ "$worktree_config" != /* ]]; then
    worktree_config="$workspace_root/$worktree_config"
  fi
  config_scopes=(--local)
  if [[ -e "$worktree_config" || -L "$worktree_config" ]]; then
    if [[ ! -f "$worktree_config" || -L "$worktree_config" ]]; then
      echo "$boundary_label rejects an aliased worktree Git configuration" >&2
      return 65
    fi
    config_scopes+=(--worktree)
  fi
  for config_scope in "${config_scopes[@]}"; do
    if ! /usr/bin/env -i HOME="$workspace_root" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 \
        /usr/bin/git -C "$workspace_root" config "$config_scope" --no-includes \
          --name-only --null --list \
        | while IFS= read -r -d '' config_name; do
            config_name_lower="$(/usr/bin/printf '%s' "$config_name" \
              | /usr/bin/tr '[:upper:]' '[:lower:]')"
            case "$config_name_lower" in
              include.*|includeif.*|core.fsmonitor|core.worktree|core.hookspath|core.attributesfile|filter.*|diff.external|diff.*.command|merge.*.driver|uploadpack.packobjectshook|remote.*.uploadpack|http.*.extraheader|http.*.proxy|credential.*|url.*.insteadof)
                exit 1
                ;;
            esac
          done; then
      echo "$boundary_label rejects unsafe local Git configuration" >&2
      return 65
    fi
    if remote_config="$(/usr/bin/env -i \
        HOME="$workspace_root" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 \
        /usr/bin/git -C "$workspace_root" config "$config_scope" --no-includes \
          --get-regexp \
            '^[Rr][Ee][Mm][Oo][Tt][Ee]\..*\.[Uu][Rr][Ll]$')"; then
      while IFS= read -r remote_entry; do
        remote_url="${remote_entry#* }"
        if [[ "$remote_url" =~ ://[^/@[:space:]]+@ ]]; then
          echo "$boundary_label rejects credential-bearing local Git remotes" >&2
          return 65
        fi
      done <<< "$remote_config"
    else
      config_status=$?
      if [[ "$config_status" -ne 1 ]]; then
        echo "$boundary_label could not verify local Git remote configuration" >&2
        return 65
      fi
    fi
  done
  # This projector hashes every stage-zero worktree object against the
  # immutable HEAD tree and enumerates every filesystem entry itself. It does
  # not invoke status/diff/check-attr, so neither index stat-cache forgery nor
  # clean/smudge attributes can hide or execute during the authority check.
  if ! assert_exact_head_worktree_authority \
      "$workspace_root" "$expected_head" "$extra_profile"; then
    echo "$boundary_label worktree bytes do not match immutable HEAD" >&2
    return 65
  fi
  if ! /usr/bin/env -i \
      HOME="$workspace_root" PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 \
      /usr/bin/git \
        -c core.fsmonitor=false \
        -c core.untrackedCache=false \
        -c core.hooksPath=/dev/null \
        -c core.ignoreStat=false \
        -c core.trustctime=true \
        -c core.checkStat=default \
        -c core.fileMode=true \
        -c core.worktree="$workspace_root" \
        -C "$workspace_root" ls-files -v -z \
      | while IFS= read -r -d '' index_entry; do
          if [[ "${index_entry:0:1}" != "H" ]]; then
            exit 1
          fi
        done; then
    echo "$boundary_label rejects hidden or nonordinary Git index state" >&2
    return 65
  fi
  if [[ "$require_detached" == "true" ]] \
    && /usr/bin/env -i HOME="$workspace_root" PATH=/usr/bin:/bin \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 \
      /usr/bin/git -c core.hooksPath=/dev/null -C "$workspace_root" \
        symbolic-ref -q HEAD >/dev/null 2>&1; then
    echo "$boundary_label requires a detached release worktree" >&2
    return 65
  fi
}

run_operator_host_root_tests() {
  local operator_cast_after
  local operator_cast_before
  local operator_cast_sha
  local operator_home
  local operator_lock_after
  local operator_lock_before
  local operator_materialized_head
  local operator_npm_cli="/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js"
  local operator_package_after
  local operator_package_before
  local operator_private_home
  local operator_private_tmp
  local operator_release_root
  local operator_ref
  local operator_ref_sha
  local operator_refs
  local operator_source_head
  local operator_tmp
  assert_plain_web_ci_environment "operator-host tests"
  assert_head_materialized_launch
  assert_pinned_operator_node_authority
  assert_clean_release_test_workspace "operator-host tests" true
  operator_source_head="$LAST_EXACT_HEAD_WORKTREE_HEAD"
  operator_home="${HOME:-}"
  if [[ "$operator_home" != /* || ! -d "$operator_home" || -L "$operator_home" \
    || "$(/bin/realpath "$operator_home")" != "$operator_home" \
    || ! -f "$operator_home/.foundry/bin/cast" \
    || -L "$operator_home/.foundry/bin/cast" ]]; then
    echo "operator-host tests require one canonical home and regular cast source" >&2
    return 64
  fi
  if [[ ! -f "$operator_npm_cli" || -L "$operator_npm_cli" \
    || "$(/bin/realpath "$operator_npm_cli")" != "$operator_npm_cli" \
    || "$(/usr/bin/stat -f '%l:%u:%Lp' "$operator_npm_cli")" \
      != "1:$(/usr/bin/id -u):755" ]]; then
    echo "operator-host tests require the canonical pinned npm entrypoint" >&2
    return 64
  fi
  if [[ ! "$operator_source_head" =~ ^[0-9a-f]{40}$ ]]; then
    echo "operator-host tests could not resolve one exact source commit" >&2
    return 64
  fi
  (
    operator_tmp="$(/bin/realpath \
      "$(/usr/bin/mktemp -d "/tmp/dnai-operator-root.XXXXXX")")"
    /bin/chmod 0700 "$operator_tmp"
    trap '/bin/rm -rf -- "$operator_tmp"' EXIT
    operator_private_home="$operator_tmp/home"
    operator_private_tmp="$operator_tmp/tmp"
    operator_release_root="$operator_tmp/release"
    /bin/mkdir -m 0700 \
      "$operator_private_home" \
      "$operator_private_home/.npm" \
      "$operator_private_home/.foundry" \
      "$operator_private_home/.foundry/bin" \
      "$operator_private_home/npm-cache" \
      "$operator_private_home/tool-bin" \
      "$operator_private_tmp"
    /usr/bin/install -m 0600 /dev/null \
      "$operator_private_home/user-npmrc"
    /usr/bin/install -m 0600 /dev/null \
      "$operator_private_home/global-npmrc"
    /usr/bin/install -m 0555 \
      "$operator_home/.foundry/bin/cast" \
      "$operator_private_home/.foundry/bin/cast"
    /bin/ln -s "$OPERATOR_NODE_EXECUTABLE" \
      "$operator_private_home/tool-bin/node"
    /usr/bin/env -i \
      HOME="$operator_private_home" \
      PATH=/usr/bin:/bin \
      TMPDIR="$operator_private_tmp" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_OPTIONAL_LOCKS=0 \
      /usr/bin/git \
        -c core.hooksPath=/dev/null \
        -c protocol.file.allow=always \
        clone --no-local --no-hardlinks --no-checkout \
          --depth=1 --no-tags --single-branch -- \
          "$ROOT_DIR" "$operator_release_root"
    /bin/chmod 0700 "$operator_release_root"
    /usr/bin/env -i \
      HOME="$operator_private_home" \
      PATH=/usr/bin:/bin \
      TMPDIR="$operator_private_tmp" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_OPTIONAL_LOCKS=0 \
      /usr/bin/git \
        -c core.fsmonitor=false \
        -c core.untrackedCache=false \
        -c core.hooksPath=/dev/null \
        -C "$operator_release_root" checkout --detach --force \
          "$operator_source_head"
    /usr/bin/env -i \
      HOME="$operator_private_home" PATH=/usr/bin:/bin \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 \
      /usr/bin/git -c core.hooksPath=/dev/null \
        -C "$operator_release_root" remote remove origin
    operator_refs="$(/usr/bin/env -i \
      HOME="$operator_private_home" PATH=/usr/bin:/bin \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 \
      /usr/bin/git -c core.hooksPath=/dev/null \
        -C "$operator_release_root" for-each-ref \
          --format='%(refname) %(objectname)')"
    while IFS=' ' read -r operator_ref operator_ref_sha; do
      [[ -n "$operator_ref" ]] || continue
      if [[ "$operator_ref" != refs/* \
        || "$operator_ref_sha" != "$operator_source_head" ]]; then
        echo "operator-host shallow materialization retained an unexpected ref" >&2
        return 64
      fi
      /usr/bin/env -i \
        HOME="$operator_private_home" PATH=/usr/bin:/bin \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 \
        /usr/bin/git -c core.hooksPath=/dev/null \
          -C "$operator_release_root" update-ref -d \
            "$operator_ref" "$operator_source_head"
    done <<< "$operator_refs"
    if [[ -e "$operator_release_root/.git/objects/info/alternates" \
      || "$(/usr/bin/env -i \
        HOME="$operator_private_home" PATH=/usr/bin:/bin \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 \
        /usr/bin/git -c core.hooksPath=/dev/null \
          -C "$operator_release_root" rev-parse --verify HEAD)" \
        != "$operator_source_head" ]] \
      || [[ "$(/usr/bin/env -i \
        HOME="$operator_private_home" PATH=/usr/bin:/bin \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 \
        /usr/bin/git -c core.hooksPath=/dev/null \
          -C "$operator_release_root" rev-parse --is-shallow-repository)" \
        != "true" ]] \
      || [[ "$(/usr/bin/env -i \
        HOME="$operator_private_home" PATH=/usr/bin:/bin \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 \
        /usr/bin/git -c core.hooksPath=/dev/null \
          -C "$operator_release_root" rev-list --count HEAD)" \
        != "1" ]] \
      || [[ -n "$(/usr/bin/env -i \
        HOME="$operator_private_home" PATH=/usr/bin:/bin \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 \
        /usr/bin/git -c core.hooksPath=/dev/null \
          -C "$operator_release_root" for-each-ref --format='%(refname)')" ]] \
      || /usr/bin/env -i \
        HOME="$operator_private_home" PATH=/usr/bin:/bin \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_OPTIONAL_LOCKS=0 \
        /usr/bin/git -c core.hooksPath=/dev/null \
          -C "$operator_release_root" symbolic-ref -q HEAD \
          >/dev/null 2>&1; then
      echo "operator-host tracked-source materialization is not exact and detached" >&2
      return 64
    fi
    if [[ -e "$operator_release_root/web/.npmrc" \
      || -L "$operator_release_root/web/.npmrc" ]]; then
      echo "operator-host tracked source rejects a project-local npm configuration" >&2
      return 65
    fi
    assert_clean_release_test_workspace \
      "operator-host tracked-source materialization" true \
        "$operator_release_root" "$operator_source_head" none
    # Authenticate the exact Node, dylib, and npm closure without importing a
    # package from node_modules. The complete authority test also imports the
    # deployment runner, so it must run only after the clean locked install.
    # Bootstrap still relies on the reviewed frozen operator filesystem and
    # trusted process launcher; executable hashing cannot authenticate an
    # already-hostile loaded dylib.
    cd "$operator_release_root/web"
    /usr/bin/env -i \
      HOME="$operator_private_home" \
      PATH="$operator_private_home/tool-bin:/usr/bin:/bin" \
      TMPDIR="$operator_private_tmp" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      NO_COLOR=1 \
      "$OPERATOR_NODE_EXECUTABLE" --input-type=module --eval \
        'import { assertPinnedReleaseRuntime } from "./scripts/release-runtime-pins-core.mjs"; assertPinnedReleaseRuntime();'
    assert_clean_release_test_workspace \
      "post-bootstrap-runtime operator source" true \
        "$ROOT_DIR" "$operator_source_head" none
    assert_clean_release_test_workspace \
      "post-bootstrap-runtime operator materialization" true \
        "$operator_release_root" "$operator_source_head" none
    assert_pinned_operator_node_authority
    operator_package_before="$(/usr/bin/env -i \
      PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /usr/bin/shasum -a 256 "$operator_release_root/web/package.json")"
    operator_package_before="${operator_package_before%% *}"
    operator_lock_before="$(/usr/bin/env -i \
      PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /usr/bin/shasum -a 256 "$operator_release_root/web/package-lock.json")"
    operator_lock_before="${operator_lock_before%% *}"
    /usr/bin/env -i \
      HOME="$operator_private_home" \
      PATH="$operator_private_home/tool-bin:/usr/bin:/bin" \
      TMPDIR="$operator_private_tmp" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      CI=true \
      NO_COLOR=1 \
      NPM_CONFIG_CACHE="$operator_private_home/npm-cache" \
      NPM_CONFIG_USERCONFIG="$operator_private_home/user-npmrc" \
      NPM_CONFIG_GLOBALCONFIG="$operator_private_home/global-npmrc" \
      NPM_CONFIG_SCRIPT_SHELL=/bin/sh \
      NPM_CONFIG_NODE_OPTIONS= \
      NPM_CONFIG_DRY_RUN=false \
      "$OPERATOR_NODE_EXECUTABLE" "$operator_npm_cli" \
        --ignore-scripts --prefix "$operator_release_root/web" ci
    operator_package_after="$(/usr/bin/env -i \
      PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /usr/bin/shasum -a 256 "$operator_release_root/web/package.json")"
    operator_package_after="${operator_package_after%% *}"
    operator_lock_after="$(/usr/bin/env -i \
      PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /usr/bin/shasum -a 256 "$operator_release_root/web/package-lock.json")"
    operator_lock_after="${operator_lock_after%% *}"
    if [[ "$operator_package_before" != "$operator_package_after" \
      || "$operator_lock_before" != "$operator_lock_after" ]]; then
      echo "operator-host npm ci changed the reviewed package or lock bytes" >&2
      return 64
    fi
    cd "$operator_release_root/web"
    /usr/bin/env -i \
      HOME="$operator_private_home" \
      PATH="$operator_private_home/tool-bin:/usr/bin:/bin" \
      TMPDIR="$operator_private_tmp" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      NO_COLOR=1 \
      "$OPERATOR_NODE_EXECUTABLE" --test \
        scripts/cloudflare-operator-host-authority.test.mjs
    assert_clean_release_test_workspace \
      "post-bootstrap-authority operator source" true \
        "$ROOT_DIR" "$operator_source_head" none
    assert_clean_release_test_workspace \
      "post-bootstrap-authority operator materialization" true \
        "$operator_release_root" "$operator_source_head" web-generated
    assert_pinned_operator_node_authority
    echo "== Full root and web Node gates on the frozen operator host =="
    echo "truth: this gate requires the real frozen operator-host authorities"
    cd "$operator_release_root/web"
    /usr/bin/env -i \
      HOME="$operator_private_home" \
      PATH="$operator_private_home/tool-bin:/usr/bin:/bin" \
      TMPDIR="$operator_private_tmp" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      NO_COLOR=1 \
      "$OPERATOR_NODE_EXECUTABLE" --test scripts/*.test.mjs
    operator_package_after="$(/usr/bin/env -i \
      PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /usr/bin/shasum -a 256 "$operator_release_root/web/package.json")"
    operator_package_after="${operator_package_after%% *}"
    operator_lock_after="$(/usr/bin/env -i \
      PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /usr/bin/shasum -a 256 "$operator_release_root/web/package-lock.json")"
    operator_lock_after="${operator_lock_after%% *}"
    if [[ "$operator_package_before" != "$operator_package_after" \
      || "$operator_lock_before" != "$operator_lock_after" \
      || -e "$operator_release_root/web/.npmrc" \
      || -L "$operator_release_root/web/.npmrc" ]]; then
      echo "operator web tests changed the reviewed package, lock, or npm config" >&2
      return 64
    fi
    assert_clean_release_test_workspace \
      "post-web operator source" true "$ROOT_DIR" "$operator_source_head" none
    assert_clean_release_test_workspace \
      "post-web operator materialization" true \
        "$operator_release_root" "$operator_source_head" web-generated
    operator_materialized_head="$(/usr/bin/env -i \
      HOME="$operator_private_home" PATH=/usr/bin:/bin \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 \
      /usr/bin/git -c core.hooksPath=/dev/null \
        -C "$operator_release_root" rev-parse --verify HEAD)"
    if [[ "$operator_materialized_head" != "$operator_source_head" ]]; then
      echo "operator web tests changed the exact materialized source commit" >&2
      return 64
    fi
    assert_pinned_operator_node_authority
    if [[ ! -f "$operator_private_home/.foundry/bin/cast" \
      || -L "$operator_private_home/.foundry/bin/cast" \
      || "$(/usr/bin/stat -f '%l:%u:%Lp' \
        "$operator_private_home/.foundry/bin/cast")" \
        != "1:$(/usr/bin/id -u):555" ]]; then
      echo "operator-host private cast copy metadata drifted" >&2
      return 64
    fi
    operator_cast_before="$(/usr/bin/stat -f '%d:%i:%z:%l:%u:%g:%Lp:%m:%c' \
      "$operator_private_home/.foundry/bin/cast")"
    operator_cast_sha="$(/usr/bin/env -i \
      PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /usr/bin/shasum -a 256 "$operator_private_home/.foundry/bin/cast")"
    operator_cast_sha="${operator_cast_sha%% *}"
    operator_cast_after="$(/usr/bin/stat -f '%d:%i:%z:%l:%u:%g:%Lp:%m:%c' \
      "$operator_private_home/.foundry/bin/cast")"
    if [[ "$operator_cast_before" != "$operator_cast_after" \
      || "$operator_cast_sha" \
        != "f7373e6e34939415fe048560ecf275463ea891fec5a124a38958983f3955542d" ]]; then
      echo "operator-host private cast copy bytes drifted" >&2
      return 64
    fi
    /usr/bin/env -i \
      HOME="$operator_private_home" \
      PATH="$operator_private_home/tool-bin:/usr/bin:/bin" \
      TMPDIR="$operator_private_tmp" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      CI=true \
      NO_COLOR=1 \
      NPM_CONFIG_CACHE="$operator_private_home/npm-cache" \
      NPM_CONFIG_USERCONFIG="$operator_private_home/user-npmrc" \
      NPM_CONFIG_GLOBALCONFIG="$operator_private_home/global-npmrc" \
      NPM_CONFIG_SCRIPT_SHELL=/bin/sh \
      NPM_CONFIG_NODE_OPTIONS= \
      NPM_CONFIG_DRY_RUN=false \
      "$OPERATOR_NODE_EXECUTABLE" "$operator_npm_cli" \
        --ignore-scripts --prefix "$operator_release_root/web" ci
    operator_package_after="$(/usr/bin/env -i \
      PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /usr/bin/shasum -a 256 "$operator_release_root/web/package.json")"
    operator_package_after="${operator_package_after%% *}"
    operator_lock_after="$(/usr/bin/env -i \
      PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /usr/bin/shasum -a 256 "$operator_release_root/web/package-lock.json")"
    operator_lock_after="${operator_lock_after%% *}"
    if [[ "$operator_package_before" != "$operator_package_after" \
      || "$operator_lock_before" != "$operator_lock_after" ]]; then
      echo "operator-host dependency restore changed package or lock bytes" >&2
      return 64
    fi
    /usr/bin/env -i \
      HOME="$operator_private_home" \
      PATH="$operator_private_home/tool-bin:/usr/bin:/bin" \
      TMPDIR="$operator_private_tmp" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      NO_COLOR=1 \
      "$OPERATOR_NODE_EXECUTABLE" --test \
        scripts/cloudflare-operator-host-authority.test.mjs
    cd "$operator_release_root"
    /usr/bin/env -i \
      HOME="$operator_private_home" \
      PATH="$operator_private_home/tool-bin:/usr/bin:/bin" \
      TMPDIR="$operator_private_tmp" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      NO_COLOR=1 \
      "$OPERATOR_NODE_EXECUTABLE" --test scripts/*.test.mjs
    # Root tests are arbitrary reviewed code. Re-run the complete frozen
    # Node/dylib/npm and Darwin sandbox authority proof after that consumer,
    # before the final exact-source and cast receipts are accepted.
    assert_pinned_operator_node_authority
    cd "$operator_release_root/web"
    /usr/bin/env -i \
      HOME="$operator_private_home" \
      PATH="$operator_private_home/tool-bin:/usr/bin:/bin" \
      TMPDIR="$operator_private_tmp" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      NO_COLOR=1 \
      "$OPERATOR_NODE_EXECUTABLE" --test \
        scripts/cloudflare-operator-host-authority.test.mjs
    cd "$operator_release_root"
    assert_clean_release_test_workspace \
      "post-root operator source" true "$ROOT_DIR" "$operator_source_head" none
    assert_clean_release_test_workspace \
      "post-root operator materialization" true \
        "$operator_release_root" "$operator_source_head" web-generated
    operator_materialized_head="$(/usr/bin/env -i \
      HOME="$operator_private_home" PATH=/usr/bin:/bin \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 \
      /usr/bin/git -c core.hooksPath=/dev/null \
        -C "$operator_release_root" rev-parse --verify HEAD)"
    if [[ "$operator_materialized_head" != "$operator_source_head" ]]; then
      echo "operator root tests changed the exact materialized source commit" >&2
      return 64
    fi
    assert_pinned_operator_node_authority
    if [[ ! -f "$operator_private_home/.foundry/bin/cast" \
      || -L "$operator_private_home/.foundry/bin/cast" \
      || "$(/usr/bin/stat -f '%l:%u:%Lp' \
        "$operator_private_home/.foundry/bin/cast")" \
        != "1:$(/usr/bin/id -u):555" ]]; then
      echo "operator-host final private cast copy metadata drifted" >&2
      return 64
    fi
    operator_cast_before="$(/usr/bin/stat -f '%d:%i:%z:%l:%u:%g:%Lp:%m:%c' \
      "$operator_private_home/.foundry/bin/cast")"
    operator_cast_sha="$(/usr/bin/env -i \
      PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      /usr/bin/shasum -a 256 "$operator_private_home/.foundry/bin/cast")"
    operator_cast_sha="${operator_cast_sha%% *}"
    operator_cast_after="$(/usr/bin/stat -f '%d:%i:%z:%l:%u:%g:%Lp:%m:%c' \
      "$operator_private_home/.foundry/bin/cast")"
    if [[ "$operator_cast_before" != "$operator_cast_after" \
      || "$operator_cast_sha" \
        != "f7373e6e34939415fe048560ecf275463ea891fec5a124a38958983f3955542d" ]]; then
      echo "operator-host final private cast copy bytes drifted" >&2
      return 64
    fi
  )
}

run_portable_ci_root_tests() {
  local node_executable="${1:-}"
  local extra_profile="${2:-none}"
  local clean_path
  local portable_home
  local portable_cast
  local portable_cast_sha
  local portable_source_head
  assert_plain_web_ci_environment "portable root CI"
  assert_head_materialized_launch
  if [ -z "$node_executable" ]; then
    assert_pinned_generic_ci_node_authority
    assert_pinned_generic_ci_foundry_authority
    node_executable="$GENERIC_CI_NODE_EXECUTABLE"
  fi
  assert_clean_release_test_workspace \
    "portable root CI" false "$ROOT_DIR" "" "$extra_profile"
  portable_source_head="$LAST_EXACT_HEAD_WORKTREE_HEAD"
  if [[ "$node_executable" != /* || ! -x "$node_executable" ]]; then
    echo "portable root gate requires an absolute executable Node path" >&2
    return 64
  fi
  clean_path="${node_executable%/*}:/usr/bin:/bin"
  (
    local portable_tmp
    portable_tmp="$(/usr/bin/readlink -f -- \
      "$(/usr/bin/mktemp -d "/tmp/dnai-portable-root.XXXXXX")")"
    /bin/chmod 0700 "$portable_tmp"
    trap '/bin/rm -rf -- "$portable_tmp"' EXIT
    portable_home="$portable_tmp"
    /usr/bin/install -d -m 0700 "$portable_home/.foundry/bin"
    /usr/bin/install -m 0755 \
      "$GENERIC_CI_CAST_EXECUTABLE" "$portable_home/.foundry/bin/cast"
    portable_cast="$portable_home/.foundry/bin/cast"
    portable_cast_sha="$(/usr/bin/sha256sum -- "$portable_cast")"
    portable_cast_sha="${portable_cast_sha%% *}"
    if [[ "$portable_cast_sha" \
        != "7b25a9c61dac49a0718ba3c2d37ba638014f3baf35739777b2d809780914e91d" \
      || "$(/usr/bin/stat -Lc '%h:%u:%a' -- "$portable_cast")" \
        != "1:$(/usr/bin/id -u):755" ]]; then
      echo "portable root cast copy drifted during private-home installation" >&2
      return 64
    fi
    GENERIC_CI_CAST_EXECUTABLE="$portable_cast"
    make_trusted_generic_ci_tool_shim "$portable_tmp"
    clean_path="$TRUSTED_GENERIC_CI_TOOL_SHIM:/usr/bin:/bin"
    /usr/bin/env -i \
      HOME="$portable_home" \
      PATH="$clean_path" \
      TMPDIR="$portable_tmp" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      CI=true \
      NO_COLOR=1 \
      DNAI_GENERIC_CI_CAST_PATH="$GENERIC_CI_CAST_EXECUTABLE" \
      "$node_executable" "$ROOT_DIR/scripts/test-harness/portable-root-test-profile.mjs"
    /usr/bin/env -i \
      HOME="$portable_home" \
      PATH="$clean_path" \
      TMPDIR="$portable_tmp" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      CI=true \
      NO_COLOR=1 \
      DNAI_GENERIC_CI_CAST_PATH="$GENERIC_CI_CAST_EXECUTABLE" \
      "$node_executable" "$ROOT_DIR/scripts/test-harness/run-portable-root-tests.mjs"
  )
  assert_clean_release_test_workspace \
    "post-test portable root CI" false "$ROOT_DIR" \
      "$portable_source_head" "$extra_profile"
  HOME="$GENERIC_CI_HOME" assert_pinned_generic_ci_node_authority
  assert_pinned_generic_ci_foundry_authority
}

run_web_ci() {
  local web_ci_source_head
  assert_plain_web_ci_environment
  assert_head_materialized_launch
  if [[ -e "$ROOT_DIR/web/.npmrc" || -L "$ROOT_DIR/web/.npmrc" ]]; then
    echo "web portable CI rejects a project-local npm configuration" >&2
    return 65
  fi
  assert_pinned_generic_ci_node_authority
  assert_pinned_generic_ci_foundry_authority
  assert_clean_release_test_workspace "web portable CI"
  web_ci_source_head="$LAST_EXACT_HEAD_WORKTREE_HEAD"
  echo "== Generic-Linux portable web and root gates =="
  echo "truth: this gate rejects rather than satisfies frozen Darwin operator authority"
  (
    local node_executable
    local npm_executable
    local clean_path
    local web_ci_home
    local audit_cache
    local package_before
    local package_after
    local package_after_root
    local lock_before
    local lock_after
    local lock_after_root

    run_web_node() {
      /usr/bin/env -i \
        HOME="$web_ci_home" \
        PATH="$clean_path" \
        TMPDIR="$web_ci_home/tmp" \
        LANG=C \
        LC_ALL=C \
        TZ=UTC \
        CI=true \
        NO_COLOR=1 \
        "$node_executable" "$@"
    }

    run_web_npm() {
      local npm_cache="$1"
      shift
      /usr/bin/env -i \
        HOME="$web_ci_home" \
        PATH="$clean_path" \
        TMPDIR="$web_ci_home/tmp" \
        LANG=C \
        LC_ALL=C \
        TZ=UTC \
        CI=true \
        NO_COLOR=1 \
        NPM_CONFIG_CACHE="$npm_cache" \
        NPM_CONFIG_USERCONFIG="$web_ci_home/user-npmrc" \
        NPM_CONFIG_GLOBALCONFIG="$web_ci_home/global-npmrc" \
        NPM_CONFIG_SCRIPT_SHELL=/bin/sh \
        NPM_CONFIG_NODE_OPTIONS= \
        NPM_CONFIG_DRY_RUN=false \
        "$node_executable" "$npm_executable" "$@"
    }

    assert_web_control_bytes() {
      package_after="$(/usr/bin/sha256sum -- "$ROOT_DIR/web/package.json")"
      package_after="${package_after%% *}"
      lock_after="$(/usr/bin/sha256sum -- "$ROOT_DIR/web/package-lock.json")"
      lock_after="${lock_after%% *}"
      if [[ "$package_before" != "$package_after" \
        || "$lock_before" != "$lock_after" \
        || -e "$ROOT_DIR/web/.npmrc" || -L "$ROOT_DIR/web/.npmrc" ]]; then
        echo "web gate changed the reviewed package, lock, or npm config" >&2
        return 64
      fi
    }

    node_executable="$GENERIC_CI_NODE_EXECUTABLE"
    npm_executable="$GENERIC_CI_NPM_CLI"
    clean_path="${node_executable%/*}:/usr/bin:/bin"
    web_ci_home="$(/usr/bin/readlink -f -- \
      "$(/usr/bin/mktemp -d "/tmp/dnai-web-ci-home.XXXXXX")")"
    /bin/chmod 0700 "$web_ci_home"
    /bin/mkdir -m 0700 "$web_ci_home/tmp" "$web_ci_home/npm-cache"
    /usr/bin/install -m 0600 /dev/null "$web_ci_home/user-npmrc"
    /usr/bin/install -m 0600 /dev/null "$web_ci_home/global-npmrc"
    trap '/bin/rm -rf -- "$web_ci_home"' EXIT
    make_trusted_generic_ci_tool_shim "$web_ci_home"
    clean_path="$TRUSTED_GENERIC_CI_TOOL_SHIM:/usr/bin:/bin"
    package_before="$(/usr/bin/sha256sum -- "$ROOT_DIR/web/package.json")"
    package_before="${package_before%% *}"
    lock_before="$(/usr/bin/sha256sum -- "$ROOT_DIR/web/package-lock.json")"
    lock_before="${lock_before%% *}"

    run_web_npm "$web_ci_home/npm-cache" \
      --ignore-scripts --prefix "$ROOT_DIR/web" ci
    assert_web_control_bytes
    cd "$ROOT_DIR/web"
    run_web_node node_modules/typescript/bin/tsc --noEmit
    assert_web_control_bytes
    assert_clean_release_test_workspace \
      "post-typecheck web portable CI" false "$ROOT_DIR" \
        "$web_ci_source_head" web-generated

    # Execute each mutation-capable test stage directly. Between stages,
    # re-project the immutable source and reinstall the exact lock so a test
    # cannot rewrite package scripts or dependency executables to skip a later
    # build or online audit while restoring only the final package bytes.
    run_web_node node_modules/vitest/vitest.mjs run
    assert_web_control_bytes
    assert_clean_release_test_workspace \
      "post-vitest web portable CI" false "$ROOT_DIR" \
        "$web_ci_source_head" web-generated
    assert_pinned_generic_ci_node_authority
    node_executable="$GENERIC_CI_NODE_EXECUTABLE"
    npm_executable="$GENERIC_CI_NPM_CLI"
    run_web_npm "$web_ci_home/npm-cache" \
      --ignore-scripts --prefix "$ROOT_DIR/web" ci

    run_web_node scripts/test-harness/run-portable-web-tests.mjs
    assert_web_control_bytes
    assert_clean_release_test_workspace \
      "post-release-tests web portable CI" false "$ROOT_DIR" \
        "$web_ci_source_head" web-generated
    assert_pinned_generic_ci_node_authority
    node_executable="$GENERIC_CI_NODE_EXECUTABLE"
    npm_executable="$GENERIC_CI_NPM_CLI"
    run_web_npm "$web_ci_home/npm-cache" \
      --ignore-scripts --prefix "$ROOT_DIR/web" ci

    run_web_node node_modules/typescript/bin/tsc --noEmit
    assert_web_control_bytes
    assert_clean_release_test_workspace \
      "post-build-typecheck web portable CI" false "$ROOT_DIR" \
        "$web_ci_source_head" web-generated
    assert_pinned_generic_ci_node_authority
    node_executable="$GENERIC_CI_NODE_EXECUTABLE"
    npm_executable="$GENERIC_CI_NPM_CLI"
    run_web_npm "$web_ci_home/npm-cache" \
      --ignore-scripts --prefix "$ROOT_DIR/web" ci

    run_web_node node_modules/vite/bin/vite.js build
    assert_web_control_bytes
    assert_clean_release_test_workspace \
      "post-vite web portable CI" false "$ROOT_DIR" \
        "$web_ci_source_head" web-generated
    assert_pinned_generic_ci_node_authority
    node_executable="$GENERIC_CI_NODE_EXECUTABLE"
    npm_executable="$GENERIC_CI_NPM_CLI"
    run_web_npm "$web_ci_home/npm-cache" \
      --ignore-scripts --prefix "$ROOT_DIR/web" ci

    run_web_node scripts/build-security-headers.mjs
    assert_web_control_bytes
    assert_clean_release_test_workspace \
      "post-build web portable CI" false "$ROOT_DIR" \
        "$web_ci_source_head" web-generated
    assert_pinned_generic_ci_node_authority
    node_executable="$GENERIC_CI_NODE_EXECUTABLE"
    npm_executable="$GENERIC_CI_NPM_CLI"

    audit_cache="$(/usr/bin/mktemp -d "$web_ci_home/audit-cache.XXXXXX")"
    /bin/chmod 0700 "$audit_cache"
    run_web_npm "$audit_cache" ping \
      --registry=https://registry.npmjs.org/ \
      --offline=false --prefer-online --strict-ssl=true
    run_web_npm "$audit_cache" audit \
      --prefix "$ROOT_DIR/web" \
      --registry=https://registry.npmjs.org/ \
      --offline=false --prefer-online --strict-ssl=true \
      --audit-level=moderate
    assert_web_control_bytes
    assert_clean_release_test_workspace \
      "post-audit web portable CI" false "$ROOT_DIR" \
        "$web_ci_source_head" web-generated
    assert_pinned_generic_ci_node_authority
    node_executable="$GENERIC_CI_NODE_EXECUTABLE"
    run_portable_ci_root_tests "$node_executable" web-generated
    /usr/bin/env -i \
      HOME="$web_ci_home" \
      PATH="$clean_path" \
      TMPDIR="$web_ci_home/tmp" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      CI=true \
      NO_COLOR=1 \
      "$node_executable" \
        "$ROOT_DIR/web/scripts/test-harness/operator-authority-fail-closed-probe.mjs"

    package_after_root="$(/usr/bin/sha256sum -- "$ROOT_DIR/web/package.json")"
    package_after_root="${package_after_root%% *}"
    lock_after_root="$(/usr/bin/sha256sum -- "$ROOT_DIR/web/package-lock.json")"
    lock_after_root="${lock_after_root%% *}"
    if [[ "$package_before" != "$package_after_root" \
      || "$lock_before" != "$lock_after_root" \
      || -e "$ROOT_DIR/web/.npmrc" || -L "$ROOT_DIR/web/.npmrc" ]]; then
      echo "portable root tests changed the reviewed web package, lock, or npm config" >&2
      return 64
    fi
    assert_clean_release_test_workspace \
      "post-test web portable CI" false "$ROOT_DIR" \
        "$web_ci_source_head" web-generated
    assert_pinned_generic_ci_node_authority
  )
}

run_foundry_common() {
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
  ./scripts/test-release-ceremony-storage-safety.sh
  ./scripts/test-royalty-release-safety.sh
  ./scripts/test-tinker-release-safety.sh
}

run_foundry_ci_common() {
  local contracts_root="$ROOT_DIR/⚙️/tinker-delegate/contracts"
  local suite
  /usr/bin/env -i \
    HOME="$HOME" PATH="$PATH" TMPDIR="$TMPDIR" \
    LANG=C LC_ALL=C TZ=UTC CI=true NO_COLOR=1 \
    "$GENERIC_CI_FORGE_EXECUTABLE" build --sizes
  /usr/bin/env -i \
    HOME="$HOME" PATH="$PATH" TMPDIR="$TMPDIR" \
    LANG=C LC_ALL=C TZ=UTC CI=true NO_COLOR=1 \
    "$GENERIC_CI_FORGE_EXECUTABLE" test --threads 1
  for suite in \
    test-deployment-safety.sh \
    test-local-release-rehearsal-safety.sh \
    test-challenge-registry-release-safety.sh \
    test-compute-release-safety.sh \
    test-diligence-release-safety.sh \
    test-email-oracle-release-safety.sh \
    test-execution-policy-anchor-release-safety.sh \
    test-release-ceremony-storage-safety.sh \
    test-royalty-release-safety.sh \
    test-tinker-release-safety.sh; do
    /usr/bin/env -i \
      HOME="$HOME" PATH="$PATH" TMPDIR="$TMPDIR" \
      LANG=C LC_ALL=C TZ=UTC CI=true NO_COLOR=1 \
      /bin/bash -p "$contracts_root/scripts/$suite"
  done
}

run_foundry() {
  assert_plain_web_ci_environment "foundry operator tests"
  assert_head_materialized_launch
  assert_pinned_operator_node_authority
  echo "== Foundry contracts and frozen operator-host Node authority =="
  pushd "$ROOT_DIR/⚙️/tinker-delegate/contracts" >/dev/null
  run_foundry_common
  "$OPERATOR_NODE_EXECUTABLE" --test \
    "$ROOT_DIR/scripts/royalty-release-finalized-history-evidence.test.mjs" \
    "$ROOT_DIR/scripts/royalty-release-history-receipt.test.mjs" \
    "$ROOT_DIR/scripts/release-ceremony-ledger.test.mjs" \
    "$ROOT_DIR/scripts/release-authority-stages.test.mjs" \
    scripts/royalty-release-phase-plan.test.mjs \
    scripts/royalty-release-manifest-filter.test.mjs \
    scripts/royalty-release-runtime-binding-adapter.test.mjs \
    scripts/royalty-release-ledger-binding.test.mjs \
    scripts/royalty-release-finality.test.mjs
  popd >/dev/null
}

run_foundry_ci() {
  local foundry_authority_path
  local foundry_ci_home
  local foundry_package_before
  local foundry_package_after
  local foundry_lock_before
  local foundry_lock_after
  local foundry_source_head
  assert_plain_web_ci_environment "foundry portable CI"
  assert_plain_foundry_ci_environment
  assert_head_materialized_launch
  if [[ -e "$ROOT_DIR/web/.npmrc" || -L "$ROOT_DIR/web/.npmrc" ]]; then
    echo "foundry portable CI rejects a project-local npm configuration" >&2
    return 65
  fi
  assert_pinned_generic_ci_node_authority
  assert_pinned_generic_ci_foundry_authority
  assert_clean_release_test_workspace "foundry portable CI"
  foundry_source_head="$LAST_EXACT_HEAD_WORKTREE_HEAD"
  (
    foundry_authority_path="${GENERIC_CI_NODE_EXECUTABLE%/*}:\
${GENERIC_CI_FORGE_EXECUTABLE%/*}:/usr/bin:/bin"
    foundry_ci_home="$(/usr/bin/readlink -f -- \
      "$(/usr/bin/mktemp -d "/tmp/dnai-foundry-ci.XXXXXX")")"
    /bin/chmod 0700 "$foundry_ci_home"
    /bin/mkdir -m 0700 "$foundry_ci_home/tmp"
    /usr/bin/install -m 0600 /dev/null "$foundry_ci_home/user-npmrc"
    /usr/bin/install -m 0600 /dev/null "$foundry_ci_home/global-npmrc"
    trap '/bin/rm -rf -- "$foundry_ci_home"' EXIT
    make_trusted_generic_ci_tool_shim "$foundry_ci_home"
    export PATH="$TRUSTED_GENERIC_CI_TOOL_SHIM:/usr/bin:/bin"
    export TMPDIR="$foundry_ci_home/tmp"
    export HOME="$foundry_ci_home"
    export LANG=C
    export LC_ALL=C
    export TZ=UTC
    export CI=true
    export NO_COLOR=1
    foundry_package_before="$(/usr/bin/sha256sum -- "$ROOT_DIR/web/package.json")"
    foundry_package_before="${foundry_package_before%% *}"
    foundry_lock_before="$(/usr/bin/sha256sum -- "$ROOT_DIR/web/package-lock.json")"
    foundry_lock_before="${foundry_lock_before%% *}"
    /usr/bin/env -i \
      HOME="$foundry_ci_home" \
      PATH="$PATH" \
      TMPDIR="$TMPDIR" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      CI=true \
      NO_COLOR=1 \
      NPM_CONFIG_USERCONFIG="$foundry_ci_home/user-npmrc" \
      NPM_CONFIG_GLOBALCONFIG="$foundry_ci_home/global-npmrc" \
      NPM_CONFIG_SCRIPT_SHELL=/bin/sh \
      NPM_CONFIG_NODE_OPTIONS= \
      NPM_CONFIG_DRY_RUN=false \
      "$GENERIC_CI_NODE_EXECUTABLE" "$GENERIC_CI_NPM_CLI" \
        --ignore-scripts --prefix "$ROOT_DIR/web" ci
    foundry_package_after="$(/usr/bin/sha256sum -- "$ROOT_DIR/web/package.json")"
    foundry_package_after="${foundry_package_after%% *}"
    foundry_lock_after="$(/usr/bin/sha256sum -- "$ROOT_DIR/web/package-lock.json")"
    foundry_lock_after="${foundry_lock_after%% *}"
    if [[ "$foundry_package_before" != "$foundry_package_after" \
      || "$foundry_lock_before" != "$foundry_lock_after" ]]; then
      echo "foundry npm ci changed the reviewed web package or lock bytes" >&2
      return 64
    fi
    HOME="$GENERIC_CI_HOME" PATH="$foundry_authority_path" \
      assert_pinned_generic_ci_node_authority
    /usr/bin/env -i \
      HOME="$HOME" \
      PATH="$PATH" \
      TMPDIR="$TMPDIR" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      CI=true \
      NO_COLOR=1 \
      "$GENERIC_CI_NODE_EXECUTABLE" \
        "$ROOT_DIR/scripts/test-harness/portable-root-test-profile.mjs"
    echo "== Foundry contracts and generic-CI portable Node suites =="
    echo "truth: portable suites do not satisfy frozen operator-host authority"
    pushd "$ROOT_DIR/⚙️/tinker-delegate/contracts" >/dev/null
    run_foundry_ci_common
    /usr/bin/env -i \
      HOME="$HOME" \
      PATH="$PATH" \
      TMPDIR="$TMPDIR" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      CI=true \
      NO_COLOR=1 \
      "$GENERIC_CI_NODE_EXECUTABLE" --test \
      "$ROOT_DIR/scripts/release-ceremony-ledger.test.mjs" \
      "$ROOT_DIR/scripts/release-authority-stages.test.mjs" \
      scripts/royalty-release-manifest-filter.test.mjs \
      scripts/royalty-release-runtime-binding-adapter.test.mjs \
      scripts/royalty-release-ledger-binding.test.mjs \
      scripts/royalty-release-finality.test.mjs
    popd >/dev/null
    foundry_package_after="$(/usr/bin/sha256sum -- "$ROOT_DIR/web/package.json")"
    foundry_package_after="${foundry_package_after%% *}"
    foundry_lock_after="$(/usr/bin/sha256sum -- "$ROOT_DIR/web/package-lock.json")"
    foundry_lock_after="${foundry_lock_after%% *}"
    if [[ "$foundry_package_before" != "$foundry_package_after" \
      || "$foundry_lock_before" != "$foundry_lock_after" \
      || -e "$ROOT_DIR/web/.npmrc" || -L "$ROOT_DIR/web/.npmrc" ]]; then
      echo "foundry portable tests changed the reviewed web package, lock, or npm config" >&2
      return 64
    fi
    assert_clean_release_test_workspace \
      "post-test foundry portable CI" false "$ROOT_DIR" \
        "$foundry_source_head" foundry-generated
    HOME="$GENERIC_CI_HOME" PATH="$foundry_authority_path" \
      assert_pinned_generic_ci_node_authority
    PATH="$foundry_authority_path" assert_pinned_generic_ci_foundry_authority
  )
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
  assert_plain_web_ci_environment "python CI"
  assert_head_materialized_launch
  # Python release tests invoke the canonical Node deployment-intent checker,
  # whose signature verifier imports the locked web cryptography dependencies.
  npm --ignore-scripts --prefix "$ROOT_DIR/web" ci
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
    run_operator_host_root_tests
    run_foundry
    run_python
    ;;
  secrets)
    run_secret_scan
    ;;
  foundry)
    run_foundry
    ;;
  foundry-ci)
    run_foundry_ci
    ;;
  portable-ci)
    run_portable_ci_root_tests
    ;;
  web-ci)
    run_web_ci
    ;;
  operator-host)
    run_operator_host_root_tests
    ;;
  python)
    run_python
    ;;
  *)
    echo "Usage: $0 --head-materialized-root ROOT EXACT_HEAD [all|secrets|foundry|foundry-ci|operator-host|portable-ci|web-ci|python]" >&2
    exit 2
    ;;
esac

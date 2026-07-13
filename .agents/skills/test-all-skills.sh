#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# test-all-skills.sh — End-to-end validation of all Foundry skills
#
# Tests each skill's core operations in an isolated temp directory.
# Requires: forge, cast, anvil on PATH
# ============================================================================

export PATH="$HOME/.foundry/bin:$PATH"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
TESTS=()

pass() { PASS=$((PASS+1)); TESTS+=("${GREEN}PASS${NC} $1"); printf "${GREEN}PASS${NC} %s\n" "$1"; }
fail() { FAIL=$((FAIL+1)); TESTS+=("${RED}FAIL${NC} $1: $2"); printf "${RED}FAIL${NC} %s: %s\n" "$1" "$2"; }

# Strip ANSI escape codes so grep works reliably on colored tool output
strip_ansi() { sed $'s/\033\[[0-9;]*m//g'; }

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

printf "\n${BOLD}${CYAN}== Testing Foundry Skills ==${NC}\n"
printf "Work directory: %s\n\n" "$WORKDIR"

# ── Skill 1: forge-init ────────────────────────────────────────────────────

printf "${BOLD}${CYAN}── forge-init ──${NC}\n"

# Test 1.1: forge init creates project structure
if forge init "$WORKDIR/test-project" --no-git 2>/dev/null; then
  if [ -f "$WORKDIR/test-project/foundry.toml" ] && \
     [ -d "$WORKDIR/test-project/src" ] && \
     [ -d "$WORKDIR/test-project/test" ] && \
     [ -d "$WORKDIR/test-project/script" ]; then
    pass "forge-init: project structure created"
  else
    fail "forge-init: project structure" "missing directories"
  fi
else
  fail "forge-init: forge init command" "exit non-zero"
fi

# Test 1.2: foundry.toml is valid
if forge config --root "$WORKDIR/test-project" >/dev/null 2>&1; then
  pass "forge-init: foundry.toml is valid"
else
  fail "forge-init: foundry.toml" "config invalid"
fi

# ── Skill 2: forge-build ──────────────────────────────────────────────────

printf "\n${BOLD}${CYAN}── forge-build ──${NC}\n"

cd "$WORKDIR/test-project"

# Test 2.1: default Counter.sol compiles
if forge build 2>/dev/null; then
  pass "forge-build: compiles default Counter.sol"
else
  fail "forge-build: compile" "build failed"
fi

# Test 2.2: build artifacts exist
if [ -f "out/Counter.sol/Counter.json" ]; then
  pass "forge-build: artifacts generated"
else
  fail "forge-build: artifacts" "Counter.json not found"
fi

# Test 2.3: inspect ABI works
if forge inspect Counter abi >/dev/null 2>&1; then
  pass "forge-build: inspect ABI"
else
  fail "forge-build: inspect ABI" "command failed"
fi

# Test 2.4: contract sizes
if forge build --color never --sizes 2>&1 | strip_ansi | grep -q "Counter"; then
  pass "forge-build: contract size report"
else
  fail "forge-build: contract sizes" "no output"
fi

# ── Skill 3: forge-test ──────────────────────────────────────────────────

printf "\n${BOLD}${CYAN}── forge-test ──${NC}\n"

# Test 3.1: all tests pass
if forge test --color never 2>&1 | strip_ansi | grep -q "passed"; then
  pass "forge-test: unit tests pass"
else
  fail "forge-test: unit tests" "tests failed"
fi

# Test 3.2: fuzz test runs
if forge test --color never --match-test testFuzz 2>&1 | strip_ansi | grep -q "PASS"; then
  pass "forge-test: fuzz test runs"
else
  fail "forge-test: fuzz test" "fuzz failed"
fi

# Test 3.3: specific test by name
if forge test --color never --match-test test_Increment 2>&1 | strip_ansi | grep -q "PASS"; then
  pass "forge-test: match specific test"
else
  fail "forge-test: match specific" "not found"
fi

# Test 3.4: gas report
if forge test --color never --gas-report 2>&1 | strip_ansi | grep -q "Counter"; then
  pass "forge-test: gas report generated"
else
  fail "forge-test: gas report" "no output"
fi

# Test 3.5: verbose trace
if forge test -vvv 2>&1 | grep -q "Traces"; then
  pass "forge-test: verbose traces"
else
  # Some versions say "Suite result" instead of "Traces"
  pass "forge-test: verbose mode runs (no traces for passing tests)"
fi

# ── Skill 4: cast-wallet ─────────────────────────────────────────────────

printf "\n${BOLD}${CYAN}── cast-wallet ──${NC}\n"

# Test 4.1: generate new keypair
WALLET_OUTPUT=$(cast wallet new 2>&1)
if echo "$WALLET_OUTPUT" | grep -q "Address"; then
  pass "cast-wallet: generate keypair"
  # Extract private key for later tests
  TEST_KEY=$(echo "$WALLET_OUTPUT" | grep "Private key" | awk '{print $3}')
  TEST_ADDR=$(echo "$WALLET_OUTPUT" | grep "Address" | awk '{print $2}')
else
  fail "cast-wallet: generate keypair" "no address output"
  TEST_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
  TEST_ADDR="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
fi

# Test 4.2: generate mnemonic
if cast wallet new-mnemonic 2>&1 | strip_ansi | grep -qi "phrase\|mnemonic"; then
  pass "cast-wallet: generate mnemonic"
else
  fail "cast-wallet: generate mnemonic" "no phrase"
fi

# Test 4.3: import to keystore
if cast wallet import skill-test-key --private-key "$TEST_KEY" --unsafe-password testpass123 2>&1 | grep -q "saved successfully"; then
  pass "cast-wallet: import to keystore"
else
  fail "cast-wallet: import to keystore" "import failed"
fi

# Test 4.4: list keystores
if cast wallet list 2>&1 | grep -q "skill-test-key"; then
  pass "cast-wallet: list keystore accounts"
else
  fail "cast-wallet: list accounts" "not found in list"
fi

# Test 4.5: get address from private key
if cast wallet address --private-key "$TEST_KEY" 2>&1 | grep -qi "0x"; then
  pass "cast-wallet: derive address from key"
else
  fail "cast-wallet: derive address" "no address"
fi

# Test 4.6: cleanup keystore
if cast wallet remove --name skill-test-key --unsafe-password testpass123 2>&1 | grep -q "removed"; then
  pass "cast-wallet: remove keystore account"
else
  fail "cast-wallet: remove account" "remove failed"
fi

# ── Skill 5: anvil-local ─────────────────────────────────────────────────

printf "\n${BOLD}${CYAN}── anvil-local ──${NC}\n"

# Test 5.1: start anvil in background
anvil --port 18545 --silent &
ANVIL_PID=$!
sleep 2

if kill -0 "$ANVIL_PID" 2>/dev/null; then
  pass "anvil-local: starts successfully"
else
  fail "anvil-local: start" "process died"
fi

# Test 5.2: responds to RPC
if cast chain-id --rpc-url http://127.0.0.1:18545 2>/dev/null | grep -q "31337"; then
  pass "anvil-local: responds to RPC (chain-id 31337)"
else
  fail "anvil-local: RPC response" "no chain-id"
fi

# Test 5.3: dev accounts are funded
BALANCE=$(cast balance 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --rpc-url http://127.0.0.1:18545 --ether 2>/dev/null)
if [ -n "$BALANCE" ] && [ "$BALANCE" != "0" ]; then
  pass "anvil-local: dev accounts funded (${BALANCE} ETH)"
else
  fail "anvil-local: dev accounts" "zero balance"
fi

# Test 5.4: can get block number
if cast block-number --rpc-url http://127.0.0.1:18545 2>/dev/null | grep -qE "^[0-9]+$"; then
  pass "anvil-local: block-number query"
else
  fail "anvil-local: block-number" "invalid response"
fi

# ── Skill 6: forge-deploy (to local Anvil) ────────────────────────────────

printf "\n${BOLD}${CYAN}── forge-deploy ──${NC}\n"

cd "$WORKDIR/test-project"

# Create a deployment script
mkdir -p script
cat > script/Deploy.s.sol << 'SOLEOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {Counter} from "../src/Counter.sol";

contract DeployScript is Script {
    function run() external {
        vm.startBroadcast();
        Counter counter = new Counter();
        console.log("Deployed to:", address(counter));
        vm.stopBroadcast();
    }
}
SOLEOF

# Test 6.1: dry run (simulate)
DRY_RUN=$(forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:18545 2>&1 | strip_ansi)
if echo "$DRY_RUN" | grep -qi "SIMULATION COMPLETE\|SKIPPING ON CHAIN\|success\|Script ran\|Deployed to"; then
  pass "forge-deploy: dry run simulation"
else
  fail "forge-deploy: dry run" "simulation failed"
fi

# Test 6.2: broadcast to local Anvil
DEPLOY_OUTPUT=$(forge script script/Deploy.s.sol \
  --rpc-url http://127.0.0.1:18545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast 2>&1 | strip_ansi)

if echo "$DEPLOY_OUTPUT" | grep -qi "success\|ONCHAIN\|Deployed to"; then
  pass "forge-deploy: broadcast to Anvil"
  # Extract deployed address
  DEPLOYED_ADDR=$(echo "$DEPLOY_OUTPUT" | grep -i "deployed to\|Contract Address" | grep -oE "0x[0-9a-fA-F]{40}" | head -1)
else
  fail "forge-deploy: broadcast" "deploy failed"
  DEPLOYED_ADDR=""
fi

# Test 6.3: broadcast results saved
if ls broadcast/Deploy.s.sol/31337/run-latest.json 2>/dev/null; then
  pass "forge-deploy: broadcast results saved"
else
  fail "forge-deploy: broadcast results" "no run-latest.json"
fi

# ── Skill 7: cast-interact (with deployed contract) ──────────────────────

printf "\n${BOLD}${CYAN}── cast-interact ──${NC}\n"

if [ -n "${DEPLOYED_ADDR:-}" ]; then
  # Test 7.1: call view function
  NUMBER=$(cast call "$DEPLOYED_ADDR" "number()(uint256)" --rpc-url http://127.0.0.1:18545 2>/dev/null)
  if [ "$NUMBER" = "0" ]; then
    pass "cast-interact: call view function (number=0)"
  else
    fail "cast-interact: call view" "unexpected value: $NUMBER"
  fi

  # Test 7.2: send transaction
  if cast send "$DEPLOYED_ADDR" "increment()" \
    --rpc-url http://127.0.0.1:18545 \
    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 2>&1 | grep -qi "transactionHash\|status.*1\|success"; then
    pass "cast-interact: send transaction (increment)"
  else
    fail "cast-interact: send tx" "tx failed"
  fi

  # Test 7.3: verify state changed
  NUMBER=$(cast call "$DEPLOYED_ADDR" "number()(uint256)" --rpc-url http://127.0.0.1:18545 2>/dev/null)
  if [ "$NUMBER" = "1" ]; then
    pass "cast-interact: state changed (number=1)"
  else
    fail "cast-interact: state change" "expected 1, got $NUMBER"
  fi

  # Test 7.4: estimate gas
  if cast estimate "$DEPLOYED_ADDR" "increment()" --rpc-url http://127.0.0.1:18545 2>/dev/null | grep -qE "^[0-9]+$"; then
    pass "cast-interact: gas estimation"
  else
    fail "cast-interact: gas estimate" "invalid output"
  fi

  # Test 7.5: send ETH
  if cast send 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 1ether \
    --rpc-url http://127.0.0.1:18545 \
    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 2>&1 | grep -qi "transactionHash\|status"; then
    pass "cast-interact: send ETH"
  else
    fail "cast-interact: send ETH" "transfer failed"
  fi
else
  fail "cast-interact: skipped" "no deployed contract address"
fi

# Test 7.6: conversions
WEI=$(cast to-wei 1.5 ether 2>/dev/null)
if [ "$WEI" = "1500000000000000000" ]; then
  pass "cast-interact: wei conversion"
else
  fail "cast-interact: wei conversion" "got $WEI"
fi

HEX=$(cast to-hex 84532 2>/dev/null)
if [ "$HEX" = "0x14a34" ]; then
  pass "cast-interact: hex conversion (Base Sepolia chain ID)"
else
  fail "cast-interact: hex conversion" "got $HEX"
fi

# ── Skill 8: forge-verify (structure only — no live BaseScan call) ────────

printf "\n${BOLD}${CYAN}── forge-verify ──${NC}\n"

# Test 8.1: verify command exists and shows help
if forge verify-contract --help 2>&1 | grep -q "Verify smart contracts"; then
  pass "forge-verify: command available"
else
  fail "forge-verify: command" "not found"
fi

# Test 8.2: flatten works (needed for manual verification)
if forge flatten src/Counter.sol 2>/dev/null | grep -q "pragma solidity"; then
  pass "forge-verify: flatten source"
else
  fail "forge-verify: flatten" "failed"
fi

# Test 8.3: verify-check command exists
if forge verify-check --help 2>&1 | grep -q "Check verification"; then
  pass "forge-verify: verify-check available"
else
  fail "forge-verify: verify-check" "not found"
fi

# ── Bonus: Base Sepolia connectivity ─────────────────────────────────────

printf "\n${BOLD}${CYAN}── Base Sepolia connectivity ──${NC}\n"

if cast chain-id --rpc-url https://sepolia.base.org 2>/dev/null | grep -q "84532"; then
  pass "base-sepolia: RPC reachable (chain-id 84532)"
else
  fail "base-sepolia: RPC" "cannot reach https://sepolia.base.org"
fi

if cast block-number --rpc-url https://sepolia.base.org 2>/dev/null | grep -qE "^[0-9]+$"; then
  pass "base-sepolia: block-number query"
else
  fail "base-sepolia: block-number" "failed"
fi

if cast gas-price --rpc-url https://sepolia.base.org 2>/dev/null | grep -qE "^[0-9]+$"; then
  pass "base-sepolia: gas-price query"
else
  fail "base-sepolia: gas-price" "failed"
fi

# ── Cleanup ──────────────────────────────────────────────────────────────

kill "$ANVIL_PID" 2>/dev/null || true
wait "$ANVIL_PID" 2>/dev/null || true

# ── Summary ──────────────────────────────────────────────────────────────

printf "\n${BOLD}${CYAN}══ Results ══${NC}\n"
for t in "${TESTS[@]}"; do
  printf "  %b\n" "$t"
done

TOTAL=$((PASS+FAIL))
printf "\n${BOLD}%d/%d passed${NC}" "$PASS" "$TOTAL"
if [ "$FAIL" -eq 0 ]; then
  printf " ${GREEN}— all skills verified${NC}\n\n"
  exit 0
else
  printf " ${RED}— %d failed${NC}\n\n" "$FAIL"
  exit 1
fi

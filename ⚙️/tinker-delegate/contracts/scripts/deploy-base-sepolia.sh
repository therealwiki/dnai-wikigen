#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/⚙️/tinker-delegate/contracts"
MANIFEST_PATH="${DEPLOYMENT_MANIFEST_PATH:-$ROOT_DIR/deployments/base-sepolia.json}"

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env"
  set +a
fi

RPC_URL="${BASE_SEPOLIA_RPC_URL:-https://sepolia.base.org}"
ACCOUNT="${FOUNDRY_KEYSTORE_ACCOUNT:-dev}"
CHAIN_ID="${CHAIN_ID:-84532}"
DEPLOYER_ADDRESS="${DEPLOYER_ADDRESS:-0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD}"
DILIGENCE_RESULT_VERIFIER="${DILIGENCE_RESULT_VERIFIER:-$DEPLOYER_ADDRESS}"
VERIFY="${VERIFY:-false}"
export DILIGENCE_RESULT_VERIFIER

if [ "$CHAIN_ID" != "84532" ]; then
  echo "Refusing to deploy: this helper is only for Base Sepolia chainId 84532." >&2
  exit 1
fi

if ! command -v forge >/dev/null 2>&1; then
  echo "forge is required" >&2
  exit 1
fi

if ! command -v cast >/dev/null 2>&1; then
  echo "cast is required" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

cd "$CONTRACTS_DIR"

echo "== Base Sepolia deploy preflight =="
echo "RPC:       $RPC_URL"
echo "Account:   $ACCOUNT"
echo "Deployer:  $DEPLOYER_ADDRESS"
echo "Verifier:  $DILIGENCE_RESULT_VERIFIER"
echo "Manifest:  $MANIFEST_PATH"
echo

echo -n "Chain ID:  "
cast chain-id --rpc-url "$RPC_URL"
echo -n "Balance:   "
cast balance "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL" --ether
echo -n "Nonce:     "
cast nonce "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL"
echo

echo "== Build and tests =="
forge build --sizes
forge test

echo
echo "== Dry runs =="
forge script script/DiligenceRoom.s.sol --rpc-url "$RPC_URL" --sender "$DEPLOYER_ADDRESS"
EMAIL_ORACLE_OWNER="${EMAIL_ORACLE_OWNER:-$DEPLOYER_ADDRESS}" \
  forge script script/EmailOracleAuth.s.sol --rpc-url "$RPC_URL" --sender "$DEPLOYER_ADDRESS"

echo
echo "== Broadcast DiligenceRoom =="
forge script script/DiligenceRoom.s.sol \
  --rpc-url "$RPC_URL" \
  --account "$ACCOUNT" \
  --broadcast \
  --slow

echo
echo "== Broadcast EmailOracleAuth =="
EMAIL_ORACLE_OWNER="${EMAIL_ORACLE_OWNER:-$DEPLOYER_ADDRESS}" \
  forge script script/EmailOracleAuth.s.sol \
    --rpc-url "$RPC_URL" \
    --account "$ACCOUNT" \
    --broadcast \
    --slow

DILIGENCE_RUN="broadcast/DiligenceRoom.s.sol/$CHAIN_ID/run-latest.json"
EMAIL_RUN="broadcast/EmailOracleAuth.s.sol/$CHAIN_ID/run-latest.json"
DILIGENCE_ADDRESS="$(jq -r '.transactions[] | select(.contractName == "DiligenceRoom") | .contractAddress' "$DILIGENCE_RUN" | tail -1)"
EMAIL_AUTH_ADDRESS="$(jq -r '.transactions[] | select(.contractName == "EmailOracleAuth") | .contractAddress' "$EMAIL_RUN" | tail -1)"
DILIGENCE_TX="$(jq -r '.transactions[] | select(.contractName == "DiligenceRoom") | .hash // .transactionHash // empty' "$DILIGENCE_RUN" | tail -1)"
EMAIL_AUTH_TX="$(jq -r '.transactions[] | select(.contractName == "EmailOracleAuth") | .hash // .transactionHash // empty' "$EMAIL_RUN" | tail -1)"

if [ -z "$DILIGENCE_ADDRESS" ] || [ -z "$EMAIL_AUTH_ADDRESS" ]; then
  echo "Could not parse deployed contract addresses from broadcast artifacts." >&2
  exit 1
fi

echo
echo "== On-chain verification reads =="
DILIGENCE_DEVELOPER="$(cast call "$DILIGENCE_ADDRESS" "developer()(address)" --rpc-url "$RPC_URL")"
DILIGENCE_VERIFIER="$(cast call "$DILIGENCE_ADDRESS" "resultVerifier()(address)" --rpc-url "$RPC_URL")"
EMAIL_OWNER="$(cast call "$EMAIL_AUTH_ADDRESS" "owner()(address)" --rpc-url "$RPC_URL")"
EMAIL_ALLOW_ANY_DEVICE="$(cast call "$EMAIL_AUTH_ADDRESS" "allowAnyDevice()(bool)" --rpc-url "$RPC_URL")"
EMAIL_DELAY="$(cast call "$EMAIL_AUTH_ADDRESS" "ORACLE_UPGRADE_DELAY()(uint256)" --rpc-url "$RPC_URL" | awk '{print $1}')"

echo "DiligenceRoom:   $DILIGENCE_ADDRESS"
echo "  developer:     $DILIGENCE_DEVELOPER"
echo "  verifier:      $DILIGENCE_VERIFIER"
echo "  tx:            $DILIGENCE_TX"
echo "EmailOracleAuth: $EMAIL_AUTH_ADDRESS"
echo "  owner:         $EMAIL_OWNER"
echo "  allowAny:      $EMAIL_ALLOW_ANY_DEVICE"
echo "  delay:         $EMAIL_DELAY"
echo "  tx:            $EMAIL_AUTH_TX"

mkdir -p "$(dirname "$MANIFEST_PATH")"
tmp_manifest="$(mktemp)"
jq -n \
  --arg reviewedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg deployer "$DEPLOYER_ADDRESS" \
  --arg account "$ACCOUNT" \
  --arg diligence "$DILIGENCE_ADDRESS" \
  --arg diligenceTx "$DILIGENCE_TX" \
  --arg diligenceDeveloper "$DILIGENCE_DEVELOPER" \
  --arg diligenceVerifier "$DILIGENCE_VERIFIER" \
  --arg emailAuth "$EMAIL_AUTH_ADDRESS" \
  --arg emailAuthTx "$EMAIL_AUTH_TX" \
  --arg emailOwner "$EMAIL_OWNER" \
  --argjson emailAllowAny "$EMAIL_ALLOW_ANY_DEVICE" \
  --arg emailDelay "$EMAIL_DELAY" \
  '{
    schemaVersion: 1,
    network: {
      name: "Base Sepolia",
      chainId: 84532,
      rpcEnv: "BASE_SEPOLIA_RPC_URL",
      explorerBaseUrl: "https://sepolia.basescan.org"
    },
    status: "current_operator_contracts_deployed",
    lastReviewedAt: $reviewedAt,
    currentOperatorDeployer: {
      address: $deployer,
      keystoreAccount: $account,
      fundingStatus: "funded_on_base_sepolia",
      privateKeyMaterial: "not_recorded"
    },
    contracts: {
      diligenceRoom: {
        status: "deployed_current_operator_controlled",
        address: $diligence,
        baseScanUrl: ("https://sepolia.basescan.org/address/" + $diligence),
        deploymentTx: $diligenceTx,
        transactionUrl: (if $diligenceTx == "" then null else "https://sepolia.basescan.org/tx/" + $diligenceTx end),
        developer: $diligenceDeveloper,
        resultVerifier: $diligenceVerifier,
        currentOperatorControlled: true
      },
      emailOracleAuth: {
        status: "deployed_current_operator_controlled",
        address: $emailAuth,
        baseScanUrl: ("https://sepolia.basescan.org/address/" + $emailAuth),
        deploymentTx: $emailAuthTx,
        transactionUrl: (if $emailAuthTx == "" then null else "https://sepolia.basescan.org/tx/" + $emailAuthTx end),
        owner: $emailOwner,
        oracleUpgradeDelaySeconds: ($emailDelay | tonumber),
        allowAnyDevice: $emailAllowAny,
        oracleCodeFrozen: false,
        consumerRegistryFrozen: false,
        currentOperatorControlled: true
      }
    },
    phala: {
      status: "not_revalidated_by_this_contract_deploy",
      cvmId: null,
      appId: null,
      composeHash: null,
      gatewayBaseDomain: null,
      imageDigests: [],
      quoteEvidence: null
    },
    freshDeployment: {
      status: "broadcast_complete",
      helper: "⚙️/tinker-delegate/contracts/scripts/deploy-base-sepolia.sh"
    }
  }' > "$tmp_manifest"
mv "$tmp_manifest" "$MANIFEST_PATH"

echo
echo "Wrote manifest: $MANIFEST_PATH"

if [ "$VERIFY" = "true" ]; then
  if [ -z "${ETHERSCAN_API_KEY:-}" ]; then
    echo "VERIFY=true requested but ETHERSCAN_API_KEY is empty." >&2
    exit 1
  fi
  echo
  echo "Run verification manually with forge verify-contract once constructor args are confirmed."
fi

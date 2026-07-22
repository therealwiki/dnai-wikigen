from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import yaml

import tinker_delegate.release_composes as release_composes_module

from tinker_delegate.release_composes import (
    BOOTSTRAP_DELEGATE_FAIL_CLOSED_KEYS,
    DEPLOYMENT_TOOLCHAIN_AUTHORITY,
    IMAGE_NAMES,
    MAIN_POST_MEASUREMENT_ENVIRONMENT_KEYS,
    MAIN_SERVICES,
    METERING_POST_MEASUREMENT_ENVIRONMENT_KEYS,
    METERING_RUNTIME_PROFILE,
    METERING_SERVICES,
    PHASE_GATE_SCHEMA,
    PRODUCTION_ORACLE_POLICY,
    QVL_POST_MEASUREMENT_ENVIRONMENT_KEYS,
    QVL_RUNTIME_PROFILE,
    QVL_SERVICES,
    ReleaseComposeError,
    _load_yaml,
    _validate_late_environment_pass_through,
    _validate_production_oracle_environment,
    _validate_secret_placeholders,
    render_release_composes,
    validate_deployment_intent,
    validate_image_release,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PROJECT_ROOT = REPOSITORY_ROOT / "⚙️" / "tinker-delegate"
SHA = "a" * 40


def _manifest() -> dict:
    images = []
    for index, name in enumerate(IMAGE_NAMES, start=1):
        digest = "sha256:" + format(index, "x") * 64
        repository = f"ghcr.io/therealwiki/dnai-wikigen/{name}"
        images.append(
            {
                "name": name,
                "repository": repository,
                "digest": digest,
                "image": f"{repository}@{digest}",
                "platform": "linux/amd64",
                "sbom_artifact": {
                    "filename": f"{name}.spdx.json",
                    "sha256": format(index + 5, "x") * 64,
                },
                "provenance_subject": {"name": repository, "digest": digest},
                "attestations": {
                    "provenance": {
                        "predicate_type": "https://slsa.dev/provenance/v1",
                        "id": str(index),
                        "url": (
                            "https://github.com/therealwiki/dnai-wikigen/attestations/"
                            f"{index}"
                        ),
                    },
                    "sbom": {
                        "predicate_type": "https://spdx.dev/Document/v2.3",
                        "id": str(index + 10),
                        "url": (
                            "https://github.com/therealwiki/dnai-wikigen/attestations/"
                            f"{index + 10}"
                        ),
                    },
                },
                "verification": {
                    "repo": "therealwiki/dnai-wikigen",
                    "signer_workflow": (
                        "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml"
                    ),
                    "source_digest": SHA,
                    "source_ref": "refs/heads/main",
                    "provenance_attestation": "verified",
                    "sbom_attestation": "verified",
                },
            }
        )
    return {
        "schema": "dnai.tee-image-release.v1",
        "release_sha": SHA,
        "source_ref": "refs/heads/main",
        "generated_at": "2026-07-15T12:00:00.000Z",
        "source_repository": "therealwiki/dnai-wikigen",
        "signer_workflow": "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
        "workflow_run_id": "123456",
        "workflow_run_url": (
            "https://github.com/therealwiki/dnai-wikigen/actions/runs/123456"
        ),
        "platform": "linux/amd64",
        "images": images,
    }


def _bundle_bytes() -> bytes:
    return (
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {"certificate": {"rawBytes": "fixture"}},
                "dsseEnvelope": {"payload": "fixture", "signatures": []},
            },
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _write_bundle(root: Path) -> Path:
    path = root / "input.bundle.json"
    path.write_bytes(_bundle_bytes())
    return path


def _intent() -> dict:
    address = lambda value: f"0x{value:040x}"
    word = lambda value: f"0x{value:064x}"
    qvl = {
        "challengeCapacity": 1024,
        "challengeTtlSeconds": 60,
        "maxConcurrency": 4,
        "rateCapacity": 30,
        "rateRefillPerSecond": "0.5",
        "requestBodyTimeoutSeconds": "5",
        "verificationTimeoutSeconds": "20",
    }
    metering = {
        "maxConcurrency": 4,
        "rateCapacity": 30,
        "rateRefillPerSecond": "0.5",
        "requestBodyTimeoutSeconds": "5",
        "rpcTimeoutSeconds": "8",
    }
    return {
        "schema": "dnai.deployment-intent-core.v6",
        "truthStatus": (
            "pre_deployment_intent_not_deployment_attestation_or_runtime_authority_evidence"
        ),
        "network": {
            "chainId": 84532,
            "name": "base-sepolia",
            "canonicalUsdc": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
        },
        "release": {
            "releaseSha": SHA,
            "reviewerAuthorityCurrentStatusEpoch": 1,
            "reviewerAuthorityCurrentStatusSha256": "sha256:" + ("92" * 32),
            "reviewerAuthorityGenesisAcceptanceSha256": "sha256:" + ("91" * 32),
            "toolchain": deepcopy(DEPLOYMENT_TOOLCHAIN_AUTHORITY),
        },
        "scope": {
            "contracts": [
                "DiligenceRoom",
                "TinkerAccountEncumbrance",
                "RoyaltyDistributor",
                "ChallengeRegistry",
                "ComputeCreditVault",
                "EmailOracleAuth",
                "ExecutionPolicyAnchor",
            ],
            "cvms": [
                "main_runtime",
                "diligence_qvl",
                "arena_qvl",
                "anchor_writer_qvl",
                "compute_workload_qvl",
                "compute_metering_qvl",
                "independent_metering",
            ],
        },
        "deploymentControl": {
            "controllerId": "deployment-operator-01",
            "controllerKind": "encrypted_foundry_keystore_eoa",
            "foundryAccount": "dev",
            "operatorAddress": address(1),
        },
        "staticContractInputs": {
            "computeCreditVault": {"developer": address(2)},
            "tinkerAccountEncumbrance": {"accountCommitment": word(10)},
        },
        "numericPolicy": {
            "contract": {
                "computeDeveloperFeeBps": 100,
                "emailOracleUpgradeDelaySeconds": 172800,
                "tinkerMaxAddBalanceWei": "5000000000000000000",
                "tinkerMaxSpendWei": "2000000000000000000",
            },
            "metering": metering,
            "qvl": {
                "anchorWriter": dict(qvl),
                "arena": dict(qvl),
                "computeMetering": dict(qvl),
                "computeWorkload": dict(qvl),
                "diligence": dict(qvl),
            },
        },
        "dynamicRuntimeAuthorities": {
            "contractAddresses": [],
            "cvmIdentities": [],
            "downstreamAnchorState": [],
            "releaseCommitments": [],
            "roleAddresses": [],
        },
    }


def _canonical_json(value: dict) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _write_intent(root: Path, intent: dict | None = None) -> Path:
    path = root / "deployment-intent.json"
    path.write_bytes(_canonical_json(intent or _intent()))
    return path


def _node_receipt(path: Path) -> dict:
    receipt_bytes = subprocess.check_output(
        [
            "node",
            "scripts/operator-policy-packet.mjs",
            "check-intent",
            "--in",
            str(path),
        ],
        cwd=REPOSITORY_ROOT,
    )
    return json.loads(receipt_bytes)


def _qvl_environment(intent_domain: dict) -> dict[str, str]:
    return {
        "QVL_CHALLENGE_CAPACITY": str(intent_domain["challengeCapacity"]),
        "QVL_CHALLENGE_TTL_SECONDS": str(intent_domain["challengeTtlSeconds"]),
        "QVL_MAX_CONCURRENCY": str(intent_domain["maxConcurrency"]),
        "QVL_RATE_CAPACITY": str(intent_domain["rateCapacity"]),
        "QVL_RATE_REFILL_PER_SECOND": str(intent_domain["rateRefillPerSecond"]),
        "QVL_REQUEST_BODY_TIMEOUT_SECONDS": str(
            intent_domain["requestBodyTimeoutSeconds"]
        ),
        "QVL_VERIFICATION_TIMEOUT_SECONDS": str(
            intent_domain["verificationTimeoutSeconds"]
        ),
    }


def _metering_environment(intent_metering: dict) -> dict[str, str]:
    return {
        "METERING_MAX_CONCURRENCY": str(intent_metering["maxConcurrency"]),
        "METERING_RATE_CAPACITY": str(intent_metering["rateCapacity"]),
        "METERING_RATE_REFILL_PER_SECOND": str(
            intent_metering["rateRefillPerSecond"]
        ),
        "METERING_REQUEST_BODY_TIMEOUT_SECONDS": str(
            intent_metering["requestBodyTimeoutSeconds"]
        ),
        "METERING_RPC_TIMEOUT_SECONDS": str(intent_metering["rpcTimeoutSeconds"]),
    }


def _fresh_contract_ledger(deployment_intent_sha256: str) -> dict:
    address = lambda value: f"0x{value:040x}"
    word = lambda value: f"0x{value:064x}"
    reviewer_genesis_acceptance_sha256 = "sha256:" + ("91" * 32)
    contract_names = (
        "challengeRegistry",
        "computeCreditVault",
        "diligenceRoom",
        "emailOracleAuth",
        "executionPolicyAnchor",
        "royaltyDistributor",
        "tinkerAccountEncumbrance",
    )
    contracts = {
        name: {
            "address": address(10 + index),
            "runtimeCodeHash": word(20 + index),
            "sourceCommit": SHA,
            "deploymentTx": word(30 + index),
            "deploymentBlock": 12_345_000 + index,
            "deploymentBlockHash": word(40 + index),
            "deploymentReceiptStatus": "success",
            "deploymentTxFrom": address(1),
            "deploymentReceiptContractAddress": address(10 + index),
        }
        for index, name in enumerate(contract_names)
    }
    transaction_spec = (
        ("diligenceRoom", "DiligenceRoom", "CREATE", "constructor(bool)"),
        ("diligenceRoom", "DiligenceRoom", "CALL", "freezeFeeBps()"),
        (
            "diligenceRoom",
            "DiligenceRoom",
            "CALL",
            "enableComputeSettlementPolicy()",
        ),
        (
            "diligenceRoom",
            "DiligenceRoom",
            "CALL",
            "setComposeApprovalRequired(bool)",
        ),
        (
            "diligenceRoom",
            "DiligenceRoom",
            "CALL",
            "setTeeIdentityApprovalRequired(bool)",
        ),
        (
            "diligenceRoom",
            "DiligenceRoom",
            "CALL",
            "freezeApprovalRequirements()",
        ),
        (
            "tinkerAccountEncumbrance",
            "TinkerAccountEncumbrance",
            "CREATE",
            "constructor(address,bytes32,bytes32,uint256,uint256)",
        ),
        ("royaltyDistributor", "RoyaltyDistributor", "CREATE", "constructor()"),
        (
            "challengeRegistry",
            "ChallengeRegistry",
            "CREATE",
            "constructor(address)",
        ),
        (
            "computeCreditVault",
            "ComputeCreditVault",
            "CREATE",
            "constructor(address,address,uint16)",
        ),
        (
            "computeCreditVault",
            "ComputeCreditVault",
            "CALL",
            "freezeDeveloperFee()",
        ),
        (
            "emailOracleAuth",
            "EmailOracleAuth",
            "CREATE",
            "constructor(address,uint256,bool,bytes32,bytes32,bool)",
        ),
        (
            "executionPolicyAnchor",
            "ExecutionPolicyAnchor",
            "CREATE",
            "constructor(address,bytes32,bytes32)",
        ),
    )
    broadcast_transactions = []
    normalized_transactions = []
    for sequence, (contract_key, contract_name, transaction_type, signature) in enumerate(
        transaction_spec
    ):
        contract = contracts[contract_key]
        create = transaction_type == "CREATE"
        input_sha256 = f"sha256:{500 + sequence:064x}"
        if create:
            contract["creationInputSha256"] = input_sha256
        transaction = {
            "sequence": sequence,
            "contractKey": contract_key,
            "contractName": contract_name,
            "transactionType": transaction_type,
            "functionSignature": signature,
            "transactionHash": (
                contract["deploymentTx"] if create else word(200 + sequence)
            ),
            "transactionFrom": address(1),
            "transactionTo": None if create else contract["address"],
            "transactionNonce": 700 + sequence,
            "transactionInputSha256": input_sha256,
            "receiptStatus": "success",
            "receiptContractAddress": contract["address"] if create else None,
            "blockNumber": (
                contract["deploymentBlock"] if create else 12_346_000 + sequence
            ),
            "blockHash": (
                contract["deploymentBlockHash"] if create else word(300 + sequence)
            ),
        }
        broadcast_transactions.append(transaction)
        normalized_transactions.append(
            {
                "sequence": transaction["sequence"],
                "contract_key": transaction["contractKey"],
                "contract_name": transaction["contractName"],
                "transaction_type": transaction["transactionType"],
                "function_signature": transaction["functionSignature"],
                "transaction_hash": transaction["transactionHash"],
                "transaction_from": transaction["transactionFrom"],
                "transaction_to": transaction["transactionTo"],
                "transaction_nonce": transaction["transactionNonce"],
                "transaction_input_sha256": transaction["transactionInputSha256"],
                "receipt_status": transaction["receiptStatus"],
                "receipt_contract_address": transaction["receiptContractAddress"],
                "block_number": transaction["blockNumber"],
                "block_hash": transaction["blockHash"],
            }
        )
    broadcast_transactions_sha256 = "sha256:" + hashlib.sha256(
        json.dumps(
            normalized_transactions,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    contracts["challengeRegistry"].update(
        {
            "status": "deployed_empty_active_registry",
            "owner": address(1),
            "registryPaused": False,
            "challengeCount": 0,
        }
    )
    contracts["executionPolicyAnchor"].update(
        {
            "deploymentIntentSha256Bytes32": (
                "0x" + deployment_intent_sha256.removeprefix("sha256:")
            ),
            "reviewerAuthorityGenesisAcceptanceSha256Bytes32": (
                "0x"
                + reviewer_genesis_acceptance_sha256.removeprefix("sha256:")
            ),
            "authorityCommitmentReadProof": (
                "primary_and_secondary_rpc_exact_getter_match_at_deployment_block"
            ),
            "authorityCommitmentReadBlock": contracts[
                "executionPolicyAnchor"
            ]["deploymentBlock"],
            "authorityCommitmentReadBlockHash": contracts[
                "executionPolicyAnchor"
            ]["deploymentBlockHash"],
        }
    )
    return {
        "schemaVersion": 2,
        "status": "fresh_contract_suite_deployed_pending_cvm_binding",
        "network": {
            "name": "Base Sepolia",
            "chainId": 84_532,
            "rpcEnv": "BASE_SEPOLIA_RPC_URL",
            "explorerBaseUrl": "https://sepolia.basescan.org",
        },
        "currentOperatorDeployer": {
            "address": address(1),
            "keystoreAccount": "dev",
            "privateKeyMaterial": "not_used",
        },
        "freshDeployment": {
            "contractSuite": {
                "status": "broadcast_complete_pending_cvm_binding",
                "sourceCommit": SHA,
                "deploymentIntentSha256": deployment_intent_sha256,
                "reviewerAuthorityGenesisAcceptanceSha256": (
                    reviewer_genesis_acceptance_sha256
                ),
                "keystoreAccount": "dev",
                "runtimeCodeProof": (
                    "exact_creation_reexecution_match_all_contracts"
                ),
                "exactCreationInputProof": (
                    "mined_transaction_input_equals_release_snapshot_creation_input_all_contracts"
                ),
                "broadcastTransactionProof": (
                    "exact_ordered_13_transaction_receipts_with_consecutive_nonces"
                ),
                "broadcastTransactionCount": len(transaction_spec),
                "broadcastTransactionsSha256": broadcast_transactions_sha256,
                "broadcastTransactions": broadcast_transactions,
            }
        },
        "contracts": contracts,
        "deploymentHistory": [
            {
                "kind": "fresh_reviewed_scope_contract_suite",
                "sourceCommit": SHA,
                "deploymentIntentSha256": deployment_intent_sha256,
                "reviewerAuthorityGenesisAcceptanceSha256": (
                    reviewer_genesis_acceptance_sha256
                ),
                "broadcastTransactionsSha256": broadcast_transactions_sha256,
            }
        ],
    }


def _old_projection() -> dict:
    return {
        "schema": "dnai.operator-role-policy-projection.v1",
        "packetSha256": f"sha256:{'f' * 64}",
        "releaseSha": SHA,
        "contractEnv": {},
        "postDeployEnv": {},
        "cvmEnvByDomain": {},
        "flatEnvironment": {},
    }


def _write_old_projection(root: Path) -> Path:
    path = root / "operator-policy-projection.json"
    path.write_text(
        json.dumps(_old_projection(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def _load(path: Path) -> dict:
    lines = path.read_text(encoding="utf-8").splitlines()
    body = "\n".join(line for line in lines if not line.startswith("#"))
    return yaml.safe_load(body)


class ReleaseComposeTest(unittest.TestCase):
    def test_late_environment_interpolation_is_empty_only_and_exact(self):
        valid = {
            "runtime": {
                "profiles": ["late-runtime"],
                "environment": {"RUNTIME_TOKEN": "${LATE_TOKEN:-}"},
            },
        }
        _validate_late_environment_pass_through(
            valid,
            ("LATE_TOKEN",),
            domain="fixture",
        )
        for invalid in (
            "${LATE_TOKEN:?too early}",
            "${LATE_TOKEN:-sentinel}",
            "${LATE_TOKEN-default}",
        ):
            mutated = deepcopy(valid)
            mutated["runtime"]["environment"]["RUNTIME_TOKEN"] = invalid
            with self.assertRaisesRegex(
                ReleaseComposeError,
                "must use exact post-measurement",
            ):
                _validate_late_environment_pass_through(
                    mutated,
                    ("LATE_TOKEN",),
                    domain="fixture",
                )

    def test_renders_seven_purpose_separated_digest_pinned_cvm_descriptors(self):
        manifest = _manifest()
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest_path = root / "input.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            bundle_path = _write_bundle(root)
            deployment_intent = _intent()
            intent_path = _write_intent(root, deployment_intent)
            output = root / "release"
            result = render_release_composes(
                manifest_path,
                output,
                manifest_attestation_bundle_path=bundle_path,
                deployment_intent_path=intent_path,
                expected_release_sha=SHA,
                repository_root=REPOSITORY_ROOT,
            )

            main = _load(result.main_compose)
            qvls = {
                "diligence_qvl_cvm": _load(result.diligence_qvl_compose),
                "arena_qvl_cvm": _load(result.arena_qvl_compose),
                "anchor_writer_qvl_cvm": _load(result.anchor_writer_qvl_compose),
                "compute_workload_qvl_cvm": _load(
                    result.compute_workload_qvl_compose
                ),
                "compute_metering_qvl_cvm": _load(
                    result.compute_metering_qvl_compose
                ),
            }
            metering = _load(result.metering_compose)
            self.assertEqual(set(main["services"]), set(MAIN_SERVICES))
            intent_domains = {
                "diligence_qvl_cvm": "diligence",
                "arena_qvl_cvm": "arena",
                "anchor_writer_qvl_cvm": "anchorWriter",
                "compute_workload_qvl_cvm": "computeWorkload",
                "compute_metering_qvl_cvm": "computeMetering",
            }
            for domain, qvl in qvls.items():
                self.assertEqual(set(qvl["services"]), set(QVL_SERVICES))
                self.assertEqual(
                    {
                        service_name: service["profiles"]
                        for service_name, service in qvl["services"].items()
                    },
                    {
                        service_name: [QVL_RUNTIME_PROFILE]
                        for service_name in QVL_SERVICES
                    },
                )
                self.assertEqual(
                    qvl["x-dnai-phase-gate"],
                    {
                        "schema": PHASE_GATE_SCHEMA,
                        "initial_phase": "bootstrap_provision",
                        "initial_services": [],
                        "initial_compose_profiles": [],
                        "post_measurement_phase": (
                            "post_measurement_policy_bootstrap"
                        ),
                        "activation_environment": {
                            "key": "COMPOSE_PROFILES",
                            "exact_value": QVL_RUNTIME_PROFILE,
                        },
                        "interpolation_policy": (
                            "late_values_use_exact_empty_default_until_"
                            "nonempty_validated_profile_activation"
                        ),
                    },
                )
                self.assertEqual(
                    qvl["services"]["policy-init"]["environment"][
                        "QVL_RELEASE_POLICY_B64"
                    ],
                    "${QVL_RELEASE_POLICY_B64:-}",
                )
                self.assertEqual(
                    qvl["services"]["qvl"]["environment"]["QVL_AUTH_TOKEN"],
                    "${QVL_AUTH_TOKEN:-}",
                )
                qvl_environment = qvl["services"]["qvl"]["environment"]
                expected_policy = _qvl_environment(
                    deployment_intent["numericPolicy"]["qvl"][intent_domains[domain]]
                )
                self.assertEqual(
                    {name: qvl_environment[name] for name in expected_policy},
                    expected_policy,
                )
                self.assertEqual(
                    qvl["x-dnai-runtime-policy"],
                    {
                        "schema": "dnai.public-runtime-numeric-policy.v1",
                        "source_schema": "dnai.deployment-intent-core.v6",
                        "numeric_environment": expected_policy,
                    },
                )
                body_timeout = float(qvl_environment["QVL_REQUEST_BODY_TIMEOUT_SECONDS"])
                verification_timeout = float(
                    qvl_environment["QVL_VERIFICATION_TIMEOUT_SECONDS"]
                )
                self.assertLessEqual(body_timeout + verification_timeout, 25.0)
            self.assertEqual(set(metering["services"]), set(METERING_SERVICES))
            self.assertEqual(
                {
                    service_name: service["profiles"]
                    for service_name, service in metering["services"].items()
                },
                {
                    service_name: [METERING_RUNTIME_PROFILE]
                    for service_name in METERING_SERVICES
                },
            )
            self.assertEqual(
                metering["x-dnai-phase-gate"]["activation_environment"],
                {
                    "key": "COMPOSE_PROFILES",
                    "exact_value": METERING_RUNTIME_PROFILE,
                },
            )
            self.assertEqual(
                metering["x-dnai-phase-gate"]["initial_services"],
                [],
            )
            metering_environment = metering["services"]["metering"]["environment"]
            for name in (
                "METERING_QVL_URL",
                "METERING_QVL_AUTH_TOKEN",
                "METERING_QVL_VERIFIER_ADDRESS",
                "METERING_QVL_RELEASE_POLICY_HASH",
            ):
                self.assertIn(name, metering_environment)
            expected_metering_policy = _metering_environment(
                deployment_intent["numericPolicy"]["metering"]
            )
            self.assertEqual(
                {name: metering_environment[name] for name in expected_metering_policy},
                expected_metering_policy,
            )
            self.assertEqual(
                metering["x-dnai-runtime-policy"]["numeric_environment"],
                expected_metering_policy,
            )
            self.assertEqual(
                metering["services"]["policy-init"]["environment"][
                    "METERING_POLICY_SET_B64"
                ],
                "${METERING_POLICY_SET_B64:-}",
            )
            for name in (
                "METERING_RPC_URL",
                "METERING_AUTH_TOKEN",
                "METERING_QVL_URL",
                "METERING_QVL_AUTH_TOKEN",
                "METERING_QVL_VERIFIER_ADDRESS",
                "METERING_QVL_RELEASE_POLICY_HASH",
            ):
                self.assertTrue(
                    metering_environment[name] == f"${{{name}:-}}",
                    name,
                )

            expected_images = {item["name"]: item["image"] for item in manifest["images"]}
            self.assertEqual(
                {service["image"] for service in main["services"].values()},
                {
                    expected_images["tinker-delegate"],
                    expected_images["tee-email-oracle"],
                    expected_images["neko-chrome"],
                },
            )
            for qvl in qvls.values():
                self.assertEqual(
                    {service["image"] for service in qvl["services"].values()},
                    {expected_images["attestation-qvl"]},
                )
            self.assertEqual(
                {service["image"] for service in metering["services"].values()},
                {expected_images["compute-metering"]},
            )
            for compose in (main, *qvls.values(), metering):
                self.assertNotIn(
                    "operator_policy_packet_sha256",
                    compose["x-dnai-release"],
                )
                if "x-dnai-runtime-policy" in compose:
                    self.assertNotIn(
                        "operator_policy_packet_sha256",
                        compose["x-dnai-runtime-policy"],
                    )
                for service in compose["services"].values():
                    self.assertNotIn("build", service)
                    self.assertEqual(service["platform"], "linux/amd64")
                    self.assertRegex(service["image"], r"@sha256:[0-9a-f]{64}$")

            self.assertEqual(
                main["services"]["arena-policy-init"]["network_mode"], "none"
            )
            self.assertEqual(
                main["services"]["arena-policy-init"]["profiles"],
                ["arena-runtime"],
            )
            self.assertEqual(
                main["services"]["arena-worker"]["profiles"],
                ["arena-runtime"],
            )
            arena_environment = main["services"]["arena-worker"]["environment"]
            expected_arena_authority = {
                "TINKER_MAIN_RUNTIME_CVM_ID": (
                    "${TINKER_COMPUTE_WORKLOAD_CVM_ID:?Canonical main runtime CVM ID required}"
                ),
                "TINKER_RELEASE_DEPLOYMENT_INTENT_SHA256": (
                    "${TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256:?Signed seven-CVM deployment intent required}"
                ),
                "TINKER_RELEASE_AUTHORITY_SHA256": (
                    "${TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256:-}"
                ),
                "TINKER_RELEASE_CEREMONY_NONCE": (
                    "${TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE:?Release ceremony nonce required}"
                ),
                "TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256": (
                    "${TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256:?Linked Arena QVL measurement policy required}"
                ),
                "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256": (
                    "${TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:-}"
                ),
                "TINKER_ARENA_WORKER_LIVE_CAPABILITY_ENABLED": "true",
            }
            for name, value in expected_arena_authority.items():
                self.assertEqual(arena_environment[name], value, name)
            for name in (
                "TINKER_MAIN_RUNTIME_CVM_ID",
                "TINKER_RELEASE_DEPLOYMENT_INTENT_SHA256",
                "TINKER_RELEASE_AUTHORITY_SHA256",
                "TINKER_RELEASE_CEREMONY_NONCE",
                "TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256",
            ):
                holders = [
                    service_name
                    for service_name, service in main["services"].items()
                    if name in service.get("environment", {})
                ]
                self.assertEqual(holders, ["arena-worker"], name)
            heartbeat_environment = {
                "TINKER_ARENA_WORKER_HEARTBEAT_PATH": (
                    "/data/arena_worker_heartbeat.json"
                ),
                "TINKER_ARENA_WORKER_HEARTBEAT_TTL_SECONDS": (
                    "${TINKER_ARENA_WORKER_HEARTBEAT_TTL_SECONDS:-30}"
                ),
                "TINKER_ARENA_WORKER_HEARTBEAT_KEY_PATH": (
                    "${TINKER_ARENA_WORKER_HEARTBEAT_KEY_PATH:-tinker/arena_worker_heartbeat}"
                ),
                "TINKER_ARENA_WORKER_HEARTBEAT_INTEGRITY_KEY": "",
            }
            for name, value in heartbeat_environment.items():
                self.assertEqual(arena_environment[name], value, name)
                self.assertEqual(
                    main["services"]["delegate"]["environment"][name],
                    value,
                    name,
                )
            self.assertEqual(
                main["services"]["delegate"]["environment"][
                    "TINKER_ARENA_WORKER_LIVE_CAPABILITY_ENABLED"
                ],
                "true",
            )
            self.assertEqual(
                main["services"]["delegate"]["environment"][
                    "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256"
                ],
                "${TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:-}",
            )
            for name in (
                "TINKER_ARENA_WORKER_RELEASE_SHA",
                "TINKER_ARENA_WORKER_IMAGE_DIGEST",
                "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
                "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256",
                "TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
                "TINKER_ARENA_WORKER_COMPOSE_HASH",
                "TINKER_ARENA_WORKER_APP_ID",
                "TINKER_ARENA_WORKER_OS_IMAGE_HASH",
            ):
                self.assertEqual(
                    main["services"]["delegate"]["environment"][name],
                    arena_environment[name],
                    name,
                )
            delegate_environment = main["services"]["delegate"]["environment"]
            for name in BOOTSTRAP_DELEGATE_FAIL_CLOSED_KEYS:
                self.assertNotIn(name, delegate_environment, name)
                holders = []
                for service_name, service in main["services"].items():
                    environment = service.get("environment", {})
                    if name not in environment:
                        continue
                    holders.append(service_name)
                    expected = (
                        f"${{{name}:-}}"
                        if name in MAIN_POST_MEASUREMENT_ENVIRONMENT_KEYS
                        else f"${{{name}:?"
                    )
                    if expected.endswith("}"):
                        self.assertEqual(environment[name], expected)
                    else:
                        self.assertTrue(
                            environment[name].startswith(expected),
                            f"{service_name}.{name}",
                        )
                self.assertTrue(holders, name)
            self.assertEqual(
                main["services"]["anchor-writer-evidence"]["profiles"],
                ["anchor-writer-ceremony"],
            )
            compute = main["services"]["compute-execution-worker"]
            self.assertEqual(compute["profiles"], ["compute-execution"])
            self.assertEqual(
                compute["x-dnai-capability-status"],
                "disabled_provider_contract_unavailable",
            )
            writer_token = "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN"
            holders = [
                name
                for name, service in main["services"].items()
                if writer_token in service.get("environment", {})
            ]
            self.assertEqual(holders, ["anchor-writer-evidence"])
            self.assertEqual(
                main["services"]["anchor-writer-evidence"]["networks"],
                ["writer-egress"],
            )
            deal = main["services"]["deal-runtime"]
            self.assertEqual(deal["profiles"], ["deal-settlement"])
            self.assertEqual(
                deal["x-dnai-capability-status"],
                "release_pinned_deterministic_evaluator",
            )
            evaluator_holders = [
                (name, service.get("environment", {}).get("TINKER_EVALUATOR_MODE"))
                for name, service in main["services"].items()
                if "TINKER_EVALUATOR_MODE" in service.get("environment", {})
            ]
            self.assertEqual(evaluator_holders, [("delegate", "deterministic")])
            evaluator_environment = main["services"]["delegate"]["environment"]
            for key in (
                "TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_PATH",
                "TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_SHA256",
                "TINKER_DILIGENCE_EVALUATOR_POLICY_SET_ROOT",
                "TINKER_DILIGENCE_CHAIN_ID",
                "TINKER_DILIGENCE_ROOM_ADDRESS",
            ):
                with self.subTest(key=key):
                    self.assertRegex(evaluator_environment[key], rf"^\$\{{{key}:\?.+\}}$")
            self.assertEqual(
                evaluator_environment["TINKER_CHAIN_CONTRACT_ADDRESS"],
                "${TINKER_CHAIN_CONTRACT_ADDRESS:?DiligenceRoom address required}",
            )
            diligence_init = main["services"]["diligence-policy-init"]
            self.assertEqual(diligence_init["network_mode"], "none")
            self.assertEqual(
                diligence_init["command"],
                ["tinker-diligence-evaluator-provision"],
            )
            self.assertEqual(
                diligence_init["volumes"],
                ["diligence-evaluator-policy:/sealed/diligence"],
            )
            self.assertIn(
                "diligence-evaluator-policy:/sealed/diligence:ro",
                main["services"]["delegate"]["volumes"],
            )
            self.assertEqual(
                main["services"]["delegate"]["depends_on"]["diligence-policy-init"],
                {"condition": "service_completed_successfully"},
            )
            self.assertEqual(deal["networks"], ["deal-control", "deal-egress"])
            self.assertNotIn("ports", deal)
            self.assertEqual(
                deal["environment"]["TINKER_QVL_AUTH_TOKEN"],
                "${TINKER_DILIGENCE_QVL_AUTH_TOKEN:-}",
            )
            self.assertIn("--attestation-release-policy-hash", deal["command"])
            self.assertIn(
                "${TINKER_DILIGENCE_QVL_RELEASE_POLICY_HASH:-}",
                deal["command"],
            )
            self.assertEqual(
                main["services"]["arena-worker"]["environment"][
                    "TINKER_ARENA_WORKER_QVL_RELEASE_POLICY_HASH"
                ],
                "${TINKER_ARENA_WORKER_QVL_RELEASE_POLICY_HASH:-}",
            )
            self.assertIn("delegate-data:/data", deal["volumes"])
            self.assertIn(
                "/var/run/dstack.sock:/var/run/dstack.sock:ro",
                deal["volumes"],
            )
            self.assertIn("deal-control", main["services"]["delegate"]["networks"])
            self.assertTrue(main["networks"]["deal-control"]["internal"])
            for service_name in (
                "oracle",
                "delegate",
                "arena-worker",
                "anchor-writer-evidence",
                "deal-runtime",
                "compute-execution-worker",
            ):
                volumes = main["services"][service_name].get("volumes", [])
                if any("dstack.sock" in str(volume) for volume in volumes):
                    self.assertIn(
                        "/var/run/dstack.sock:/var/run/dstack.sock:ro",
                        volumes,
                    )
            self.assertNotIn("ports", main["services"]["neko"])
            self.assertNotIn("ports", main["services"]["oracle"])
            self.assertEqual(main["services"]["delegate"]["ports"], ["8080:8080"])
            oracle_environment = main["services"]["oracle"]["environment"]
            for name, value in PRODUCTION_ORACLE_POLICY.items():
                self.assertEqual(oracle_environment[name], value, name)
            self.assertEqual(oracle_environment["ORACLE_PRODUCTION_RELEASE"], "true")
            self.assertEqual(oracle_environment["ORACLE_DSTACK_ENABLED"], "true")
            self.assertEqual(oracle_environment["ORACLE_RUNTIME_AUTH_REQUIRED"], "true")
            self.assertEqual(oracle_environment["ORACLE_AUTH_REQUIRED"], "true")
            self.assertEqual(
                oracle_environment["ORACLE_AUTH_CONTRACT_ADDRESS"],
                "${EMAIL_ORACLE_AUTH_ADDRESS:?Fresh EmailOracleAuth address required}",
            )
            self.assertEqual(
                oracle_environment["ORACLE_AUTH_RPC_URL"],
                "${BASE_SEPOLIA_RPC_URL:?Primary Base Sepolia HTTPS RPC URL required}",
            )
            self.assertEqual(
                oracle_environment["ORACLE_AUTH_RPC_URL_SECONDARY"],
                "${BASE_SEPOLIA_RPC_URL_SECONDARY:?Independent secondary Base Sepolia HTTPS RPC URL required}",
            )
            self.assertEqual(
                oracle_environment["ORACLE_AUTH_CONSUMER_APP_ID"],
                "${EMAIL_ORACLE_CONSUMER_APP_ID:?Release-bound main CVM TEE identity required}",
            )
            self.assertEqual(
                oracle_environment["ORACLE_AUTH_CONSUMER_COMPOSE_HASH"],
                "${EMAIL_ORACLE_CONSUMER_COMPOSE_HASH:?Release-bound main CVM compose hash required}",
            )
            self.assertEqual(
                oracle_environment["ORACLE_AUTH_EXPECTED_CALLER_IDENTITY"],
                "tinker-delegate.signup",
            )
            self.assertIn(
                "oracle-data:/data",
                main["services"]["oracle"]["volumes"],
            )
            self.assertIn("oracle-data", main["volumes"])

            topology = json.loads(result.topology.read_text(encoding="utf-8"))
            self.assertEqual(topology["schema"], "dnai.cvm-topology.v6")
            self.assertEqual(
                result.deployment_intent.read_bytes(),
                intent_path.read_bytes(),
            )
            self.assertEqual(
                topology["deploymentIntentSha256"],
                "sha256:" + hashlib.sha256(intent_path.read_bytes()).hexdigest(),
            )
            self.assertEqual(
                topology["deploymentIntent"],
                {
                    "file": "dnai-deployment-intent-core.json",
                    "sha256": hashlib.sha256(intent_path.read_bytes()).hexdigest(),
                    "schema": "dnai.deployment-intent-core.v6",
                },
            )
            self.assertEqual(result.image_manifest_attestation.read_bytes(), _bundle_bytes())
            self.assertEqual(
                topology["image_manifest_attestation"],
                {
                    "file": "dnai-tee-image-release.bundle.json",
                    "sha256": hashlib.sha256(_bundle_bytes()).hexdigest(),
                    "predicate_type": "https://slsa.dev/provenance/v1",
                },
            )
            self.assertEqual(topology["status"], "rendered_not_deployed")
            self.assertFalse(topology["checks"]["deployment_attempted"])
            self.assertFalse(topology["checks"]["tdx_verification_claimed"])
            self.assertTrue(topology["checks"]["seven_cvm_descriptors"])
            self.assertTrue(topology["checks"]["purpose_separated_qvl_descriptors"])
            self.assertEqual(
                topology["trust_domains"]["main_runtime_cvm"]["deal_settlement"],
                "release_pinned_deterministic_evaluator",
            )
            self.assertEqual(
                topology["trust_domains"]["main_runtime_cvm"][
                    "email_oracle_consumer_policy"
                ],
                "required_onchain_exact_release_binding",
            )
            self.assertEqual(
                set(topology["trust_domains"]),
                {
                    "main_runtime_cvm",
                    "diligence_qvl_cvm",
                    "arena_qvl_cvm",
                    "anchor_writer_qvl_cvm",
                    "compute_workload_qvl_cvm",
                    "compute_metering_qvl_cvm",
                    "independent_metering_cvm",
                },
            )
            qvl_hashes = {
                topology["trust_domains"][name]["sha256"]
                for name in (
                    "diligence_qvl_cvm",
                    "arena_qvl_cvm",
                    "anchor_writer_qvl_cvm",
                    "compute_workload_qvl_cvm",
                    "compute_metering_qvl_cvm",
                )
            }
            self.assertEqual(len(qvl_hashes), 5)
            for domain, intent_domain in intent_domains.items():
                self.assertEqual(
                    topology["trust_domains"][domain]["runtime_policy"],
                    _qvl_environment(
                        deployment_intent["numericPolicy"]["qvl"][intent_domain]
                    ),
                )
            self.assertEqual(
                topology["trust_domains"]["independent_metering_cvm"][
                    "runtime_policy"
                ],
                expected_metering_policy,
            )
            for domain in intent_domains:
                self.assertEqual(
                    topology["trust_domains"][domain]["phase_gate"],
                    qvls[domain]["x-dnai-phase-gate"],
                )
            self.assertEqual(
                topology["trust_domains"]["independent_metering_cvm"][
                    "phase_gate"
                ],
                metering["x-dnai-phase-gate"],
            )
            for domain in topology["trust_domains"].values():
                compose_bytes = (output / domain["compose"]).read_bytes()
                self.assertEqual(domain["sha256"], hashlib.sha256(compose_bytes).hexdigest())

    def test_real_node_check_intent_receipt_is_consumed_and_bound_byte_for_byte(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            intent = _intent()
            intent_path = _write_intent(root, intent)
            receipt = _node_receipt(intent_path)
            expected_digest = "sha256:" + hashlib.sha256(
                intent_path.read_bytes()
            ).hexdigest()
            self.assertEqual(
                receipt,
                {
                    "schema": "dnai.deployment-intent-validation-receipt.v6",
                    "status": "valid",
                    "truthStatus": (
                        "intent_shape_and_bounds_validated_not_signer_control_deployment_or_tdx"
                    ),
                    "deploymentIntentSha256": expected_digest,
                    "releaseSha": SHA,
                    "chainId": 84532,
                    "canonicalContractCount": 7,
                    "canonicalCvmCount": 7,
                    "dynamicRuntimeAuthorityCount": 0,
                    "qvlNumericPolicyCount": 5,
                    "reviewerAuthorityCurrentStatusEpoch": 1,
                    "reviewerAuthorityCurrentStatusSha256": (
                        "sha256:" + ("92" * 32)
                    ),
                    "staticContractInputCount": 2,
                },
            )
            validated = validate_deployment_intent(
                intent,
                receipt,
                SHA,
                artifact_bytes=intent_path.read_bytes(),
            )
            self.assertEqual(validated.deployment_intent_sha256, expected_digest)
            self.assertEqual(validated.release_sha, SHA)

            manifest_path = root / "input.json"
            manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
            result = render_release_composes(
                manifest_path,
                root / "release",
                manifest_attestation_bundle_path=_write_bundle(root),
                deployment_intent_path=intent_path,
                expected_release_sha=SHA,
                repository_root=REPOSITORY_ROOT,
            )
            self.assertEqual(
                result.deployment_intent.read_bytes(),
                intent_path.read_bytes(),
            )
            topology = json.loads(result.topology.read_text(encoding="utf-8"))
            self.assertEqual(
                topology["deploymentIntentSha256"],
                receipt["deploymentIntentSha256"],
            )
            self.assertEqual(
                topology["deploymentIntent"]["sha256"],
                hashlib.sha256(intent_path.read_bytes()).hexdigest(),
            )
            diligence = _load(result.diligence_qvl_compose)
            self.assertEqual(
                diligence["x-dnai-runtime-policy"]["numeric_environment"],
                _qvl_environment(intent["numericPolicy"]["qvl"]["diligence"]),
            )
            self.assertNotIn(
                "operator_policy_packet_sha256",
                diligence["x-dnai-release"],
            )

    def test_rendered_phase_gated_descriptors_build_a_launch_intent(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest_path = root / "input.json"
            manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
            intent_path = _write_intent(root)
            rendered = render_release_composes(
                manifest_path,
                root / "release",
                manifest_attestation_bundle_path=_write_bundle(root),
                deployment_intent_path=intent_path,
                expected_release_sha=SHA,
                repository_root=REPOSITORY_ROOT,
            )
            deployment_intent_sha256 = "sha256:" + hashlib.sha256(
                intent_path.read_bytes()
            ).hexdigest()
            ledger_path = root / "base-sepolia.json"
            ledger_path.write_text(
                json.dumps(
                    _fresh_contract_ledger(deployment_intent_sha256),
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            launch_path = root / "launch.json"
            receipt_path = root / "fresh-contract-receipt.json"
            completed = subprocess.run(
                [
                    "node",
                    "scripts/cvm-launch-intent.mjs",
                    "build",
                    "--topology",
                    str(rendered.topology),
                    "--ledger",
                    str(ledger_path),
                    "--out",
                    str(launch_path),
                    "--contract-receipt-out",
                    str(receipt_path),
                ],
                cwd=REPOSITORY_ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                shell=False,
                timeout=30,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout.decode("utf-8", errors="replace")
                + completed.stderr.decode("utf-8", errors="replace"),
            )
            launch = json.loads(launch_path.read_text(encoding="utf-8"))
            self.assertEqual(launch["schema"], "dnai.cvm-launch-intent-core.v3")
            self.assertEqual(len(launch["descriptors"]), 7)
            self.assertTrue(receipt_path.is_file())

    def test_rendered_topology_is_accepted_by_activation_preflight(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest_path = root / "input.json"
            manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
            rendered = render_release_composes(
                manifest_path,
                root / "release",
                manifest_attestation_bundle_path=_write_bundle(root),
                deployment_intent_path=_write_intent(root),
                expected_release_sha=SHA,
                repository_root=REPOSITORY_ROOT,
            )
            completed = subprocess.run(
                [
                    "node",
                    "--input-type=module",
                    "--eval",
                    (
                        "import { readFileSync } from 'node:fs';"
                        "import { inspectCvmTopology } from "
                        "'./scripts/activation-preflight-core.mjs';"
                        "const value = JSON.parse(readFileSync(process.argv[1], 'utf8'));"
                        "process.stdout.write(JSON.stringify(inspectCvmTopology(value)));"
                    ),
                    str(rendered.topology),
                ],
                cwd=REPOSITORY_ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                shell=False,
                timeout=30,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", errors="replace"),
            )
            result = json.loads(completed.stdout.decode("utf-8"))
            self.assertTrue(result["valid"], result)
            self.assertEqual(result["releaseSha"], SHA)
            self.assertEqual(len(result["domains"]), 7)

    def test_output_is_deterministic_and_contains_no_absolute_paths(self):
        manifest = _manifest()
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest_path = root / "input.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            bundle_path = _write_bundle(root)
            intent_path = _write_intent(root)
            first = render_release_composes(
                manifest_path,
                root / "one",
                manifest_attestation_bundle_path=bundle_path,
                deployment_intent_path=intent_path,
                expected_release_sha=SHA,
                repository_root=REPOSITORY_ROOT,
            )
            second = render_release_composes(
                manifest_path,
                root / "two",
                manifest_attestation_bundle_path=bundle_path,
                deployment_intent_path=intent_path,
                expected_release_sha=SHA,
                repository_root=REPOSITORY_ROOT,
            )
            for left, right in (
                (first.main_compose, second.main_compose),
                (first.diligence_qvl_compose, second.diligence_qvl_compose),
                (first.arena_qvl_compose, second.arena_qvl_compose),
                (first.anchor_writer_qvl_compose, second.anchor_writer_qvl_compose),
                (
                    first.compute_workload_qvl_compose,
                    second.compute_workload_qvl_compose,
                ),
                (
                    first.compute_metering_qvl_compose,
                    second.compute_metering_qvl_compose,
                ),
                (first.metering_compose, second.metering_compose),
                (
                    first.image_manifest_attestation,
                    second.image_manifest_attestation,
                ),
                (
                    first.deployment_intent,
                    second.deployment_intent,
                ),
                (first.topology, second.topology),
            ):
                self.assertEqual(left.read_bytes(), right.read_bytes())
                self.assertNotIn(str(root), left.read_text(encoding="utf-8"))
                body = "\n".join(
                    line
                    for line in left.read_text(encoding="utf-8").splitlines()
                    if not line.startswith("#")
                )
                self.assertEqual(json.loads(body), yaml.safe_load(body))

    def test_manifest_validation_rejects_drift_and_unreviewed_fields(self):
        cases = []
        missing = _manifest()
        missing["images"].pop()
        cases.append(missing)
        reordered = _manifest()
        reordered["images"][0], reordered["images"][1] = (
            reordered["images"][1],
            reordered["images"][0],
        )
        cases.append(reordered)
        external = _manifest()
        external["images"][0]["repository"] = "ghcr.io/someone-else/tinker-delegate"
        cases.append(external)
        mutable = _manifest()
        mutable["images"][0]["digest"] = "latest"
        cases.append(mutable)
        drifted = _manifest()
        drifted["images"][0]["verification"]["source_digest"] = "b" * 40
        cases.append(drifted)
        extra = _manifest()
        extra["unreviewed"] = True
        cases.append(extra)

        for case in cases:
            with self.subTest(case=cases.index(case)):
                with self.assertRaises(ReleaseComposeError):
                    validate_image_release(case, SHA)

    def test_deployment_intent_receipt_rejects_digest_release_count_and_extra_drift(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            intent = _intent()
            intent_path = _write_intent(root, intent)
            receipt = _node_receipt(intent_path)
            cases = []
            for name, value in (
                ("deploymentIntentSha256", f"sha256:{'f' * 64}"),
                ("releaseSha", "b" * 40),
                ("staticContractInputCount", 3),
                ("dynamicRuntimeAuthorityCount", 1),
                ("canonicalContractCount", True),
                ("chainId", 84532.0),
                ("reviewerAuthorityCurrentStatusEpoch", 2),
                (
                    "reviewerAuthorityCurrentStatusSha256",
                    "sha256:" + ("93" * 32),
                ),
            ):
                changed = dict(receipt)
                changed[name] = value
                cases.append(changed)
            extra = dict(receipt)
            extra["postDeployEnv"] = {"DILIGENCE_TEE_IDENTITY": "forbidden"}
            cases.append(extra)
            for index, changed in enumerate(cases):
                with self.subTest(index=index), self.assertRaises(ReleaseComposeError):
                    validate_deployment_intent(
                        intent,
                        changed,
                        SHA,
                        artifact_bytes=intent_path.read_bytes(),
                    )

    def test_deployment_intent_v6_independently_validates_current_reviewer_head(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            valid = _intent()
            valid_path = _write_intent(root, valid)
            valid_receipt = _node_receipt(valid_path)
            cases = (
                ("reviewerAuthorityCurrentStatusEpoch", 0, "current-status epoch"),
                ("reviewerAuthorityCurrentStatusEpoch", True, "current-status epoch"),
                (
                    "reviewerAuthorityCurrentStatusEpoch",
                    4_294_967_296,
                    "current-status epoch",
                ),
                (
                    "reviewerAuthorityCurrentStatusSha256",
                    "sha256:" + ("0" * 64),
                    "current-status digest",
                ),
                (
                    "reviewerAuthorityCurrentStatusSha256",
                    "92" * 32,
                    "current-status digest",
                ),
            )
            for field, value, message in cases:
                changed = deepcopy(valid)
                changed["release"][field] = value
                changed_bytes = _canonical_json(changed)
                changed_receipt = dict(valid_receipt)
                changed_receipt["deploymentIntentSha256"] = (
                    "sha256:" + hashlib.sha256(changed_bytes).hexdigest()
                )
                changed_receipt[field] = value
                with self.subTest(field=field, value=value), self.assertRaisesRegex(
                    ReleaseComposeError,
                    message,
                ):
                    validate_deployment_intent(
                        changed,
                        changed_receipt,
                        SHA,
                        artifact_bytes=changed_bytes,
                    )

    def test_deployment_intent_v6_rejects_toolchain_drift_even_with_matching_bytes_digest(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            valid_path = _write_intent(root, _intent())
            receipt = _node_receipt(valid_path)
            changed = _intent()
            changed["release"]["toolchain"]["solidity"]["optimizerRuns"] = 201
            changed_bytes = _canonical_json(changed)
            receipt["deploymentIntentSha256"] = (
                "sha256:" + hashlib.sha256(changed_bytes).hexdigest()
            )
            with self.assertRaisesRegex(ReleaseComposeError, "exact build authority"):
                validate_deployment_intent(
                    changed,
                    receipt,
                    SHA,
                    artifact_bytes=changed_bytes,
                )

    def test_deployment_intent_is_required_canonical_bounded_and_no_follow(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest_path = root / "input.json"
            manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
            bundle_path = _write_bundle(root)
            output = root / "release"

            missing = root / "missing-intent.json"
            with self.assertRaisesRegex(ReleaseComposeError, "deployment intent"):
                render_release_composes(
                    manifest_path,
                    output,
                    manifest_attestation_bundle_path=bundle_path,
                    deployment_intent_path=missing,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )

            canonical = _write_intent(root)
            linked = root / "linked-intent.json"
            linked.symlink_to(canonical)
            with self.assertRaisesRegex(ReleaseComposeError, "deployment intent"):
                render_release_composes(
                    manifest_path,
                    output,
                    manifest_attestation_bundle_path=bundle_path,
                    deployment_intent_path=linked,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )

            compact = root / "compact-intent.json"
            compact.write_text(json.dumps(_intent()), encoding="utf-8")
            with self.assertRaisesRegex(ReleaseComposeError, "checker rejected"):
                render_release_composes(
                    manifest_path,
                    output,
                    manifest_attestation_bundle_path=bundle_path,
                    deployment_intent_path=compact,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )

            duplicate = root / "duplicate-intent.json"
            duplicate.write_text(
                canonical.read_text(encoding="utf-8").replace(
                    '  "schema": "dnai.deployment-intent-core.v6",',
                    '  "schema": "dnai.deployment-intent-core.v6",\n  "schema": "dnai.deployment-intent-core.v6",',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ReleaseComposeError, "checker rejected"):
                render_release_composes(
                    manifest_path,
                    output,
                    manifest_attestation_bundle_path=bundle_path,
                    deployment_intent_path=duplicate,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )
            self.assertFalse(output.exists())

    def test_old_projection_artifact_and_cli_flag_are_absent(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest_path = root / "input.json"
            manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
            old_projection = _write_old_projection(root)
            with self.assertRaisesRegex(ReleaseComposeError, "checker rejected"):
                render_release_composes(
                    manifest_path,
                    root / "release",
                    manifest_attestation_bundle_path=_write_bundle(root),
                    deployment_intent_path=old_projection,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )
            parser = release_composes_module._parser()
            option_strings = {
                option
                for action in parser._actions
                for option in action.option_strings
            }
            self.assertIn("--deployment-intent", option_strings)
            self.assertNotIn("--operator-policy-projection", option_strings)

    def test_deployment_intent_is_re_read_after_checker_to_close_toctou(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            intent = _intent()
            intent_path = _write_intent(root, intent)
            receipt = _node_receipt(intent_path)
            completed = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=(json.dumps(receipt, indent=2) + "\n").encode("utf-8"),
                stderr=b"",
            )
            changed = deepcopy(intent)
            for qvl_policy in changed["numericPolicy"]["qvl"].values():
                qvl_policy["rateCapacity"] = 31

            def race(command, **kwargs):
                self.assertEqual(
                    command,
                    [
                        "node",
                        str(REPOSITORY_ROOT / "scripts/operator-policy-packet.mjs"),
                        "check-intent",
                        "--in",
                        str(intent_path),
                    ],
                )
                self.assertIs(kwargs["shell"], False)
                self.assertEqual(kwargs["cwd"], REPOSITORY_ROOT)
                intent_path.write_bytes(_canonical_json(changed))
                return completed

            manifest_path = root / "input.json"
            manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
            output = root / "release"
            with patch.object(
                release_composes_module.subprocess,
                "run",
                side_effect=race,
            ), self.assertRaisesRegex(
                ReleaseComposeError,
                "changed during external validation",
            ):
                render_release_composes(
                    manifest_path,
                    output,
                    manifest_attestation_bundle_path=_write_bundle(root),
                    deployment_intent_path=intent_path,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )
            self.assertFalse(output.exists())

    def test_release_sha_mismatch_fails_before_writing(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest_path = root / "input.json"
            manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
            bundle_path = _write_bundle(root)
            intent_path = _write_intent(root)
            output = root / "release"
            with self.assertRaisesRegex(ReleaseComposeError, "reviewed release SHA"):
                render_release_composes(
                    manifest_path,
                    output,
                    manifest_attestation_bundle_path=bundle_path,
                    deployment_intent_path=intent_path,
                    expected_release_sha="b" * 40,
                    repository_root=REPOSITORY_ROOT,
                )
            self.assertFalse(output.exists())

    def test_manifest_urls_are_exactly_bound_to_their_ids(self):
        cases = []
        workflow_suffix = _manifest()
        workflow_suffix["workflow_run_url"] += "/extra"
        cases.append(workflow_suffix)
        workflow_query = _manifest()
        workflow_query["workflow_run_url"] += "?attempt=2"
        cases.append(workflow_query)
        attestation_suffix = _manifest()
        attestation_suffix["images"][0]["attestations"]["provenance"]["url"] += "0"
        cases.append(attestation_suffix)
        attestation_query = _manifest()
        attestation_query["images"][0]["attestations"]["sbom"]["url"] += "?raw=1"
        cases.append(attestation_query)
        offset_timestamp = _manifest()
        offset_timestamp["generated_at"] = "2026-07-15T13:00:00.000+01:00"
        cases.append(offset_timestamp)

        for index, case in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(ReleaseComposeError):
                    validate_image_release(case, SHA)

    def test_secret_placeholders_reject_nonempty_defaults_and_literals(self):
        for value in ("literal-secret", "${TOKEN:-literal-secret}", "${TOKEN-literal-secret}"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ReleaseComposeError, "secret-shaped literal"):
                    _validate_secret_placeholders(
                        "main",
                        {"service": {"environment": {"SERVICE_API_KEY": value}}},
                    )
        for value in ("", "${TOKEN}", "${TOKEN:-}", "${TOKEN:?required}"):
            with self.subTest(value=value):
                _validate_secret_placeholders(
                    "main",
                    {"service": {"environment": {"SERVICE_API_KEY": value}}},
                )

    def test_production_oracle_policy_rejects_every_critical_setting_drift(self):
        for name, expected in PRODUCTION_ORACLE_POLICY.items():
            unsafe = dict(PRODUCTION_ORACLE_POLICY)
            unsafe[name] = "true" if expected == "false" else "unsafe-drift"
            with self.subTest(name=name), self.assertRaisesRegex(
                ReleaseComposeError,
                "exact on-chain and sealed-state policy",
            ):
                _validate_production_oracle_environment(unsafe)

    def test_source_templates_share_exact_email_oracle_release_policy(self):
        phala = _load_yaml(PROJECT_ROOT / "docker-compose.all.phala.yaml")
        dstack = _load_yaml(
            PROJECT_ROOT / "docker-compose.all.dstack.yaml",
            overlay=True,
        )

        for template_name, compose in (
            ("docker-compose.all.phala.yaml", phala),
            ("docker-compose.all.dstack.yaml", dstack),
        ):
            with self.subTest(template=template_name):
                environment = compose["services"]["oracle"]["environment"]
                for name, value in PRODUCTION_ORACLE_POLICY.items():
                    self.assertEqual(environment.get(name), value, name)

        self.assertIn("oracle-data:/data", phala["services"]["oracle"]["volumes"])
        self.assertIn("oracle-data", phala["volumes"])

        local_base = _load_yaml(PROJECT_ROOT / "docker-compose.all.yaml")
        self.assertIn(
            "oracle-data:/data",
            local_base["services"]["oracle"]["volumes"],
        )
        self.assertIn("oracle-data", local_base["volumes"])

    def test_compose_loader_accepts_security_override_directive(self):
        dstack = _load_yaml(
            PROJECT_ROOT / "docker-compose.all.dstack.yaml",
            overlay=True,
        )

        self.assertEqual(
            dstack["services"]["diligence-policy-init"]["security_opt"],
            ["no-new-privileges:true"],
        )

    def test_manifest_attestation_bundle_is_required_bounded_and_no_follow(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest_path = root / "input.json"
            manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
            intent_path = _write_intent(root)
            output = root / "release"
            missing = root / "missing.bundle.json"
            with self.assertRaisesRegex(ReleaseComposeError, "attestation bundle"):
                render_release_composes(
                    manifest_path,
                    output,
                    manifest_attestation_bundle_path=missing,
                    deployment_intent_path=intent_path,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )

            actual = _write_bundle(root)
            linked = root / "linked.bundle.json"
            linked.symlink_to(actual)
            with self.assertRaisesRegex(ReleaseComposeError, "attestation bundle"):
                render_release_composes(
                    manifest_path,
                    output,
                    manifest_attestation_bundle_path=linked,
                    deployment_intent_path=intent_path,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )

            malformed = root / "malformed.bundle.json"
            malformed.write_text("{\n", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseComposeError, "invalid JSON"):
                render_release_composes(
                    manifest_path,
                    output,
                    manifest_attestation_bundle_path=malformed,
                    deployment_intent_path=intent_path,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )

            empty = root / "empty.bundle.json"
            empty.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseComposeError, "non-empty JSON object"):
                render_release_composes(
                    manifest_path,
                    output,
                    manifest_attestation_bundle_path=empty,
                    deployment_intent_path=intent_path,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )
            self.assertFalse(output.exists())

    def test_manifest_symlink_and_duplicate_json_keys_fail_closed(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            actual = root / "actual.json"
            actual.write_text(json.dumps(_manifest()), encoding="utf-8")
            bundle_path = _write_bundle(root)
            intent_path = _write_intent(root)
            symlink = root / "symlink.json"
            symlink.symlink_to(actual)
            with self.assertRaises(ReleaseComposeError):
                render_release_composes(
                    symlink,
                    root / "symlink-output",
                    manifest_attestation_bundle_path=bundle_path,
                    deployment_intent_path=intent_path,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )

            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema":"dnai.tee-image-release.v1","schema":"duplicate"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ReleaseComposeError, "repeats JSON field schema"):
                render_release_composes(
                    duplicate,
                    root / "duplicate-output",
                    manifest_attestation_bundle_path=bundle_path,
                    deployment_intent_path=intent_path,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )

    def test_duplicate_compose_template_keys_and_output_symlinks_fail_closed(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            duplicate = root / "duplicate.yaml"
            duplicate.write_text(
                "services:\n  worker:\n    image: first\n  worker:\n    image: second\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ReleaseComposeError, "could not load"):
                _load_yaml(duplicate)

            manifest_path = root / "input.json"
            manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
            bundle_path = _write_bundle(root)
            intent_path = _write_intent(root)
            output = root / "release"
            output.mkdir()
            target = root / "must-not-change"
            target.write_text("sentinel", encoding="utf-8")
            (output / "dnai-main-runtime.phala.yaml").symlink_to(target)
            with self.assertRaisesRegex(ReleaseComposeError, "symlink"):
                render_release_composes(
                    manifest_path,
                    output,
                    manifest_attestation_bundle_path=bundle_path,
                    deployment_intent_path=intent_path,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel")

    def test_topology_is_not_replaced_when_the_final_publication_fails(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest_path = root / "input.json"
            manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
            bundle_path = _write_bundle(root)
            intent_path = _write_intent(root)
            output = root / "release"
            output.mkdir()
            topology_path = output / "dnai-cvm-topology.json"
            previous_topology = '{"schema":"old-generation-sentinel"}\n'
            topology_path.write_text(previous_topology, encoding="utf-8")

            real_atomic_write = release_composes_module._atomic_write

            def fail_on_topology(path: Path, value: bytes, *, mode: int = 0o644):
                if path.name == "dnai-cvm-topology.json":
                    raise ReleaseComposeError("injected final publication failure")
                return real_atomic_write(path, value, mode=mode)

            with patch.object(
                release_composes_module,
                "_atomic_write",
                side_effect=fail_on_topology,
            ), self.assertRaisesRegex(
                ReleaseComposeError,
                "injected final publication failure",
            ):
                render_release_composes(
                    manifest_path,
                    output,
                    manifest_attestation_bundle_path=bundle_path,
                    deployment_intent_path=intent_path,
                    expected_release_sha=SHA,
                    repository_root=REPOSITORY_ROOT,
                )

            self.assertTrue((output / "dnai-main-runtime.phala.yaml").is_file())
            self.assertEqual(
                topology_path.read_text(encoding="utf-8"),
                previous_topology,
            )
            self.assertNotIn(
                hashlib.sha256(
                    (output / "dnai-main-runtime.phala.yaml").read_bytes()
                ).hexdigest(),
                previous_topology,
            )


if __name__ == "__main__":
    unittest.main()

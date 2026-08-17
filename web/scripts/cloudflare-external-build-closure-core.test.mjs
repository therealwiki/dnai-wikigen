import assert from "node:assert/strict";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  __test as closureTest,
  canonicalCloudflareExternalBuildClosureText,
  cloudflareExternalBuildClosureSha256,
  CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS,
  CLOUDFLARE_EXTERNAL_BUILD_FILES,
  normalizeCloudflareExternalBuildClosure,
  projectCloudflareExternalBuildClosure,
} from "./cloudflare-external-build-closure-core.mjs";

const MODULE_SOURCES = Object.freeze({
  "scripts/build-tee-image-release.mjs": [
    'import "node:crypto";',
    'import "node:fs";',
    'import "node:fs/promises";',
    'import "node:path";',
    'import "node:url";',
    'import { publicHttpsUrl } from "./canonical-public-https-url-core.mjs";',
    'new URL("./build-tee-image-release.mjs", import.meta.url);',
    "export const imageRelease = publicHttpsUrl;",
    "",
  ].join("\n"),
  "scripts/canonical-authority-graph.mjs": [
    'import "node:util";',
    "export const canonical = true;",
    "",
  ].join("\n"),
  "scripts/canonical-public-https-url-core.mjs":
    "export const publicHttpsUrl = true;\n",
  "scripts/compute-workload-activation-observation-core.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    'import { evidence } from "./phala-seven-cvm-historical-evidence-core.mjs";',
    'import { release as releaseLegacy } from "./phala-seven-cvm-release-verification-authority-core.mjs";',
    'import { release as releaseCurrent } from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";',
    'import { signature } from "./release-authority-signature-verifier-core.mjs";',
    "export const observation = canonical && evidence && releaseLegacy && releaseCurrent && signature;",
    "",
  ].join("\n"),
  "scripts/cvm-descriptor-runtime-authority-core.mjs": [
    'import { v1Policy } from "./cvm-descriptor-runtime-authority-v1-policy.mjs";',
    'import { descriptors } from "./cvm-release-descriptor-set-constants.mjs";',
    "export const descriptor = v1Policy && descriptors;",
    "",
  ].join("\n"),
  "scripts/cvm-descriptor-runtime-authority-v1-policy.mjs": [
    'import "node:crypto";',
    'import { canonical } from "./canonical-authority-graph.mjs";',
    'import { launch } from "./cvm-launch-intent-core.mjs";',
    "export const v1Policy = canonical && launch;",
    "",
  ].join("\n"),
  "scripts/cvm-descriptor-runtime-authority-v2-core.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    'import { descriptors } from "./cvm-release-descriptor-set-constants-v3.mjs";',
    "export const descriptorV2 = canonical && descriptors;",
    "",
  ].join("\n"),
  "scripts/cvm-descriptor-runtime-authority-v2.mjs": [
    'import "node:crypto";',
    'import "node:fs";',
    'import "node:fs/promises";',
    'import "node:path";',
    'import { descriptorSet } from "./cvm-release-descriptor-set-v3.mjs";',
    'import { descriptorV2 } from "./cvm-descriptor-runtime-authority-v2-core.mjs";',
    "export const descriptorAuthorityV2 = descriptorSet && descriptorV2;",
    "",
  ].join("\n"),
  "scripts/cvm-launch-intent-core.mjs": [
    'import { policy } from "./phala-production-execution-policy.mjs";',
    "export const launch = policy;",
    "",
  ].join("\n"),
  "scripts/cvm-release-descriptor-set-constants.mjs":
    "export const descriptors = true;\n",
  "scripts/cvm-release-descriptor-set-constants-v3.mjs":
    "export const descriptors = true;\n",
  "scripts/cvm-release-descriptor-set-v3.mjs": [
    'import "node:child_process";',
    'import "node:crypto";',
    'import "node:fs";',
    'import "node:fs/promises";',
    'import "node:os";',
    'import "node:path";',
    'import "node:url";',
    'import "node:util";',
    'import { imageRelease } from "./build-tee-image-release.mjs";',
    'import { descriptors } from "./cvm-release-descriptor-set-constants-v3.mjs";',
    'new URL("./cvm-release-descriptor-set-v3.mjs", import.meta.url);',
    "export const descriptorSet = imageRelease && descriptors;",
    "",
  ].join("\n"),
  "scripts/ethereum-keccak.mjs": "export const keccak = true;\n",
  "scripts/exact-model-a-dependency-graph.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    "export const exactGraph = canonical;",
    "",
  ].join("\n"),
  "scripts/exact37-model-a-semantic-validator.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    'import { packet } from "./operator-policy-packet-core.mjs";',
    'import { signature } from "./release-authority-signature-verifier-core.mjs";',
    'import { reviewer } from "./release-reviewer-authority-core.mjs";',
    'import { launch } from "./cvm-launch-intent-core.mjs";',
    'import { bootstrap } from "./phala-bootstrap-public-environment-authority-core.mjs";',
    'import { nonlive } from "./phala-nonlive-bootstrap-authorization-core.mjs";',
    'import { executor } from "./phala-executor-state-core.mjs";',
    'import { completion } from "./phala-seven-cvm-launch-completion-core.mjs";',
    'import { preCeremony } from "./pre-ceremony-runtime-authority-core.mjs";',
    'import { transcript } from "./phala-seven-cvm-historical-transcript.mjs";',
    'import { manifestDescriptor } from "./release-manifest-descriptor-historical-core.mjs";',
    'import { observation } from "./compute-workload-activation-observation-core.mjs";',
    'import { receipt } from "./phala-post-measurement-activation-receipt-core.mjs";',
    'import { historical } from "./release-authority-historical-core.mjs";',
    'import { execution } from "./execution-policy-release-core.mjs";',
    'import { frontendHistorical } from "../web/scripts/frontend-release-historical-core.mjs";',
    'import { evidence } from "./phala-seven-cvm-historical-evidence-core.mjs";',
    'import { externalFive } from "../web/scripts/external-five-historical-evidence-core.mjs";',
    'import { replay } from "../web/scripts/independent-eip191-replay-core.mjs";',
    'import { exactGraph } from "./exact-model-a-dependency-graph.mjs";',
    'import { historicalAuthority } from "./phala-seven-cvm-historical-release-verification-authority.mjs";',
    'import { verifierEvidence } from "./phala-seven-cvm-verifier-evidence.mjs";',
    "export const exact37 = Boolean(canonical && packet && signature && reviewer && launch",
    "  && bootstrap && nonlive && executor && completion && preCeremony && transcript",
    "  && manifestDescriptor && observation && receipt && historical && execution",
    "  && frontendHistorical && evidence && externalFive && replay && exactGraph",
    "  && historicalAuthority && verifierEvidence);",
    "",
  ].join("\n"),
  "scripts/execution-policy-release-core-v3-historical.fixture.mjs":
    "export const historicalFixture = true;\n",
  "scripts/execution-policy-release-core-v3-historical.mjs": [
    'import "node:crypto";',
    'import "node:url";',
    "export const historicalExecution = true;",
    "",
  ].join("\n"),
  "scripts/execution-policy-release-core.fixture.mjs": [
    'import { execution } from "./execution-policy-release-core.mjs";',
    "export const fixture = execution;",
    "",
  ].join("\n"),
  "scripts/execution-policy-release-core.mjs": [
    'import { keccak } from "./ethereum-keccak.mjs";',
    "export const execution = keccak;",
    "",
  ].join("\n"),
  "scripts/frontend-build-candidate-receipt-core.mjs": [
    'import "node:crypto";',
    'import { canonical } from "./canonical-authority-graph.mjs";',
    "export const frontendReceipt = canonical;",
    "",
  ].join("\n"),
  "scripts/operator-policy-packet-core.mjs": [
    'import { execution } from "./execution-policy-release-core.mjs";',
    'import { launch } from "./cvm-launch-intent-core.mjs";',
    'import { tinkerBinding } from "./tinker-account-binding-core.mjs";',
    "export const packet = execution && launch && tinkerBinding;",
    "",
  ].join("\n"),
  "scripts/phala-bootstrap-public-environment-authority-core.mjs": [
    'import { launch } from "./cvm-launch-intent-core.mjs";',
    'import { publicHttpsUrl } from "./canonical-public-https-url-core.mjs";',
    "export const bootstrap = launch && publicHttpsUrl;",
    "",
  ].join("\n"),
  "scripts/phala-executor-state-core.mjs": [
    'import { posture } from "./phala-production-posture-core.mjs";',
    "export const executor = posture;",
    "",
  ].join("\n"),
  "scripts/phala-nonlive-bootstrap-authorization-core.mjs": [
    'import { launch } from "./cvm-launch-intent-core.mjs";',
    'import { bootstrap } from "./phala-bootstrap-public-environment-authority-core.mjs";',
    'import { signature } from "./release-authority-signature-verifier-core.mjs";',
    "export const nonlive = launch && bootstrap && signature;",
    "",
  ].join("\n"),
  "scripts/phala-nonlive-bootstrap-authorization.mjs": [
    'import "node:crypto";',
    'import "node:fs";',
    'import "node:path";',
    'import { nonlive } from "./phala-nonlive-bootstrap-authorization-core.mjs";',
    'import { descriptorSet } from "./cvm-release-descriptor-set-v3.mjs";',
    'import { targetAuthority } from "./phala-production-target-authority.mjs";',
    'import { signatureRuntime } from "./release-authority-signature-verifier.mjs";',
    'import { reviewerGenesis } from "./release-reviewer-authority-genesis.mjs";',
    'import { reviewerAcceptance } from "./release-reviewer-authority-genesis-acceptance.mjs";',
    "export const nonliveRuntime = Boolean(nonlive && descriptorSet && targetAuthority",
    "  && signatureRuntime && reviewerGenesis && reviewerAcceptance);",
    "",
  ].join("\n"),
  "scripts/phala-post-measurement-activation-core.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    'import { release as releaseLegacy } from "./phala-seven-cvm-release-verification-authority-core.mjs";',
    'import { release as releaseCurrent } from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";',
    "export const activation = canonical && releaseLegacy && releaseCurrent;",
    "",
  ].join("\n"),
  "scripts/phala-post-measurement-activation-receipt-core.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    "export const receipt = canonical;",
    "",
  ].join("\n"),
  "scripts/phala-production-execution-policy.mjs": "export const policy = true;\n",
  "scripts/phala-production-posture-core.mjs": [
    'import { launch } from "./cvm-launch-intent-core.mjs";',
    "export const posture = launch;",
    "",
  ].join("\n"),
  "scripts/phala-production-posture-receipt.mjs": [
    'import "node:crypto";',
    'import { posture } from "./phala-production-posture-core.mjs";',
    "export const postureReceipt = posture;",
    "",
  ].join("\n"),
  "scripts/phala-production-target-authority.mjs": [
    'import "node:crypto";',
    'import { launch } from "./cvm-launch-intent-core.mjs";',
    'import { publicHttpsUrl } from "./canonical-public-https-url-core.mjs";',
    "export const targetAuthority = launch && publicHttpsUrl;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-historical-evidence-core.mjs": [
    'import { runtime } from "./phala-seven-cvm-historical-runtime-binding-core.mjs";',
    'import { transcript } from "./phala-seven-cvm-historical-transcript.mjs";',
    'import { measurement } from "./phala-seven-cvm-measurement-policy.mjs";',
    'import { release } from "./phala-seven-cvm-release-verification-authority-core.mjs";',
    'import { replay } from "../web/scripts/independent-eip191-replay-core.mjs";',
    "export const evidence = runtime && transcript && measurement && release && replay;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-historical-release-verification-authority.mjs": [
    'import { release } from "./phala-seven-cvm-release-verification-authority-core.mjs";',
    'import { nonlive } from "./phala-nonlive-bootstrap-authorization-core.mjs";',
    'import { reviewerCurrent } from "./release-authority-current-reviewer-facade.mjs";',
    'import { signature } from "./release-authority-signature-verifier-core.mjs";',
    "export const historicalAuthority = release && nonlive && reviewerCurrent && signature;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-historical-runtime-binding-core.mjs": [
    'import { transcript } from "./phala-seven-cvm-historical-transcript.mjs";',
    'import { release } from "./phala-seven-cvm-release-verification-authority-core.mjs";',
    "export const runtime = transcript && release;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-historical-transcript.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    "export const transcript = canonical;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-launch-completion-core.mjs": [
    'import { launch } from "./cvm-launch-intent-core.mjs";',
    'import { executor } from "./phala-executor-state-core.mjs";',
    'import { posture } from "./phala-production-posture-core.mjs";',
    'import { runtime } from "./phala-seven-cvm-historical-runtime-binding-core.mjs";',
    'import { transcript } from "./phala-seven-cvm-historical-transcript.mjs";',
    'import { release as releaseLegacy } from "./phala-seven-cvm-release-verification-authority-core.mjs";',
    'import { release as releaseCurrent } from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";',
    "export const completion = launch && executor && posture && runtime && transcript && releaseLegacy && releaseCurrent;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-measurement-policy.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    "export const measurement = canonical;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-opened-fd-runtime-core.mjs": [
    'import "node:child_process";',
    'import "node:crypto";',
    'import "node:fs";',
    'import "node:os";',
    'import "node:path";',
    "export const openedRuntime = true;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-release-verification-authority-core.mjs": [
    'import { launch } from "./cvm-launch-intent-core.mjs";',
    'import { descriptor } from "./cvm-descriptor-runtime-authority-core.mjs";',
    'import { measurement } from "./phala-seven-cvm-measurement-policy.mjs";',
    "export const release = launch && descriptor && measurement;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-release-verification-authority-v4-core.mjs": [
    'import { launch } from "./cvm-launch-intent-core.mjs";',
    'import { descriptorV2 } from "./cvm-descriptor-runtime-authority-v2-core.mjs";',
    'import { measurement } from "./phala-seven-cvm-measurement-policy.mjs";',
    "export const release = launch && descriptorV2 && measurement;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-verifier-evidence.mjs": [
    'import "node:child_process";',
    'import "node:crypto";',
    'import "node:fs";',
    'import "node:path";',
    'import "node:url";',
    'import { descriptorAuthorityV2 } from "./cvm-descriptor-runtime-authority-v2.mjs";',
    'import { nonliveRuntime } from "./phala-nonlive-bootstrap-authorization.mjs";',
    'import { postureReceipt } from "./phala-production-posture-receipt.mjs";',
    'import { openedRuntime } from "./phala-seven-cvm-opened-fd-runtime-core.mjs";',
    'import { historicalAuthority } from "./phala-seven-cvm-historical-release-verification-authority.mjs";',
    'import { release as releaseLegacy } from "./phala-seven-cvm-release-verification-authority-core.mjs";',
    'import { release as releaseCurrent } from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";',
    'new URL("./phala-seven-cvm-dcap-verify.py", import.meta.url);',
    "export const verifierEvidence = Boolean(descriptorAuthorityV2 && nonliveRuntime",
    "  && postureReceipt && openedRuntime && historicalAuthority && releaseLegacy",
    "  && releaseCurrent);",
    "",
  ].join("\n"),
  "scripts/pre-ceremony-runtime-authority-core.mjs": [
    'import { activation } from "./phala-post-measurement-activation-core.mjs";',
    'import { runtime } from "./phala-seven-cvm-historical-runtime-binding-core.mjs";',
    "export const preCeremony = activation && runtime;",
    "",
  ].join("\n"),
  "scripts/release-authority-current-c-v6-core.mjs": [
    'import { liveAuthorization } from "./release-ceremony-authorization.mjs";',
    'import { currentStage } from "./release-authority-stages.mjs";',
    "export const currentC = liveAuthorization && currentStage;",
    "",
  ].join("\n"),
  "scripts/release-authority-current-reviewer-facade.mjs": [
    'import { reviewerGenesis } from "./release-reviewer-authority-genesis.mjs";',
    'import { reviewerAcceptance } from "./release-reviewer-authority-genesis-acceptance.mjs";',
    'import { signatureRuntime } from "./release-authority-signature-verifier.mjs";',
    "export const reviewerCurrent = reviewerGenesis && reviewerAcceptance && signatureRuntime;",
    "",
  ].join("\n"),
  "scripts/release-authority-historical-core.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    'import { receipt } from "./phala-post-measurement-activation-receipt-core.mjs";',
    'import { signature } from "./release-authority-signature-verifier-core.mjs";',
    "export const historical = canonical && receipt && signature;",
    "",
  ].join("\n"),
  "scripts/release-authority-signature-verifier-core.mjs": [
    'import { replay } from "../web/scripts/independent-eip191-replay-core.mjs";',
    "export const signature = replay;",
    "",
  ].join("\n"),
  "scripts/release-authority-signature-verifier.mjs": [
    'import "node:child_process";',
    'import "node:crypto";',
    'import "node:fs";',
    'import "node:os";',
    'import "node:path";',
    'import { signature } from "./release-authority-signature-verifier-core.mjs";',
    "export const signatureRuntime = signature;",
    "",
  ].join("\n"),
  "scripts/release-authority-stages.mjs": [
    'import "node:crypto";',
    'import "node:path";',
    'import { frontendReceipt } from "./frontend-build-candidate-receipt-core.mjs";',
    'import { liveAuthorization } from "./release-ceremony-authorization.mjs";',
    'import { lockProtocol } from "./release-ceremony-lock-protocol-core.mjs";',
    "export const currentStage = frontendReceipt && liveAuthorization && lockProtocol;",
    "",
  ].join("\n"),
  "scripts/release-ceremony-authorization.mjs": [
    'import "node:crypto";',
    'import "node:path";',
    'import { preCeremony } from "./pre-ceremony-runtime-authority-core.mjs";',
    'import { packet } from "./operator-policy-packet-core.mjs";',
    'import { lockProtocol } from "./release-ceremony-lock-protocol-core.mjs";',
    'import { signatureRuntime } from "./release-authority-signature-verifier.mjs";',
    'import { reviewerGenesis } from "./release-reviewer-authority-genesis.mjs";',
    'import { reviewerCurrent } from "./release-authority-current-reviewer-facade.mjs";',
    'import { launch } from "./cvm-launch-intent-core.mjs";',
    'import { historical } from "./release-authority-historical-core.mjs";',
    "export const liveAuthorization = Boolean(preCeremony && packet && lockProtocol",
    "  && signatureRuntime && reviewerGenesis && reviewerCurrent && launch && historical);",
    "",
  ].join("\n"),
  "scripts/release-ceremony-lock-protocol-core.mjs":
    "export const lockProtocol = true;\n",
  "scripts/release-manifest-descriptor-historical-core.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    "export const manifestDescriptor = canonical;",
    "",
  ].join("\n"),
  "scripts/release-manifest-sigstore-verifier.mjs": [
    'import "node:child_process";',
    'import { createHash } from "node:crypto";',
    'import "node:fs";',
    'import "node:fs/promises";',
    'import "node:path";',
    'export const verifier = createHash("sha256").digest("hex");',
    "",
  ].join("\n"),
  "scripts/release-reviewer-authority-core.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    'import { signature } from "./release-authority-signature-verifier-core.mjs";',
    "export const reviewer = canonical && signature;",
    "",
  ].join("\n"),
  "scripts/release-reviewer-authority-genesis-acceptance.mjs": [
    'import "node:crypto";',
    'import { reviewerGenesis } from "./release-reviewer-authority-genesis.mjs";',
    'import { signatureRuntime } from "./release-authority-signature-verifier.mjs";',
    "export const reviewerAcceptance = reviewerGenesis && signatureRuntime;",
    "",
  ].join("\n"),
  "scripts/release-reviewer-authority-genesis.mjs": [
    'import "node:crypto";',
    'import { signatureRuntime } from "./release-authority-signature-verifier.mjs";',
    "export const reviewerGenesis = signatureRuntime;",
    "",
  ].join("\n"),
  "scripts/royalty-release-authority-core.mjs": [
    'import "node:crypto";',
    'import { keccak } from "./ethereum-keccak.mjs";',
    "export const royaltyAuthority = keccak;",
    "",
  ].join("\n"),
  "scripts/royalty-release-history-receipt-core.mjs": [
    'import "node:crypto";',
    'import { royaltyAuthority } from "./royalty-release-authority-core.mjs";',
    "export const royaltyHistory = royaltyAuthority;",
    "",
  ].join("\n"),
  "scripts/tinker-account-binding-core.mjs": [
    'import "node:crypto";',
    'import { keccak } from "./ethereum-keccak.mjs";',
    "export const tinkerBinding = keccak;",
    "",
  ].join("\n"),
  "web/scripts/independent-eip191-replay-core.mjs": [
    'import "@noble/curves/secp256k1";',
    'import "@noble/hashes/sha3";',
    'import "@noble/hashes/utils";',
    "export const replay = true;",
    "",
  ].join("\n"),
});

const WEB_SCRIPT_SOURCES = Object.freeze({
  "web/scripts/bootstrap-retirement.test.mjs":
    'new URL("./bootstrap-retirement.test.mjs", import.meta.url);\n',
  "web/scripts/cloudflare-external-build-closure-core.mjs":
    'new URL("../node_modules/typescript/lib/typescript.js", import.meta.url);\n',
  "web/scripts/cloudflare-external-build-closure-core.test.mjs": [
    'new URL("../..", import.meta.url);',
    'new URL("../node_modules/typescript/lib/typescript.js", import.meta.url);',
    "",
  ].join("\n"),
  "web/scripts/cloudflare-release-artifact-core.test.mjs":
    'new URL("../..", import.meta.url);\n',
  "web/scripts/collaboration-execution-release-env-core.test.mjs":
    'import "../../scripts/execution-policy-release-core.fixture.mjs";\n',
  "web/scripts/build-security-headers.mjs":
    'new URL("./build-security-headers.mjs", import.meta.url);\n',
  "web/scripts/cloudflare-build-sandbox-core.test.mjs":
    'new URL("./cloudflare-build-sandbox-core.test.mjs", import.meta.url);\n',
  "web/scripts/deploy-cloudflare.mjs":
    'new URL("./deploy-cloudflare.mjs", import.meta.url);\n',
  "web/scripts/deploy-cloudflare-runner.test.mjs": [
    'new URL("../node_modules/wrangler/wrangler-dist/cli.js", import.meta.url);',
    'new URL("../package-lock.json", import.meta.url);',
    'new URL("../package.json", import.meta.url);',
    "",
  ].join("\n"),
  "web/scripts/external-five-historical-evidence-core.test.mjs": [
    'new URL("../../scripts/canonical-authority-graph.mjs", import.meta.url);',
    'new URL("./external-five-historical-evidence-core.mjs", import.meta.url);',
    "",
  ].join("\n"),
  "web/scripts/independent-eip191-replay-core.test.mjs": [
    'new URL("../package-lock.json", import.meta.url);',
    'new URL("../package.json", import.meta.url);',
    'new URL("./independent-eip191-replay-core.mjs", import.meta.url);',
    "",
  ].join("\n"),
  "web/scripts/build-release-env.mjs": [
    'import "../../scripts/exact37-model-a-semantic-validator.mjs";',
    'import "../../scripts/operator-policy-packet-core.mjs";',
    'import "../../scripts/phala-seven-cvm-historical-transcript.mjs";',
    'import "../../scripts/release-authority-current-c-v6-core.mjs";',
    'import "../../scripts/release-manifest-sigstore-verifier.mjs";',
    'new URL("./build-release-env.mjs", import.meta.url);',
    "",
  ].join("\n"),
  "web/scripts/build-release-env.test.mjs":
    'new URL("./build-release-env.test.mjs", import.meta.url);\n',
  "web/scripts/deploy-cloudflare-core.test.mjs":
    'import "../../scripts/compute-workload-activation-observation-core.mjs";\n',
  "web/scripts/execution-policy-release-core-binding.mjs": [
    'import "../../scripts/execution-policy-release-core.mjs";',
    'import "../../scripts/pre-ceremony-runtime-authority-core.mjs";',
    "",
  ].join("\n"),
  "web/scripts/external-five-historical-evidence-core.mjs": [
    'import { canonical } from "../../scripts/canonical-authority-graph.mjs";',
    "export const externalFive = canonical;",
    "",
  ].join("\n"),
  "web/scripts/frontend-release-historical-core.mjs": [
    'import "../../scripts/canonical-authority-graph.mjs";',
    'import "../../scripts/execution-policy-release-core-v3-historical.mjs";',
    'import "../../scripts/release-authority-historical-core.mjs";',
    "export const frontendHistorical = true;",
    "",
  ].join("\n"),
  "web/scripts/frontend-build-candidate-producer-core.mjs":
    'new URL("./frontend-build-candidate-producer-core.mjs", import.meta.url);\n',
  "web/scripts/frontend-release-historical-core.test.mjs": [
    'import "../../scripts/execution-policy-release-core-v3-historical.fixture.mjs";',
    'import "../../scripts/execution-policy-release-core-v3-historical.mjs";',
    'new URL("./frontend-release-historical-core.mjs", import.meta.url);',
    "",
  ].join("\n"),
  "web/scripts/release-env-core.mjs":
    'import "../../scripts/compute-workload-activation-observation-core.mjs";\n',
  "web/scripts/release-env-core.test.mjs": [
    "export const filter = new URL(",
    '  "../../⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",',
    "  import.meta.url,",
    ");",
    'export const manifest = new URL("../RELEASE-MANIFEST.md", import.meta.url);',
    "",
  ].join("\n"),
  "web/scripts/royalty-release-env-core.mjs": [
    'import "../../scripts/royalty-release-authority-core.mjs";',
    'import "../../scripts/royalty-release-history-receipt-core.mjs";',
    "",
  ].join("\n"),
  "web/scripts/pitch-assets-provenance.test.mjs": [
    'const root = new URL("../..", import.meta.url);',
    'const attested = new URL("../../outputs/wikigen-pitch-assets/attested-network.png", import.meta.url);',
    'const oracle = new URL("../../outputs/wikigen-pitch-assets/private-reward-oracle.png", import.meta.url);',
    "export { attested, oracle, root };",
    "",
  ].join("\n"),
  "web/scripts/pages-apex-redirect.test.mjs":
    'new URL("./pages-apex-redirect.test.mjs", import.meta.url);\n',
  "web/scripts/security-headers-core.test.mjs":
    'new URL("./security-headers-core.test.mjs", import.meta.url);\n',
});

const WEB_STATIC_MODULE_SOURCES = Object.freeze({
  "web/functions/_middleware.js": [
    "export function onRequest(context) {",
    "  const { request } = context;",
    "  const target = new URL(request.url);",
    "  return target.protocol === 'https:' ? context.next() : new Response(null, { status: 308 });",
    "}",
    "",
  ].join("\n"),
});

const WEB_SOURCE_CONSUMERS = Object.freeze({
  "web/src/components/ComputeWorkloadPanel.test.ts": [
    'import computeConsoleApi from "../../../docs/compute-console-api.md?raw";',
    "export { computeConsoleApi };",
    "",
  ].join("\n"),
  "web/src/config.ts": [
    "const location = globalThis.location;",
    "export const localOrigin = location.origin;",
    "",
  ].join("\n"),
  "web/src/productTruth.test.ts": [
    'import architecture from "../../ARCHITECTURE.md?raw";',
    'import project from "../../PROJECT.md?raw";',
    'import readme from "../../README.md?raw";',
    "export { architecture, project, readme };",
    "",
  ].join("\n"),
  "web/src/views/Overview.tsx": [
    'import image from "../assets/pitch/private-reward-oracle.webp";',
    "export const Overview = () => image;",
    "",
  ].join("\n"),
  "web/src/views/Verify.tsx": [
    'import image from "../assets/pitch/attested-network.webp";',
    "export const Verify = () => image;",
    "",
  ].join("\n"),
  "web/src/index.tsx": [
    'import "./styles.css";',
    'import { Overview } from "./views/Overview";',
    "export const entry = Overview;",
    "",
  ].join("\n"),
});

const WEB_BUILD_CONTROL_SOURCES = Object.freeze({
  "web/vite.config.ts": [
    'import { defineConfig } from "vite";',
    'import solid from "vite-plugin-solid";',
    "",
    "export default defineConfig({",
    "  plugins: [solid()],",
    "  server: { port: 5175 },",
    "  // Keep the content hash and add an asset epoch so a poisoned or historically",
    "  // incompatible immutable module cache can be retired across the whole graph.",
    "  // `/assets/*` continues to cover this nested path in the Pages headers file.",
    '  build: { target: "es2020", assetsDir: "assets/r2" },',
    "});",
    "",
  ].join("\n"),
  "web/vitest.config.ts": [
    'import { defineConfig } from "vitest/config";',
    'import solid from "vite-plugin-solid";',
    "",
    "export default defineConfig({",
    "  plugins: [solid({ ssr: true })],",
    "  test: {",
    '    environment: "node",',
    '    include: ["src/**/*.test.ts"],',
    "  },",
    "});",
    "",
  ].join("\n"),
  "web/tsconfig.json": `${JSON.stringify({
    compilerOptions: {
      target: "ES2020",
      module: "ESNext",
      moduleResolution: "bundler",
      lib: ["ES2022", "DOM", "DOM.Iterable"],
      jsx: "preserve",
      jsxImportSource: "solid-js",
      types: ["vite/client"],
      strict: true,
      noUnusedLocals: true,
      noUnusedParameters: true,
      noFallthroughCasesInSwitch: true,
      esModuleInterop: true,
      skipLibCheck: true,
      isolatedModules: true,
      verbatimModuleSyntax: true,
      noEmit: true,
    },
    include: ["src"],
  }, null, 2)}\n`,
  "web/index.html": [
    "<!doctype html>",
    '<html lang="en">',
    "  <head>",
    '    <meta charset="UTF-8" />',
    '    <link rel="icon" href="/favicon.svg" type="image/svg+xml" />',
    '    <link rel="canonical" href="https://www.wikigen.me/" />',
    '    <script src="/wikigen-bootstrap-v3.js"></script>',
    "    <title>Fixture</title>",
    "  </head>",
    "  <body>",
    '    <div id="root"></div>',
    '    <script type="module" src="/src/index.tsx"></script>',
    "  </body>",
    "</html>",
    "",
  ].join("\n"),
});

const WEB_PUBLIC_SOURCES = Object.freeze({
  "web/public/_headers": "/*\n  X-Content-Type-Options: nosniff\n",
  "web/public/favicon.svg": '<svg xmlns="http://www.w3.org/2000/svg"></svg>\n',
  "web/public/wikigen-bootstrap-v3.js": [
    "(() => {",
    '  "use strict";',
    "",
    "  const state = document.documentElement.dataset;",
    '  state.wikigenBootstrap = "v3";',
    "",
    "  // Use one canonical browser origin. The apex has historical per-origin",
    "  // client state in some browsers; www is the clean Pages origin. Preserve the",
    "  // complete URL so hash-routed product surfaces and query context survive.",
    '  if (window.location.hostname === "wikigen.me") {',
    "    const target = new URL(window.location.href);",
    '    target.hostname = "www.wikigen.me";',
    '    state.wikigenCanonicalRedirect = "www";',
    "    window.location.replace(target.toString());",
    "    return;",
    "  }",
    "",
    '  if (!("serviceWorker" in navigator)) {',
    '    state.wikigenServiceWorker = "unsupported";',
    "    return;",
    "  }",
    "  if (!navigator.serviceWorker.controller) {",
    '    state.wikigenServiceWorker = "clear";',
    "    return;",
    "  }",
    "",
    "  // Wikigen does not install a service worker. A controller here can only be",
    "  // residue from an older deployment, and may keep serving obsolete modules.",
    "  // Retire registrations without clearing cookies, wallet state, or storage.",
    '  state.wikigenServiceWorker = "retiring";',
    "  navigator.serviceWorker.getRegistrations()",
    "    .then((registrations) => {",
    "      if (registrations.length === 0) {",
    '        state.wikigenServiceWorker = "controller-without-registration";',
    "        return false;",
    "      }",
    "      return Promise.all(registrations.map((registration) => registration.unregister()))",
    "        .then(() => true);",
    "    })",
    "    .then((retired) => {",
    "      if (!retired) return;",
    '      state.wikigenServiceWorker = "retired";',
    "      window.location.reload();",
    "    })",
    "    .catch(() => {",
    '      state.wikigenServiceWorker = "retirement-failed";',
    "    });",
    "})();",
    "",
  ].join("\n"),
});

const WEB_AUXILIARY_SOURCES = Object.freeze({
  "web/README.md": "# Web fixture\n",
  "web/src/assets/pitch/attested-network.webp": "fixture webp bytes\n",
  "web/src/assets/pitch/private-reward-oracle.webp": "fixture webp bytes\n",
  "web/src/styles.css": [
    "body { background-image: url(\"data:image/svg+xml,%3Csvg viewBox='0 0 180 180' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.92' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.12'/%3E%3C/svg%3E\"); }",
    "",
  ].join("\n"),
});

const RESOURCE_BYTES = Object.freeze({
  ".gitignore": "node_modules/\ndist/\n",
  "ARCHITECTURE.md": "# Architecture\nBound fixture.\n",
  "docs/compute-console-api.md": "# Compute Console API\nBound fixture.\n",
  "PROJECT.md": "# Project\nBound fixture.\n",
  "README.md": "# Readme\nBound fixture.\n",
  "scripts/phala-seven-cvm-dcap-verify.py": "# pinned verifier fixture\n",
  "outputs/wikigen-pitch-assets/attested-network.png":
    "fixture attested-network PNG authority bytes\n",
  "outputs/wikigen-pitch-assets/private-reward-oracle.png":
    "fixture private-reward-oracle PNG authority bytes\n",
  "⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq":
    ". as $manifest | $manifest\n",
});

async function writeFixtureFile(root, relative, content) {
  const target = path.join(root, ...relative.split("/"));
  await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
  await writeFile(target, content, { mode: 0o644 });
  await chmod(target, 0o644);
}

async function createFixture() {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const root = await mkdtemp(path.join(canonicalTemporaryRoot, "dnai-external-closure-"));
  await chmod(root, 0o700);
  for (const [relative, content] of Object.entries({
    ...MODULE_SOURCES,
    ...WEB_SCRIPT_SOURCES,
    ...WEB_STATIC_MODULE_SOURCES,
    ...WEB_SOURCE_CONSUMERS,
    ...WEB_BUILD_CONTROL_SOURCES,
    ...WEB_PUBLIC_SOURCES,
    ...WEB_AUXILIARY_SOURCES,
    ...RESOURCE_BYTES,
  })) {
    await writeFixtureFile(root, relative, content);
  }
  return root;
}

async function withFixture(callback) {
  const root = await createFixture();
  try {
    return await callback(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("external closure is exact, typed, canonical, and domain separated", async () => {
  await withFixture(async (root) => {
    const closure = await projectCloudflareExternalBuildClosure(root);
    assert.deepEqual(
      closure.entrypoints,
      CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS,
    );
    assert.deepEqual(
      closure.files.map(({ kind, path: filePath }) => ({ kind, path: filePath })),
      CLOUDFLARE_EXTERNAL_BUILD_FILES.map(({ kind, path: filePath }) => ({
        kind,
        path: filePath,
      })),
    );
    assert.equal(closure.raw_secret_egress, false);
    assert.deepEqual(normalizeCloudflareExternalBuildClosure(closure), closure);
    assert.equal(
      canonicalCloudflareExternalBuildClosureText(closure),
      `${JSON.stringify(closure, null, 2)}\n`,
    );
    assert.match(closure.aggregate_sha256, /^sha256:[0-9a-f]{64}$/);
    assert.match(
      cloudflareExternalBuildClosureSha256(closure),
      /^sha256:[0-9a-f]{64}$/,
    );
    assert.notEqual(
      cloudflareExternalBuildClosureSha256(closure),
      closure.aggregate_sha256,
    );
    // This KAT freezes the closure algorithm and canonicalization over the
    // synthetic graph above. It is intentionally separate from the real
    // checked-in source projection KAT at the end of this file.
    assert.equal(
      closure.aggregate_sha256,
      "sha256:ddb8aae1a0e57dd11d69982018ab5d686aa6f637edee38ab788b8cae42e4ecb8",
    );
    assert.equal(
      cloudflareExternalBuildClosureSha256(closure),
      "sha256:93a8c8d346022c897f3293a024347fa7e7831eb7e7a1d0ec7f70b0973e079ad9",
    );
  });
});

test("closure rejects omission, undeclared transitive imports, extras, and back-edges", async () => {
  await withFixture(async (root) => {
    await unlink(path.join(root, "scripts/ethereum-keccak.mjs"));
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /missing/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'import "./undeclared.mjs";\nexport const canonical = true;\n',
    );
    await writeFixtureFile(root, "scripts/undeclared.mjs", "export default true;\n");
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /undeclared import|back-edge/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/unbound-consumer.mjs",
      'import "../../scripts/unbound.mjs";\n',
    );
    await writeFixtureFile(root, "scripts/unbound.mjs", "export default true;\n");
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /undeclared external import/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'import "../web/scripts/build-release-env.mjs";\nexport const canonical = true;\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /undeclared import|back-edge/,
    );
  });

  await withFixture(async (root) => {
    const closure = await projectCloudflareExternalBuildClosure(root);
    const extra = structuredClone(closure);
    extra.files.push({ ...extra.files.at(-1), path: "scripts/extra.mjs" });
    assert.throws(
      () => normalizeCloudflareExternalBuildClosure(extra),
      /not exact|incomplete/,
    );
  });
});

test("jq, content, mode, and aggregate substitutions cannot preserve authority", async () => {
  await withFixture(async (root) => {
    const baseline = await projectCloudflareExternalBuildClosure(root);
    await writeFixtureFile(
      root,
      "⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",
      ". as $substituted | $substituted\n",
    );
    const substituted = await projectCloudflareExternalBuildClosure(root);
    assert.notEqual(substituted.aggregate_sha256, baseline.aggregate_sha256);
    await unlink(path.join(
      root,
      "⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",
    ));
    await assert.rejects(projectCloudflareExternalBuildClosure(root), /missing/);
  });

  await withFixture(async (root) => {
    const baseline = await projectCloudflareExternalBuildClosure(root);
    const target = path.join(root, "README.md");
    await chmod(target, 0o600);
    const modeChanged = await projectCloudflareExternalBuildClosure(root);
    assert.notEqual(modeChanged.aggregate_sha256, baseline.aggregate_sha256);
    await chmod(target, 0o664);
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /owner-controlled/,
    );
  });

  await withFixture(async (root) => {
    const closure = await projectCloudflareExternalBuildClosure(root);
    const forged = structuredClone(closure);
    forged.files[0].sha256 = `sha256:${"f".repeat(64)}`;
    assert.throws(
      () => normalizeCloudflareExternalBuildClosure(forged),
      /aggregate is invalid/,
    );
  });
});

test("symlinked and hard-linked closure files fail before projection", async () => {
  await withFixture(async (root) => {
    const target = path.join(root, "README.md");
    const real = path.join(root, "README.real.md");
    const content = await readFile(target);
    await unlink(target);
    await writeFixtureFile(root, "README.real.md", content);
    await symlink(real, target);
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /symlinked or aliased/,
    );
  });

  await withFixture(async (root) => {
    const target = path.join(root, "PROJECT.md");
    const alias = path.join(root, "PROJECT.alias.md");
    await link(target, alias);
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /single-link/,
    );
  });
});

test("external module parser rejects dynamic loading, CommonJS, bare packages, and cycles", async () => {
  await withFixture(async (root) => {
    for (const modulePath of [
      "scripts/cvm-release-descriptor-set-v3.mjs",
      "scripts/phala-seven-cvm-opened-fd-runtime-core.mjs",
      "scripts/phala-seven-cvm-verifier-evidence.mjs",
      "scripts/release-authority-signature-verifier.mjs",
      "scripts/release-manifest-sigstore-verifier.mjs",
    ]) {
      await writeFixtureFile(
        root,
        modulePath,
        MODULE_SOURCES[modulePath].replace('import "node:child_process";\n', ""),
      );
    }
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /Node builtin allowlist contains an unreachable extra/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/runtime-escape.mjs",
      'export const escaped = import("../../scripts/canonical-authority-graph.mjs");\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require in any consumer/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/runtime-escape.mjs",
      'export const escaped = require("../../scripts/canonical-authority-graph.mjs");\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require in any consumer/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'export const canonical = import("./ethereum-keccak.mjs");\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/runtime-escape.mjs",
      [
        'import { createRequire } from "node:module";',
        "const loader = createRequire(import.meta.url);",
        'export const escaped = loader("../../scripts/canonical-authority-graph.mjs");',
        "",
      ].join("\n"),
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require in any consumer/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'export const canonical = module.require("./ethereum-keccak.mjs");\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'export const canonical = module["require"]("./ethereum-keccak.mjs");\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'export const canonical = new Function("return true")();\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'const Dynamic = (() => {}).constructor;\nexport const canonical = Dynamic("return true")();\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'export const canonical = (0, eval)("true");\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      [
        'import { Worker as BackgroundTask } from "node:worker_threads";',
        'export const canonical = new BackgroundTask("./ethereum-keccak.mjs");',
        "",
      ].join("\n"),
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'const value = require("./ethereum-keccak.mjs");\nexport { value as canonical };\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'import value from "mutable-package";\nexport const canonical = value;\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /bare package/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'import "./compute-workload-activation-observation-core.mjs";\nexport const canonical = true;\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /cycle/,
    );
  });
});

test("runtime module capability policy rejects aliases, reflection, computed access, and re-exports", async () => {
  for (const source of [
    'export const target = new URL("https://attacker.invalid/");\n',
    'export function onRequest({ request }) { const U = URL; return new U(request.url); }\n',
    'export function onRequest({ request }) { return new URL(request["url"]); }\n',
    'export function onRequest(context) { return new URL(context.request.url); }\n',
  ]) {
    await withFixture(async (root) => {
      await writeFixtureFile(root, "web/functions/_middleware.js", source);
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /dynamic import or CommonJS require in any consumer/,
      );
    });
  }

  const rejectedSources = [
    'export const loader = process.getBuiltinModule("fs");\n',
    'const load = process.getBuiltinModule; export const fs = load("fs");\n',
    'const { getBuiltinModule: load } = process; export const fs = load("fs");\n',
    'const load = process["get" + "BuiltinModule"]; export const fs = load("fs");\n',
    'const load = Reflect.get(process, "getBuiltinModule"); export const fs = load("fs");\n',
    'const load = module["create" + "Require"]; export { load };\n',
    'const load = require; export const fs = load("fs");\n',
    'const execute = (0, eval); export const value = execute("1");\n',
    'const F = globalThis["Fun" + "ction"]; export const value = F("return 1")();\n',
    'const { Worker: BackgroundTask } = globalThis; export const task = new BackgroundTask("./task.mjs");\n',
    'const load = global["process"]["getBuiltinModule"]; export const fs = load("fs");\n',
    'const root = global; export const fs = root.process.getBuiltinModule("fs");\n',
    'const key = ["Wor", "ker"].join(""); export const task = new window[key]("./task.mjs");\n',
    'const root = self; export const task = new root.Worker("./task.mjs");\n',
    'const { constructor: Dynamic } = (() => {}); export const value = Dynamic("return 1")();\n',
    'const F = Reflect.getOwnPropertyDescriptor(() => {}, "constructor").value; export const value = F("return 1")();\n',
    'export { createRequire as loader } from "node:module";\n',
    'export { SourceTextModule as Loader } from "node:vm";\n',
    'import vm from "node:vm"; export const Loader = vm.SourceTextModule;\n',
    'import { Worker as BackgroundTask } from "node:worker_threads"; export { BackgroundTask };\n',
  ];
  for (const source of rejectedSources) {
    await withFixture(async (root) => {
      await writeFixtureFile(root, "web/scripts/runtime-capability-escape.mjs", source);
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /dynamic import or CommonJS require in any consumer/,
      );
    });
  }

  const auditedBootstrapResourceTuple =
    'new URL("./bootstrap-retirement.test.mjs", import.meta.url);\n';
  for (const source of [
    [
      'import vm from "node:vm";',
      "const { runInNewContext: execute } = vm;",
      'export const value = execute("1", Object.create(null));',
      "",
    ].join("\n"),
    [
      'import vm from "node:vm";',
      'export const value = vm["run" + "InNewContext"]("1", Object.create(null), {});',
      "",
    ].join("\n"),
    [
      'import vm from "node:vm";',
      'const execute = Reflect.get(vm, "runInNewContext");',
      'export const value = execute("1", Object.create(null), {});',
      "",
    ].join("\n"),
    [
      'import vm from "node:vm";',
      'export const value = vm.runInNewContext("process.getBuiltinModule(\\"fs\\")", {}, {});',
      "",
    ].join("\n"),
  ]) {
    await withFixture(async (root) => {
      await writeFixtureFile(
        root,
        "web/scripts/bootstrap-retirement.test.mjs",
        `${auditedBootstrapResourceTuple}${source}`,
      );
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /dynamic import or CommonJS require in any consumer/,
      );
    });
  }

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/bootstrap-retirement.test.mjs",
      [
        'new URL("./bootstrap-retirement.test.mjs", import.meta.url);',
        'import vm from "node:vm";',
        'const bootstrapSource = "1";',
        "const context = Object.create(null);",
        'const bootstrapPath = "/audited/bootstrap.js";',
        "export const value = vm.runInNewContext(bootstrapSource, context, { filename: bootstrapPath });",
        "",
      ].join("\n"),
    );
    await writeFixtureFile(
      root,
      "web/scripts/audited-capability-controls.mjs",
      [
        "export const environment = process.env;",
        "export const keys = Reflect.ownKeys({});",
        "export const descriptor = Reflect.getOwnPropertyDescriptor({}, \"x\");",
        "",
      ].join("\n"),
    );
    await projectCloudflareExternalBuildClosure(root);
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/unaudited-child-process.mjs",
      'import { execFileSync } from "node:child_process";\nexport const output = execFileSync("node", ["-e", "0"]);\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /exact reviewed importers/,
    );
  });
});

test("web modules reject absolute, URI, unaudited, and unenumerated static imports", async () => {
  const rejectedSpecifiers = [
    "/tmp/absolute-escape.mjs",
    "file:///tmp/file-escape.mjs",
    "data:text/javascript,export default true",
    "http://example.invalid/escape.mjs",
    "https://example.invalid/escape.mjs",
    "custom+transport:escape",
    "node:sqlite",
    "already-installed-transitive-package",
  ];
  for (const specifier of rejectedSpecifiers) {
    await withFixture(async (root) => {
      await writeFixtureFile(
        root,
        "web/scripts/static-import-escape.mjs",
        `import ${JSON.stringify(specifier)};\n`,
      );
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /absolute static module specifier|unsupported or unaudited URI module specifier|unaudited bare package import/,
      );
    });
  }

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/static-import-escape.mjs",
      'import "./missing-but-relative.mjs";\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /outside the enumerated module set/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/audited-static-imports.mjs",
      [
        'import "node:crypto";',
        'import "viem";',
        "export const audited = true;",
        "",
      ].join("\n"),
    );
    await projectCloudflareExternalBuildClosure(root);
  });
});

test("TypeScript consumers reject absolute, URI, and unaudited package imports", async () => {
  const rejectedSpecifiers = [
    "/tmp/browser-absolute-escape.ts",
    "file:///tmp/browser-file-escape.ts",
    "data:text/javascript,export default true",
    "http://example.invalid/browser-escape.ts",
    "https://example.invalid/browser-escape.ts",
    "custom+transport:browser-escape",
    "node:fs",
    "already-installed-transitive-package",
  ];
  for (const specifier of rejectedSpecifiers) {
    await withFixture(async (root) => {
      await writeFixtureFile(
        root,
        "web/src/static-import-escape.ts",
        `import ${JSON.stringify(specifier)};\nexport const escaped = true;\n`,
      );
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /absolute static module specifier|unsupported or unaudited URI module specifier|unaudited bare package import/,
      );
    });
  }

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/src/audited-static-import.ts",
      'import "solid-js";\nexport const audited = true;\n',
    );
    await projectCloudflareExternalBuildClosure(root);
  });
});

test("TypeScript AST extraction rejects commented, continued, exported, and nonliteral imports", async () => {
  const rejectedSources = [
    'import/*comment*/"/tmp/commented-side-effect.ts";\nexport const escaped = true;\n',
    'export const escaped = import/*comment*/("file:///tmp/commented-dynamic.ts");\n',
    'export/*comment*/ * from "https://example.invalid/commented-export.ts";\n',
    'import "/tmp/line\\\ncontinued.ts";\nexport const escaped = true;\n',
    'const target = "./views/Overview";\nexport const escaped = import(target);\n',
    'import escaped = require("data:text/javascript,export default true");\nexport { escaped };\n',
    'const target = "./views/Overview";\nimport escaped = require(target);\nexport { escaped };\n',
  ];
  for (const source of rejectedSources) {
    await withFixture(async (root) => {
      await writeFixtureFile(root, "web/src/typescript-import-escape.ts", source);
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /absolute static module specifier|unsupported or unaudited URI module specifier|nonliteral module request|TypeScript module graph is invalid/,
      );
    });
  }

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/src/audited-dynamic-import.ts",
      'export const loaded = import("./views/Overview");\n',
    );
    await projectCloudflareExternalBuildClosure(root);
  });
});

test("TypeScript capability policy rejects loaders, constructors, reflection, and aliases", async () => {
  const rejectedSources = [
    'export const escaped = require("node:fs");\n',
    'const load = require; export const escaped = load("node:fs");\n',
    'export const escaped = (0, eval)("1");\n',
    'export const escaped = Function("return 1")();\n',
    'const F = globalThis["Fun" + "ction"]; export const escaped = F("return 1")();\n',
    'const { Worker: BackgroundTask } = globalThis; export const escaped = new BackgroundTask("./task.ts");\n',
    'export const escaped = process.getBuiltinModule("fs");\n',
    'const proc = process; export const escaped = proc.getBuiltinModule("fs");\n',
    'const { getBuiltinModule: load } = process; export const escaped = load("fs");\n',
    'const load = Reflect.get(process, "getBuiltinModule"); export const escaped = load("fs");\n',
    'const load = module["create" + "Require"]; export { load as escaped };\n',
    'const key = ["Wor", "ker"].join(""); export const escaped = new window[key]("./task.ts");\n',
    'const root = self; export const escaped = new root.Worker("./task.ts");\n',
    'const { constructor: Dynamic } = (() => {}); export const escaped = Dynamic("return 1")();\n',
    'const key = ["con", "structor"].join(""); export const escaped = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(() => {}), key)?.value;\n',
    'const key = ["con", "structor"].join(""); export const escaped = Object.getPrototypeOf(() => {})[key];\n',
    'export { createRequire as escaped } from "node:module";\n',
    'import vm from "node:vm"; export const escaped = vm.SourceTextModule;\n',
    'export const escaped = ({} as object).constructor;\n',
    'export const escaped = new Worker("./task.ts");\n',
  ];
  for (const source of rejectedSources) {
    await withFixture(async (root) => {
      await writeFixtureFile(root, "web/src/typescript-capability-escape.ts", source);
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /runtime module capability|unsupported or unaudited URI module specifier/,
      );
    });
  }

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/src/audited-local-require-helper.ts",
      [
        "export function check(condition: boolean): Crypto {",
        "  const require = (value: boolean): void => {",
        '    if (!value) throw new Error("required condition failed");',
        "  };",
        "  require(condition);",
        "  return globalThis.crypto;",
        "}",
        "",
      ].join("\n"),
    );
    await projectCloudflareExternalBuildClosure(root);
  });
});

test("frontend config permits only its exact direct browser-location snapshot", async () => {
  await withFixture(async (root) => {
    await projectCloudflareExternalBuildClosure(root);
  });

  for (const source of [
    'const location = globalThis["location"];\nexport { location };\n',
    'const browser = globalThis;\nexport const location = browser.location;\n',
    'export const location = globalThis.location;\n',
  ]) {
    await withFixture(async (root) => {
      await writeFixtureFile(root, "web/src/config.ts", source);
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /unaudited globalThis capability access|runtime module capability/,
      );
    });
  }

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/src/unreviewed-location.ts",
      'const location = globalThis.location;\nexport { location };\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /unaudited globalThis capability access/,
    );
  });
});

test("TypeScript binds import types and rejects import-equals and triple-slash resolution", async () => {
  const rejectedSources = [
    'type Escaped = import("node:fs").PathLike;\nexport type { Escaped };\n',
    'type Escaped = import("data:text/javascript,export default true").default;\nexport type { Escaped };\n',
    'import escaped = require("solid-js");\nexport { escaped };\n',
    '/// <reference path="./views/Overview.tsx" />\nexport const value = true;\n',
    '/// <reference types="solid-js" />\nexport const value = true;\n',
    '/// <reference lib="dom" />\nexport const value = true;\n',
    '/// <amd-dependency path="solid-js" />\nexport const value = true;\n',
    '/// <reference no-default-lib="true" />\nexport const value = true;\n',
    'export const modules = import.meta.glob("../../outside/*.ts");\n',
    'export const asset = new URL("../../outside.bin", import.meta.url);\n',
    'const resourceBase = import.meta.url; const ResourceUrl = URL; export const asset = new ResourceUrl("../../outside.bin", resourceBase);\n',
    'declare module "external-package" { export const value: true; }\n',
    '/** @jsxImportSource external-package */\nexport const value = <div />;\n',
  ];
  for (const source of rejectedSources) {
    await withFixture(async (root) => {
      await writeFixtureFile(
        root,
        source.includes("<div")
          ? "web/src/typescript-resolution-escape.tsx"
          : "web/src/typescript-resolution-escape.ts",
        source,
      );
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /runtime module capability|unsupported or unaudited URI module specifier|triple-slash|no-default-lib|glob resolution|URL asset resolution|module augmentation|JSX import-source/,
      );
    });
  }

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/src/audited-import-type.ts",
      'export type OverviewModule = typeof import("./views/Overview");\n',
    );
    await projectCloudflareExternalBuildClosure(root);
  });
});

test("Vite configs are exact and JavaScript or JSX source targets stay in the parsed graph", async () => {
  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/src/javascript-helper.js",
      'export const helper = "parsed JavaScript";\n',
    );
    await writeFixtureFile(
      root,
      "web/src/javascript-view.jsx",
      [
        'import { helper } from "./javascript-helper.js";',
        "export const JavaScriptView = () => <span>{helper}</span>;",
        "",
      ].join("\n"),
    );
    await projectCloudflareExternalBuildClosure(root);
  });

  for (const [configPath, source] of [
    [
      "web/vite.config.ts",
      WEB_BUILD_CONTROL_SOURCES["web/vite.config.ts"].replace(
        'from "vite"',
        'from "rollup"',
      ),
    ],
    [
      "web/vitest.config.ts",
      `${WEB_BUILD_CONTROL_SOURCES["web/vitest.config.ts"]}import "./src/index.tsx";\n`,
    ],
  ]) {
    await withFixture(async (root) => {
      await writeFixtureFile(root, configPath, source);
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /config semantics changed outside its reviewed pin/,
      );
    });
  }

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/src/javascript-missing.js",
      'import "./not-enumerated.js";\nexport const escaped = true;\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /relative target is missing or ambiguous in the enumerated graph/,
    );
  });
});

test("JavaScript JSDoc imports, JSX resolver pragmas, and runtime loaders are rejected", async () => {
  const rejected = [
    [
      "web/src/jsdoc-import-type.js",
      '/** @type {import("node:fs").PathLike} */\nexport const value = "x";\n',
    ],
    [
      "web/src/jsdoc-import-tag.js",
      '/** @import { PathLike } from "node:fs" */\nexport const value = "x";\n',
    ],
    [
      "web/src/nested-jsdoc-import.js",
      'export class Nested {\n  /** @returns {import("node:fs").PathLike} */\n  value() { return "x"; }\n}\n',
    ],
    [
      "web/src/jsx-import-source.jsx",
      '/** @jsxImportSource external-jsx-runtime */\nexport const value = <div />;\n',
    ],
    [
      "web/src/jsx-runtime.jsx",
      '/** @jsxRuntime classic */\nexport const value = <div />;\n',
    ],
    [
      "web/src/jsx-factory.jsx",
      '/** @jsx externalFactory */\nexport const value = <div />;\n',
    ],
    [
      "web/src/javascript-require.js",
      'export const value = require("node:fs");\n',
    ],
    [
      "web/src/javascript-worker.js",
      'export const value = new Worker("./worker.js");\n',
    ],
  ];
  for (const [filePath, source] of rejected) {
    await withFixture(async (root) => {
      await writeFixtureFile(root, filePath, source);
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /TypeScript module graph is invalid|JSDoc import resolution|JSX resolver pragma|runtime module capability/,
      );
    });
  }
});

test("tsconfig is a duplicate-free exact implicit-resolution projector", async () => {
  const baseline = JSON.parse(WEB_BUILD_CONTROL_SOURCES["web/tsconfig.json"]);
  const mutated = [];
  for (const [label, mutate] of [
    ["extends", (value) => { value.extends = "../tsconfig.json"; }],
    ["plugins", (value) => { value.compilerOptions.plugins = [{ name: "escape" }]; }],
    ["typeRoots", (value) => { value.compilerOptions.typeRoots = ["../types"]; }],
    ["paths", (value) => { value.compilerOptions.paths = { "*": ["../*"] }; }],
    ["references", (value) => { value.references = [{ path: "../outside" }]; }],
    ["jsxImportSource", (value) => { value.compilerOptions.jsxImportSource = "external"; }],
    ["types", (value) => { value.compilerOptions.types = ["vite/client", "node"]; }],
  ]) {
    const value = structuredClone(baseline);
    mutate(value);
    mutated.push([label, `${JSON.stringify(value, null, 2)}\n`]);
  }
  mutated.push([
    "duplicate",
    WEB_BUILD_CONTROL_SOURCES["web/tsconfig.json"].replace(
      '    "types": [',
      '    "types": ["vite/client"],\n    "types": [',
    ),
  ]);
  mutated.push([
    "prototype-key",
    WEB_BUILD_CONTROL_SOURCES["web/tsconfig.json"].replace(
      "{\n",
      '{\n  "__proto__": {},\n',
    ),
  ]);
  for (const [, source] of mutated) {
    await withFixture(async (root) => {
      await writeFixtureFile(root, "web/tsconfig.json", source);
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /duplicate object key|unexpected shape|resolution policy is not exact/,
      );
    });
  }
});

test("index HTML has an exact parsed local-resource graph", async () => {
  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/index.html",
      WEB_BUILD_CONTROL_SOURCES["web/index.html"].replace(
        "  <head>",
        '  <head>\n    <!-- <script src="/not-live.js"></script> -->',
      ),
    );
    await projectCloudflareExternalBuildClosure(root);
  });

  const additions = [
    '<script src="/undeclared.js"></script>',
    '<script>window.location.reload()</script>',
    '<link rel="stylesheet" href="/undeclared.css" />',
    '<img src="/undeclared.png" />',
    '<base href="/" />',
    '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>',
    '<meta http-equiv="refresh" content="0;url=/elsewhere" />',
  ];
  for (const addition of additions) {
    await withFixture(async (root) => {
      await writeFixtureFile(
        root,
        "web/index.html",
        WEB_BUILD_CONTROL_SOURCES["web/index.html"].replace(
          "  </head>",
          `    ${addition}\n  </head>`,
        ),
      );
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /undeclared|unsupported markup|inline|HTTP-equivalent/,
      );
    });
  }

  await withFixture(async (root) => {
    const script = '<script src="/wikigen-bootstrap-v3.js"></script>';
    await writeFixtureFile(
      root,
      "web/index.html",
      WEB_BUILD_CONTROL_SOURCES["web/index.html"].replace(script, `<!-- ${script} -->`),
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /references are not exact and ordered/,
    );
  });
});

test("public bootstrap has no module loader and only its reviewed browser roots", async () => {
  const rejectedSources = [
    'require("node:fs");\n',
    'import("./undeclared.js");\n',
    'eval("1");\n',
    'Function("return 1")();\n',
    'new Worker("./worker.js");\n',
    'const root = window; root.location.reload();\n',
    'window.document.cookie = "escape";\n',
    'document.defaultView.location.reload();\n',
    'navigator.sendBeacon("/escape", "x");\n',
    'window["loc" + "ation"].reload();\n',
    'fetch("https://example.invalid/escape");\n',
    'new WebSocket("wss://example.invalid/escape");\n',
    'new XMLHttpRequest();\n',
  ];
  for (const source of rejectedSources) {
    await withFixture(async (root) => {
      await writeFixtureFile(root, "web/public/wikigen-bootstrap-v3.js", source);
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /public bootstrap refuses module requests|runtime module capability|browser-global capability|public-bootstrap global identifier/,
      );
    });
  }
});

test("CSS permits only the reviewed quoted data URL and no import resolver", async () => {
  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/src/styles.css",
      `${WEB_AUXILIARY_SOURCES["web/src/styles.css"]}/* @import url(\"https://comment.invalid\"); */\nbody::before { content: \"url(https://string.invalid)\"; }\n`,
    );
    await projectCloudflareExternalBuildClosure(root);
  });

  const baseline = WEB_AUXILIARY_SOURCES["web/src/styles.css"];
  const rejectedSources = [
    `${baseline}@import "https://example.invalid/theme.css";\n`,
    `${baseline}${String.raw`@\69mport "https://example.invalid/theme.css";`}\n`,
    `${baseline}body { background: url("https://example.invalid/image.png"); }\n`,
    `${baseline}body { background: url(https://example.invalid/image.png); }\n`,
    `${baseline}${String.raw`body { background: u\72l("https://example.invalid/image.png"); }`}\n`,
    `${baseline}body { background: image-set("https://example.invalid/image.png" 1x); }\n`,
    `${baseline}${String.raw`@font-face { src: s\72 c("https://example.invalid/font.woff2"); }`}\n`,
    `${baseline}body { background: url("data:image/svg+xml,%3Csvg/%3E"); }\n`,
    `${baseline}${baseline}`,
  ];
  for (const source of rejectedSources) {
    await withFixture(async (root) => {
      await writeFixtureFile(root, "web/src/styles.css", source);
      await assert.rejects(
        projectCloudflareExternalBuildClosure(root),
        /refuses @import|refuses non-data|refuses unquoted|refuses an unsupported resource function|data URL graph is not exact/,
      );
    });
  }
});

test("external resource authority requires exact live AST request tuples", async () => {
  await withFixture(async (root) => {
    await unlink(path.join(root, "web/scripts/cloudflare-release-artifact-core.test.mjs"));
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /reviewed import-meta URL consumer is missing/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/pitch-assets-provenance.test.mjs",
      [
        'const root = new URL("../..", import.meta.url);',
        'const attested = "../../outputs/wikigen-pitch-assets/attested-network.png";',
        '// new URL("../../outputs/wikigen-pitch-assets/private-reward-oracle.png", import.meta.url);',
        "export { attested, root };",
        "",
      ].join("\n"),
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /import-meta URL graph is not exact|external resource AST binding is missing/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/pitch-assets-provenance.test.mjs",
      `${WEB_SCRIPT_SOURCES["web/scripts/pitch-assets-provenance.test.mjs"]}new URL("../../outputs/wikigen-pitch-assets/attested-network.png", import.meta.url);\n`,
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /import-meta URL graph is not exact/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/pitch-assets-provenance.test.mjs",
      [
        'const root = new URL("../..", import.meta.url);',
        'const source = "../../outputs/wikigen-pitch-assets/attested-network.png";',
        "const attested = new URL(source, import.meta.url);",
        'const oracle = new URL("../../outputs/wikigen-pitch-assets/private-reward-oracle.png", import.meta.url);',
        "export { attested, oracle, root };",
        "",
      ].join("\n"),
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /resource request is nonliteral or unsupported/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/pitch-assets-provenance.test.mjs",
      `const URL = class LocalUrl {};\n${WEB_SCRIPT_SOURCES["web/scripts/pitch-assets-provenance.test.mjs"]}`,
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /refuses dynamic import or CommonJS require in any consumer/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/pitch-assets-provenance.test.mjs",
      [
        'const ResourceUrl = URL;',
        WEB_SCRIPT_SOURCES["web/scripts/pitch-assets-provenance.test.mjs"],
        'new ResourceUrl("../../unreviewed-resource.bin", import.meta.url);',
        "",
      ].join("\n"),
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /refuses dynamic import or CommonJS require in any consumer/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/src/productTruth.test.ts",
      WEB_SOURCE_CONSUMERS["web/src/productTruth.test.ts"].replace(
        'import architecture from "../../ARCHITECTURE.md?raw";',
        'const architecture = "../../ARCHITECTURE.md?raw";',
      ),
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /external resource AST binding is missing/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/src/productTruth.test.ts",
      WEB_SOURCE_CONSUMERS["web/src/productTruth.test.ts"].replace("?raw", "?url"),
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /unsupported import query/,
    );
  });
});

test("stable reads bind the pathname and complete projections bind one generation", async () => {
  await withFixture(async (root) => {
    const target = path.join(root, "README.md");
    await assert.rejects(
      closureTest.readStableRepositoryFile(
        root,
        "README.md",
        4 * 1024 * 1024,
        "Cloudflare replacement KAT",
        {
          afterRead: async () => {
            await rename(target, `${target}.previous`);
            await writeFile(target, "# replacement bytes with the same pathname\n", {
              mode: 0o644,
            });
          },
        },
      ),
      /pathname was replaced after its stable read/,
    );
  });

  await withFixture(async (root) => {
    await assert.rejects(
      closureTest.projectCloudflareExternalBuildClosureGenerations(
        root,
        async () => {
          await writeFixtureFile(
            root,
            "web/src/views/Overview.tsx",
            `${WEB_SOURCE_CONSUMERS["web/src/views/Overview.tsx"]}export const generation = 2;\n`,
          );
        },
      ),
      /mutable source changed across complete closure projections/,
    );
  });
});

test("TypeScript parser pin is byte-exact and projected fixtures need no node_modules", async () => {
  const runtimePath = new URL("../node_modules/typescript/lib/typescript.js", import.meta.url);
  const runtimeBytes = await readFile(runtimePath);
  assert.strictEqual(
    closureTest.assertPinnedTypeScriptParserBytes(runtimeBytes),
    runtimeBytes,
  );
  const mutated = Buffer.from(runtimeBytes);
  mutated[Math.floor(mutated.length / 2)] ^= 1;
  assert.throws(
    () => closureTest.assertPinnedTypeScriptParserBytes(mutated),
    /parser runtime bytes do not match the reviewed pin/,
  );

  await withFixture(async (root) => {
    await assert.rejects(
      readFile(path.join(root, "web/node_modules/typescript/lib/typescript.js")),
      (error) => error?.code === "ENOENT",
    );
    await projectCloudflareExternalBuildClosure(root);
  });
});

test("real checked-in external bytes match the final release projection KAT", async () => {
  const repositoryRoot = path.resolve(new URL("../..", import.meta.url).pathname);
  const closure = await projectCloudflareExternalBuildClosure(repositoryRoot);
  assert.equal(closure.entrypoints.length, 24);
  assert.equal(closure.files.length, 67);
  assert.equal(
    closure.aggregate_sha256,
    "sha256:f93801e84c9f0be119a80ef1269b38b5897cc0e1ee7afafbc4926d89a3187c0b",
  );
  assert.equal(
    cloudflareExternalBuildClosureSha256(closure),
    "sha256:5900256a93f17b05aa86e6ae824bd4e575771b6fe51330a538fc024a16ca6aa2",
  );
  assert.deepEqual(closureTest.MODULE_ENTRYPOINT_PATHS, [
    "scripts/canonical-authority-graph.mjs",
    "scripts/compute-workload-activation-observation-core.mjs",
    "scripts/exact37-model-a-semantic-validator.mjs",
    "scripts/execution-policy-release-core-v3-historical.fixture.mjs",
    "scripts/execution-policy-release-core-v3-historical.mjs",
    "scripts/execution-policy-release-core.fixture.mjs",
    "scripts/execution-policy-release-core.mjs",
    "scripts/operator-policy-packet-core.mjs",
    "scripts/phala-seven-cvm-historical-transcript.mjs",
    "scripts/pre-ceremony-runtime-authority-core.mjs",
    "scripts/release-authority-current-c-v6-core.mjs",
    "scripts/release-authority-historical-core.mjs",
    "scripts/release-manifest-sigstore-verifier.mjs",
    "scripts/royalty-release-authority-core.mjs",
    "scripts/royalty-release-history-receipt-core.mjs",
  ]);
  assert.deepEqual(closureTest.MODULE_CLOSURE_PATHS, [
    "scripts/build-tee-image-release.mjs",
    "scripts/canonical-authority-graph.mjs",
    "scripts/canonical-public-https-url-core.mjs",
    "scripts/compute-workload-activation-observation-core.mjs",
    "scripts/cvm-descriptor-runtime-authority-core.mjs",
    "scripts/cvm-descriptor-runtime-authority-v1-policy.mjs",
    "scripts/cvm-descriptor-runtime-authority-v2-core.mjs",
    "scripts/cvm-descriptor-runtime-authority-v2.mjs",
    "scripts/cvm-launch-intent-core.mjs",
    "scripts/cvm-release-descriptor-set-constants.mjs",
    "scripts/cvm-release-descriptor-set-constants-v3.mjs",
    "scripts/cvm-release-descriptor-set-v3.mjs",
    "scripts/ethereum-keccak.mjs",
    "scripts/exact-model-a-dependency-graph.mjs",
    "scripts/exact37-model-a-semantic-validator.mjs",
    "scripts/execution-policy-release-core-v3-historical.fixture.mjs",
    "scripts/execution-policy-release-core-v3-historical.mjs",
    "scripts/execution-policy-release-core.fixture.mjs",
    "scripts/execution-policy-release-core.mjs",
    "scripts/frontend-build-candidate-receipt-core.mjs",
    "scripts/operator-policy-packet-core.mjs",
    "scripts/phala-bootstrap-public-environment-authority-core.mjs",
    "scripts/phala-executor-state-core.mjs",
    "scripts/phala-nonlive-bootstrap-authorization-core.mjs",
    "scripts/phala-nonlive-bootstrap-authorization.mjs",
    "scripts/phala-post-measurement-activation-core.mjs",
    "scripts/phala-post-measurement-activation-receipt-core.mjs",
    "scripts/phala-production-execution-policy.mjs",
    "scripts/phala-production-posture-core.mjs",
    "scripts/phala-production-posture-receipt.mjs",
    "scripts/phala-production-target-authority.mjs",
    "scripts/phala-seven-cvm-historical-evidence-core.mjs",
    "scripts/phala-seven-cvm-historical-release-verification-authority.mjs",
    "scripts/phala-seven-cvm-historical-runtime-binding-core.mjs",
    "scripts/phala-seven-cvm-historical-transcript.mjs",
    "scripts/phala-seven-cvm-launch-completion-core.mjs",
    "scripts/phala-seven-cvm-measurement-policy.mjs",
    "scripts/phala-seven-cvm-opened-fd-runtime-core.mjs",
    "scripts/phala-seven-cvm-release-verification-authority-core.mjs",
    "scripts/phala-seven-cvm-release-verification-authority-v4-core.mjs",
    "scripts/phala-seven-cvm-verifier-evidence.mjs",
    "scripts/pre-ceremony-runtime-authority-core.mjs",
    "scripts/release-authority-current-c-v6-core.mjs",
    "scripts/release-authority-current-reviewer-facade.mjs",
    "scripts/release-authority-historical-core.mjs",
    "scripts/release-authority-signature-verifier-core.mjs",
    "scripts/release-authority-signature-verifier.mjs",
    "scripts/release-authority-stages.mjs",
    "scripts/release-ceremony-authorization.mjs",
    "scripts/release-ceremony-lock-protocol-core.mjs",
    "scripts/release-manifest-descriptor-historical-core.mjs",
    "scripts/release-manifest-sigstore-verifier.mjs",
    "scripts/release-reviewer-authority-core.mjs",
    "scripts/release-reviewer-authority-genesis-acceptance.mjs",
    "scripts/release-reviewer-authority-genesis.mjs",
    "scripts/royalty-release-authority-core.mjs",
    "scripts/royalty-release-history-receipt-core.mjs",
    "scripts/tinker-account-binding-core.mjs",
  ]);
  assert.deepEqual(closureTest.MODULE_WEB_BACKEDGE_PATHS, [
    "web/scripts/external-five-historical-evidence-core.mjs",
    "web/scripts/frontend-release-historical-core.mjs",
    "web/scripts/independent-eip191-replay-core.mjs",
  ]);
  assert.deepEqual(closureTest.MODULE_BARE_PACKAGE_IMPORTS, [
    "@noble/curves/secp256k1",
    "@noble/hashes/sha3",
    "@noble/hashes/utils",
  ]);
  assert.deepEqual(closureTest.MODULE_NODE_BUILTIN_IMPORTS, [
    "node:child_process",
    "node:crypto",
    "node:fs",
    "node:fs/promises",
    "node:os",
    "node:path",
    "node:url",
    "node:util",
  ]);
  assert.deepEqual(closureTest.MODULE_PRIVILEGED_NODE_IMPORTERS, {
    "node:child_process": [
      "scripts/cvm-release-descriptor-set-v3.mjs",
      "scripts/phala-seven-cvm-opened-fd-runtime-core.mjs",
      "scripts/phala-seven-cvm-verifier-evidence.mjs",
      "scripts/release-authority-signature-verifier.mjs",
      "scripts/release-manifest-sigstore-verifier.mjs",
    ],
  });
  assert.deepEqual(closureTest.WEB_MODULE_BARE_PACKAGE_IMPORTS, [
    "@noble/curves/secp256k1",
    "@noble/hashes/sha3",
    "@noble/hashes/utils",
    "typescript",
    "viem",
    "viem/accounts",
    "vite",
  ]);
  assert.deepEqual(closureTest.WEB_MODULE_NODE_BUILTIN_IMPORTS, [
    "node:assert/strict",
    "node:child_process",
    "node:crypto",
    "node:fs",
    "node:fs/promises",
    "node:net",
    "node:os",
    "node:path",
    "node:process",
    "node:test",
    "node:url",
    "node:util",
    "node:vm",
  ]);
  assert.deepEqual(closureTest.WEB_MODULE_PRIVILEGED_NODE_IMPORTERS, {
    "node:child_process": [
      "web/scripts/build-release-env.mjs",
      "web/scripts/cloudflare-build-sandbox-core.mjs",
      "web/scripts/cloudflare-build-sandbox-core.test.mjs",
      "web/scripts/cloudflare-external-build-closure-core.mjs",
      "web/scripts/deploy-cloudflare.mjs",
      "web/scripts/frontend-build-candidate-producer-core.mjs",
      "web/scripts/release-env-core.test.mjs",
      "web/scripts/release-runtime-pins-core.mjs",
    ],
    "node:process": [
      "web/scripts/durable-private-file-core.mjs",
    ],
    "node:vm": [
      "web/scripts/bootstrap-retirement.test.mjs",
    ],
  });
  assert.deepEqual(closureTest.WEB_SOURCE_BARE_PACKAGE_IMPORTS, [
    "@fontsource-variable/jetbrains-mono",
    "@fontsource-variable/manrope",
    "@walletconnect/ethereum-provider",
    "lucide-solid",
    "solid-js",
    "solid-js/web",
    "viem",
    "viem/accounts",
    "viem/chains",
    "vitest",
  ]);
  assert.deepEqual(closureTest.WEB_CONFIG_MODULES, {
    "web/vite.config.ts": {
      barePackages: ["vite", "vite-plugin-solid"],
      sha256: "f8e3310ba29644759402cc83c0046cb71bdc060eee37d172d15cf70338691895",
    },
    "web/vitest.config.ts": {
      barePackages: ["vite-plugin-solid", "vitest/config"],
      sha256: "8d1ec483a5a18b15bc16c0033cdd3eed5d9096922481cbeacc49f8d5d7c1153c",
    },
  });
  assert.deepEqual(closureTest.WEB_PUBLIC_PATHS, [
    "web/public/_headers",
    "web/public/favicon.svg",
    "web/public/wikigen-bootstrap-v3.js",
  ]);
  assert.deepEqual(closureTest.WEB_CSS_DATA_URLS, {
    "web/src/styles.css": [
      "data:image/svg+xml,%3Csvg viewBox='0 0 180 180' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.92' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.12'/%3E%3C/svg%3E",
    ],
  });
  assert.deepEqual(closureTest.WEB_MODULE_IMPORT_META_URLS, {
    "scripts/build-tee-image-release.mjs": [
      "./build-tee-image-release.mjs",
    ],
    "scripts/cvm-release-descriptor-set-v3.mjs": [
      "./cvm-release-descriptor-set-v3.mjs",
    ],
    "scripts/phala-seven-cvm-verifier-evidence.mjs": [
      "./phala-seven-cvm-dcap-verify.py",
    ],
    "web/scripts/bootstrap-retirement.test.mjs": [
      "./bootstrap-retirement.test.mjs",
    ],
    "web/scripts/build-release-env.mjs": [
      "./build-release-env.mjs",
    ],
    "web/scripts/build-release-env.test.mjs": [
      "./build-release-env.test.mjs",
    ],
    "web/scripts/build-security-headers.mjs": [
      "./build-security-headers.mjs",
    ],
    "web/scripts/cloudflare-build-sandbox-core.test.mjs": [
      "./cloudflare-build-sandbox-core.test.mjs",
    ],
    "web/scripts/cloudflare-external-build-closure-core.mjs": [
      "../node_modules/typescript/lib/typescript.js",
    ],
    "web/scripts/cloudflare-external-build-closure-core.test.mjs": [
      "../..",
      "../node_modules/typescript/lib/typescript.js",
    ],
    "web/scripts/cloudflare-release-artifact-core.test.mjs": ["../.."],
    "web/scripts/deploy-cloudflare-runner.test.mjs": [
      "../node_modules/wrangler/wrangler-dist/cli.js",
      "../package-lock.json",
      "../package.json",
    ],
    "web/scripts/deploy-cloudflare.mjs": [
      "./deploy-cloudflare.mjs",
    ],
    "web/scripts/external-five-historical-evidence-core.test.mjs": [
      "../../scripts/canonical-authority-graph.mjs",
      "./external-five-historical-evidence-core.mjs",
    ],
    "web/scripts/frontend-build-candidate-producer-core.mjs": [
      "./frontend-build-candidate-producer-core.mjs",
    ],
    "web/scripts/frontend-release-historical-core.test.mjs": [
      "./frontend-release-historical-core.mjs",
    ],
    "web/scripts/independent-eip191-replay-core.test.mjs": [
      "../package-lock.json",
      "../package.json",
      "./independent-eip191-replay-core.mjs",
    ],
    "web/scripts/pitch-assets-provenance.test.mjs": [
      "../..",
      "../../outputs/wikigen-pitch-assets/attested-network.png",
      "../../outputs/wikigen-pitch-assets/private-reward-oracle.png",
    ],
    "web/scripts/pages-apex-redirect.test.mjs": [
      "./pages-apex-redirect.test.mjs",
    ],
    "web/scripts/release-env-core.test.mjs": [
      "../RELEASE-MANIFEST.md",
      "../../⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",
    ],
    "web/scripts/security-headers-core.test.mjs": [
      "./security-headers-core.test.mjs",
    ],
  });
  assert.deepEqual(closureTest.WEB_STATIC_MODULE_PATHS, [
    "web/functions/_middleware.js",
  ]);
  assert.deepEqual(closureTest.RESOURCE_CONSUMER_BINDINGS, [
    {
      consumer: "scripts/phala-seven-cvm-verifier-evidence.mjs",
      externalPath: "scripts/phala-seven-cvm-dcap-verify.py",
      query: "",
      requestKind: "import_meta_url",
      specifier: "./phala-seven-cvm-dcap-verify.py",
    },
    {
      consumer: "web/src/components/ComputeWorkloadPanel.test.ts",
      externalPath: "docs/compute-console-api.md",
      query: "?raw",
      requestKind: "static_import",
      specifier: "../../../docs/compute-console-api.md?raw",
    },
    {
      consumer: "web/src/productTruth.test.ts",
      externalPath: "ARCHITECTURE.md",
      query: "?raw",
      requestKind: "static_import",
      specifier: "../../ARCHITECTURE.md?raw",
    },
    {
      consumer: "web/src/productTruth.test.ts",
      externalPath: "PROJECT.md",
      query: "?raw",
      requestKind: "static_import",
      specifier: "../../PROJECT.md?raw",
    },
    {
      consumer: "web/src/productTruth.test.ts",
      externalPath: "README.md",
      query: "?raw",
      requestKind: "static_import",
      specifier: "../../README.md?raw",
    },
    {
      consumer: "web/scripts/release-env-core.test.mjs",
      externalPath: "⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",
      query: "",
      requestKind: "import_meta_url",
      specifier: "../../⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",
    },
    {
      consumer: "web/scripts/pitch-assets-provenance.test.mjs",
      externalPath: "outputs/wikigen-pitch-assets/attested-network.png",
      query: "",
      requestKind: "import_meta_url",
      specifier: "../../outputs/wikigen-pitch-assets/attested-network.png",
    },
    {
      consumer: "web/scripts/pitch-assets-provenance.test.mjs",
      externalPath: "outputs/wikigen-pitch-assets/private-reward-oracle.png",
      query: "",
      requestKind: "import_meta_url",
      specifier: "../../outputs/wikigen-pitch-assets/private-reward-oracle.png",
    },
  ]);
  assert.equal(closureTest.RESOURCE_DEFINITIONS.length, 9);
});

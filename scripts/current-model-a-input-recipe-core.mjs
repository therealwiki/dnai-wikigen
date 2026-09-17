// Current Model-A inputs are one fixed recipe, not caller-selected flags.
// Historical exact-35/exact-37 recipes remain in their frozen validators.
export const CURRENT_MODEL_A_LIVE_INPUT_FLAGS = Object.freeze([
  "--release",
  "--release-core",
  "--runtime-authority-dependency",
  "--deployment-intent",
  "--contract-receipt",
  "--reviewer-authority-genesis",
  "--reviewer-authority-genesis-acceptance",
  "--bootstrap-authority",
  "--bootstrap-authorization",
  "--bootstrap-authorization-receipt",
  "--seven-cvm-launch-completion-receipt",
  "--main-runtime-qvl-challenge",
  "--main-runtime-independent-tdx-verdict",
  "--diligence-qvl-identity-request",
  "--diligence-qvl-identity-response",
  "--arena-qvl-identity-request",
  "--arena-qvl-identity-response",
  "--anchor-writer-qvl-identity-request",
  "--anchor-writer-qvl-identity-response",
  "--compute-workload-qvl-identity-request",
  "--compute-workload-qvl-identity-response",
  "--compute-metering-qvl-identity-request",
  "--compute-metering-qvl-identity-response",
  "--independent-metering-qvl-challenge",
  "--independent-metering-independent-tdx-verdict",
  "--image-release-sigstore-verification-receipt",
  "--cvm-descriptor-set-receipt",
  "--phala-executor-final-state",
  "--ceremony-authorization",
  "--ledger",
  "--artifact-evidence",
  "--arena-evidence",
  "--anchor-writer-evidence",
  "--email-oracle-evidence",
  "--live-activation-authority",
  "--royalty-release-history-receipt",
  "--post-measurement-activation-execution-receipt",
  "--compute-workload-activation-observation",
  "--frontend-build-candidate-receipt",
]);

export const CURRENT_MODEL_A_EXCLUDED_CYCLIC_INPUT_FLAGS = Object.freeze([
  "--live-activation-authority",
  "--frontend-build-candidate-receipt",
]);

// The standalone activation receipt is already machine evidence before C.
// Keeping it in pre-D avoids using final C to prove the inputs of D itself.
export const CURRENT_MODEL_A_PREBUILD_INPUT_FLAGS = Object.freeze(
  CURRENT_MODEL_A_LIVE_INPUT_FLAGS.filter(
    (flag) => !CURRENT_MODEL_A_EXCLUDED_CYCLIC_INPUT_FLAGS.includes(flag),
  ),
);

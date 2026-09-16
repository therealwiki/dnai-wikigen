# Deployment manifests

No fresh project-owned seven-contract Base Sepolia suite or seven-CVM Phala
release has been deployed from the current working tree. Existing addresses,
CVM identifiers, and evidence in this directory are historical inputs only.
Local Anvil broadcasts and rendered `rendered_not_deployed` compose files must
never replace or promote those current pointers.

`base-sepolia.json` is the machine-readable deployment ledger for chain ID
84532. It contains both current pointers and historical Phala/contract evidence;
it must never be recreated from scratch during a partial deployment.

The fresh contract-suite helper applies
`⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq` to the
existing object. The merge:

- preserves unrelated top-level fields and nested Phala evidence;
- snapshots replaced current contract entries into `deploymentHistory`;
- validates the canonical, independently reviewed deployment-intent core from
  the ignored `.release/` workspace before wallet access or simulation, records
  its immutable digest in append-only deployment history, and does not pretend
  that post-deployment contract/CVM identities or the final authority were
  known before broadcast;
- updates current pointers only after runtime bytecode and trust-root reads pass;
- records the source commit, transactions, explicit operator, and the initially
  unset Diligence result-verifier state that awaits its timelocked ceremony;
- records that DiligenceRoom's 100 bps fee was frozen during the deployment
  transaction, eliminating mutable post-release metering;
- records that its one-way 100 bps deterministic compute-settlement policy was
  enabled, preventing evaluator-selected cost values from becoming an output
  channel;
- records exact creation-reexecution runtime code hashes for all seven fresh
  contracts in both the current entries and append-only deployment history;
- marks the new DiligenceRoom `fail_closed_pending_cvm_binding`: both compose
  and TEE-identity gates are enabled, their requirements are irreversibly
  frozen, the active and pending compose/TEE counters are all zero, and both
  addition paths remain open only for the reviewed timelocked activation flow;
- activates DiligenceRoom only through the separate four-phase, six-day minimum
  `configure-diligence-release.sh` flow. Phase 3 closes the exact release policy
  and proposes the deployment-intent and final-authority-reviewed permanent
  governance controller already bound immutably by the room constructor as the
  production fee recipient;
  phase 4 can be accepted only by that controller after the fixed delay through
  its own reviewed EOA or contract-wallet ceremony. The operator helper never
  broadcasts phase 4 or replaces the encrypted `dev` account; it verifies a
  finalized direct-call receipt for an EOA or explicitly bounded event+state
  evidence with no trace claim for a Safe/contract controller. The final
  release must contain
  exactly one active compose hash, exactly one active TEE identity bound to that
  compose, zero pending proposals, permanent freezes on both addition paths,
  developer equal to the reviewed controller, and no pending developer transfer;
  emergency revocation is fail-closed and cannot be followed by replacement
  admission at the same address;
- replaces EmailOracleAuth with a same-operator, exact-runtime-checked instance
  that is explicitly deny-all pending CVM binding, while retaining its prior
  pointer in deployment history;
- adds `ComputeCreditVault` with a permanently frozen developer fee and empty
  compose/TEE/rate-policy admission. The vault is deployed but execution stays
  fail-closed until the timelocked release bindings are independently reviewed;
- activates that vault only through the separate three-phase, four-day minimum
  `configure-compute-release.sh` flow. The final release must expose exactly one
  ERC20 admission, two active rate policies, and one compose hash, then freeze
  asset additions, rate-policy additions, and the compose requirement;
- adds `ExecutionPolicyAnchor` paused with no writer, no release commitment,
  no pending proposal, and zero heads. Its separate two-phase helper timelocks
  the final CVM-controlled writer/release pair, permanently freezes writer
  rotation, and only then unpauses. The ledger records its exact runtime and
  complete initial fail-closed tuple; a local anchor event is never described as
  TDX or QVL evidence;
- records that challenge-prize, bond, and candidate custody are excluded. Vault
  credits are non-transferable, exact-asset claims and have no oracle or FX.

The fresh `TinkerAccountEncumbrance` entry is intentionally a halted
constructor draft with empty compose and manager authority sets. It becomes
production-current only after the two ordered
governance phases and immutable two-day review complete. The final current entry
uses status `deployed_exact_release_policy_frozen_active` and policy state
`exact_timelocked_release_policy_frozen_active`; it records exact account,
decimal-string caps, one compose, one distinct manager, current/frozen-baseline
roots and counts, no pending policy, `releasePolicyFrozen=true`, and
`emergencyHalted=false`. The matching `deploymentHistory` entry retains the
original fail-closed draft, while `tinkerReleaseHistory` retains both broadcasts
bound to chain, address, runtime code, and source. Rewriting the draft in place
would erase deployment provenance and is rejected.

The deploy helper defaults to a dry run and does not touch this ledger until a
successful `BROADCAST=true` flow completes all post-deployment checks. A failed
broadcast or failed verification read must leave the existing manifest intact.

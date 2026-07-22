# Email oracle attestation boundary

`GET /attestation` is an evidence endpoint, not a verdict endpoint. In dstack
mode it returns the quote bytes supplied by dstack, the claimed app/compose/OS
identity fields, and a context-bound X25519 credential-ingress key. The oracle
does not run an independent Intel DCAP/QVL verification of its own quote.

The response is an exact service/context/key/code/quote envelope. It contains
no mailbox address or commitment, readiness flag, IMAP state, message/header
value, or server timestamp. Those private and stateful values cannot modulate
the response bytes for a fixed key, context, and deployed code identity.

The response therefore always returns `verified: false`, including when
`mode: "tdx"` and `tdx_quote` is non-empty. A successful dstack SDK call means
only that evidence was retrieved. It does not establish a valid signature,
current collateral/TCB status, expected measurements, or a trusted report-data
binding.

The bundled credential uploader performs bounded envelope checks: fetch age,
mode, claimed app/compose/OS values, key shape, context, and report-data/key
consistency. Those checks are not cryptographic quote verification. Production
credential provisioning fails closed against the oracle's service-local
`verified: false` until an independently authenticated verifier handoff is
integrated. The explicit local-attestation flag exists only for development.

Before enabling production mailbox credential provisioning:

1. Independently validate the fresh quote signature and Intel collateral/TCB
   status with a maintained DCAP/QVL verifier.
2. Enforce approved app, compose, OS, and TDX measurement policy.
3. Extract report data from the verified quote and bind it to the exact
   `oracle-credentials` public key returned by this deployment.
4. Authenticate the verifier verdict separately from the quote-producing
   oracle and enforce a short freshness window.
5. Keep provisioning disabled on any missing, stale, ambiguous, or mismatched
   evidence.

Until those gates are present, the TDX credential-ingress path is roadmap
security infrastructure rather than a live attestation guarantee.

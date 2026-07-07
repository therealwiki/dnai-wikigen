import type { GateEnv } from "../gate/evaluate";

/**
 * A synchronous, illustrative hash. NOT cryptographic — it exists only to
 * produce a stable, hash-shaped hex string for the demo's resultHash /
 * signature fields, which stand in for a real enclave-signed digest.
 */
export function demoHash(input: string): string {
  const seeds = [0x811c9dc5, 0x1000193, 0xdeadbeef, 0x9e3779b1, 0x85ebca77, 0xc2b2ae3d, 0x27d4eb2f, 0x165667b1];
  let out = "";
  for (const seed of seeds) {
    let h = seed >>> 0;
    for (let i = 0; i < input.length; i++) {
      h ^= input.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    out += h.toString(16).padStart(8, "0");
  }
  return out;
}

function demoSignature(payload: string): string {
  const digest = demoHash(payload);
  // Shape it like a TDX-quote-anchored signature reference, but label it plainly
  // as illustrative — this is a non-cryptographic hash, NOT a verified TDX quote.
  return `tdx:mrenclave=${digest.slice(0, 16)}…:sig=${digest.slice(16, 48)}:illustrative-not-verified`;
}

/**
 * Fresh env per run. `now()` advances a few ms per call so the four stage
 * verdicts and the attestation carry realistically increasing timestamps.
 */
export function createRuntimeEnv(): GateEnv {
  let t = Date.now();
  const uuid = () =>
    typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : demoHash(String(t) + Math.random()).replace(/(.{8})(.{4})(.{4})(.{4})(.{12}).*/, "$1-$2-$3-$4-$5");
  return {
    now: () => {
      t += 37;
      return new Date(t).toISOString();
    },
    uuid,
    sign: demoSignature,
    hash: (p: string) => demoHash(p),
  };
}

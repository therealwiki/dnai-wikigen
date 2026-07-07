import { useEffect, useMemo, useRef, useState } from "react";
import {
  DAEMON_BASE,
  fetchSubstrate,
  fetchVerification,
  osImageHash,
  resolveTargets,
  type SubstrateClaim,
  type TeeTarget,
  type VerificationBundle,
} from "../lib/dstackVerifier";
import { CAPTURED_AT, CAPTURED_SUBSTRATE, CAPTURED_VERIFICATION } from "../data/attestationFixture";
import { Section } from "./ui/atoms";
import { JsonView } from "./JsonView";
import styles from "./LiveAttestation.module.css";

type Status = "idle" | "fixture" | "loading" | "live" | "error";

const shortHost = (url: string) => url.replace(/^https?:\/\//, "").split("/")[0];

export function LiveAttestation() {
  const targets = useMemo(() => resolveTargets(), []);
  const selfTarget = useMemo(() => targets.find((t) => t.isSelf), [targets]);
  const initial: TeeTarget = selfTarget ?? targets.find((t) => t.hasFixture) ?? targets[0];

  const [selectedKey, setSelectedKey] = useState<string>(initial.key);
  const [bundle, setBundle] = useState<VerificationBundle | null>(initial.hasFixture ? CAPTURED_VERIFICATION : null);
  const [substrate, setSubstrate] = useState<SubstrateClaim | null>(initial.hasFixture ? CAPTURED_SUBSTRATE : null);
  const [status, setStatus] = useState<Status>(initial.hasFixture ? "fixture" : "idle");
  const [error, setError] = useState<string>("");
  const [fetchedAt, setFetchedAt] = useState<string>("");

  const target = targets.find((t) => t.key === selectedKey) ?? initial;

  const selectTarget = (key: string) => {
    const t = targets.find((x) => x.key === key) ?? initial;
    setSelectedKey(key);
    setError("");
    setFetchedAt("");
    if (t.hasFixture) {
      setBundle(CAPTURED_VERIFICATION);
      setSubstrate(CAPTURED_SUBSTRATE);
      setStatus("fixture");
    } else {
      setBundle(null);
      setSubstrate(null);
      setStatus("idle");
    }
  };

  const verifyLive = async () => {
    setStatus("loading");
    setError("");
    try {
      const [v, s] = await Promise.all([fetchVerification(target.project, target.base), fetchSubstrate(target.base)]);
      setBundle(v);
      setSubstrate(s);
      setFetchedAt(new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC"));
      setStatus("live");
    } catch (e) {
      setError(e instanceof Error ? e.message : "fetch failed");
      setStatus("error");
    }
  };

  // When this build is hosted on its own tee-daemon, verify its OWN attestation
  // on load (same-origin / configured — cheap). The external reference demo stays
  // click-to-verify so plain browsing never fires a cross-origin request.
  const autoRan = useRef(false);
  useEffect(() => {
    if (autoRan.current) return;
    if (initial.isSelf) {
      autoRan.current = true;
      void verifyLive();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const src = bundle?.app.source;
  const osHash = bundle ? osImageHash(bundle) : null;
  const quoteLen = bundle ? bundle.platform_quote.quote.replace(/….*$/, "").length : 0;

  return (
    <Section
      id="attestation"
      eyebrow="The privacy layer, for real"
      title="Verify a live TEE — a real attestation, not a demo hash"
      sub={
        selfTarget ? (
          <>
            This build is wired to verify <strong>itself</strong>: it is hosted on a dstack-webhost tee-daemon, so it can
            fetch its own source-hash-bound Intel TDX quote. The reference demo remains selectable for comparison.
          </>
        ) : (
          <>
            This app's own attestations are illustrative scaffolding. dstack-webhost hosts tenants inside a Phala Intel
            TDX enclave and binds each project's source hash into a real TDX quote; its verifier endpoints are public and
            CORS-open, so this page fetches a genuine attestation live. Host this app on a tee-daemon (see{" "}
            <code>deploy/</code>) and it verifies itself.
          </>
        )
      }
    >
      <div className={styles.contrast}>
        <div className={`${styles.card} ${styles.cardIllus}`}>
          <p className={styles.cardLabel}>This app's gate · illustrative</p>
          <p className={styles.cardText}>
            The gate simulator signs with <code>tdx:mrenclave=…:sig=…:illustrative-not-verified</code> — a
            non-cryptographic demo hash. It shows the <em>shape</em> of provenance, but proves nothing.
          </p>
        </div>
        <div className={`${styles.card} ${styles.cardReal}`}>
          <p className={styles.cardLabel}>dstack-webhost · real{target.isSelf ? " · this app" : ""}</p>
          <p className={styles.cardText}>
            A hardware-rooted TDX quote binds the running code's measurement to its output. The source{" "}
            <code>tree_hash</code> is folded into the enclave measurement; a relying party verifies it without trusting
            the operator{target.isSelf ? " — and here, the running code is this very app." : "."}
          </p>
        </div>
      </div>

      <div className={styles.controls}>
        <label className="sr-only" htmlFor="attest-target">
          Target to verify
        </label>
        <select
          id="attest-target"
          className={styles.select}
          value={selectedKey}
          onChange={(e) => selectTarget(e.target.value)}
        >
          {targets.map((t) => (
            <option key={t.key} value={t.key}>
              {t.label}
            </option>
          ))}
        </select>
        <button className={styles.verifyBtn} onClick={verifyLive} disabled={status === "loading"} type="button">
          {status === "loading" ? "verifying…" : "▸ Verify live"}
        </button>
        <span
          className={`${styles.status} ${
            status === "live" ? styles.statusLive : status === "error" ? styles.statusError : styles.statusFixture
          }`}
          role="status"
        >
          {status === "live" && `✓ fetched live · ${fetchedAt} · ${target.project}`}
          {status === "fixture" && `captured ${CAPTURED_AT} (offline fixture — genuine ${target.project} bundle)`}
          {status === "idle" && `not verified yet — click “Verify live” to fetch ${target.project} from ${shortHost(target.base)}`}
          {status === "loading" && "contacting the enclave…"}
          {status === "error" && `live fetch failed (${error})${bundle ? " — showing last bundle" : ""}`}
        </span>
      </div>

      {bundle && src ? (
        <div className={styles.layout}>
          <dl className={styles.facts}>
            <div className={styles.fact}>
              <dt className={styles.factLabel}>Project</dt>
              <dd className={styles.factValue}>
                {bundle.app.project}
                {target.isSelf && " · this app"}
              </dd>
            </div>
            <div className={styles.fact}>
              <dt className={styles.factLabel}>Substrate runtime</dt>
              <dd className={styles.factValue}>
                {substrate?.effective_runtime ?? "—"} {substrate?.effective_runtime === "runsc" && "(gVisor)"}
              </dd>
            </div>
            <div className={styles.fact}>
              <dt className={styles.factLabel}>Source</dt>
              <dd className={styles.factValue}>
                {src.repo ? (
                  <a href={src.repo} target="_blank" rel="noreferrer noopener">
                    {src.repo.replace(/^https?:\/\//, "")}
                  </a>
                ) : (
                  "—"
                )}
                {src.commit_sha && <> @ {src.commit_sha.slice(0, 10)}</>}
              </dd>
            </div>
            <div className={styles.fact}>
              <dt className={styles.factLabel}>Source tree_hash → measurement</dt>
              <dd className={styles.factValue}>{src.tree_hash || "—"}</dd>
            </div>
            <div className={styles.fact}>
              <dt className={styles.factLabel}>Image digest</dt>
              <dd className={styles.factValue}>{bundle.app.image_digest || "—"}</dd>
            </div>
            <div className={styles.fact}>
              <dt className={styles.factLabel}>OS image hash</dt>
              <dd className={styles.factValue}>{osHash ?? "—"}</dd>
            </div>
            <div className={styles.fact}>
              <dt className={styles.factLabel}>Binding key (KMS-rooted)</dt>
              <dd className={styles.factValue}>
                {bundle.app.binding_quote.pubkey}
                <br />
                <span className={styles.chain}>
                  ⛓ signature chain · {bundle.app.binding_quote.signature_chain.length} links
                </span>
              </dd>
            </div>
            <div className={styles.fact}>
              <dt className={styles.factLabel}>TDX quote</dt>
              <dd className={styles.factValue}>
                {quoteLen.toLocaleString()} hex chars{status !== "live" && " (truncated in fixture)"}
              </dd>
            </div>
          </dl>

          <div>
            <p className={styles.jsonLabel}>VerificationBundle · GET /_api/verification/{bundle.app.project}</p>
            <JsonView value={bundle} label="Live TEE verification bundle JSON" />
          </div>
        </div>
      ) : (
        <div className={styles.facts}>
          <p className={styles.cardText}>
            {status === "error"
              ? `Could not reach ${shortHost(target.base)}. If this is a self-hosted target, confirm the daemon is up and the project is promoted to attested.`
              : `Press “Verify live” to pull a real attestation for ${target.project} from ${shortHost(target.base)}.`}
          </p>
        </div>
      )}

      <p className={styles.footNote}>
        {selfTarget ? (
          <>
            <strong>Wired to self.</strong> This build targets <code>{selfTarget.base}</code> (project{" "}
            <code>{selfTarget.project}</code>). Change it with <code>VITE_TEE_DAEMON_URL</code> /{" "}
            <code>VITE_TEE_PROJECT</code> at build time, or it auto-detects a same-origin daemon.{" "}
          </>
        ) : (
          <>
            <strong>Interacting with the privacy layer.</strong>{" "}
          </>
        )}
        Three ways: (1) <strong>verify</strong> — fetch these public endpoints, as above (also{" "}
        <a href={`${DAEMON_BASE}/probe/`} target="_blank" rel="noreferrer noopener">
          the live isolation probe
        </a>
        ); (2) <strong>host this gate</strong> — its Vite <code>dist/</code> deploys as a <code>runtime:"static"</code>{" "}
        project via <code>deploy/deploy-gate.sh --promote</code>, which bakes the daemon URL into this section; (3){" "}
        <strong>run your own daemon</strong> — <code>deploy/provision-daemon.sh</code> on Phala, or{" "}
        <code>docker compose up</code> locally. See{" "}
        <a href="https://amiller.github.io/dstack-webhost" target="_blank" rel="noreferrer noopener">
          amiller.github.io/dstack-webhost
        </a>
        .
      </p>
    </Section>
  );
}

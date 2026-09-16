import { createMemo, createSignal, For, onMount, Show } from "solid-js";
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  MailCheck,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from "lucide-solid";
import { deployment, explorerAddress, explorerTx } from "../config";
import { shortAddress } from "../lib/contract";
import {
  assessEmailOracleReadiness,
  configuredEmailOracleRelease,
  observeEmailOracleReadiness,
  type EmailOracleReadinessObservation,
  type EmailOracleRelease,
} from "../lib/emailOracleReadiness";

type PanelState = "unconfigured" | "idle" | "loading" | "ready" | "blocked" | "error";

interface ReleaseConfigResult {
  release?: EmailOracleRelease;
  error?: string;
}

function releaseConfig(): ReleaseConfigResult {
  try {
    return {
      release: configuredEmailOracleRelease(
        deployment.emailOracleAuthAddress,
        deployment.emailOracleAuthCodeHash,
      ),
    };
  } catch (error) {
    return { error: error instanceof Error ? error.message : "EmailOracleAuth release configuration is invalid" };
  }
}

function BooleanFact(props: { label: string; value: boolean; trueLabel: string; falseLabel: string }) {
  return (
    <div class={`email-oracle-fact ${props.value ? "pass" : "fail"}`}>
      {props.value ? <CheckCircle2 size={15} /> : <XCircle size={15} />}
      <span><small>{props.label}</small><strong>{props.value ? props.trueLabel : props.falseLabel}</strong></span>
    </div>
  );
}

export function EmailOracleReadinessPanel() {
  const config = releaseConfig();
  const [state, setState] = createSignal<PanelState>(config.release ? "idle" : "unconfigured");
  const [message, setMessage] = createSignal(config.error ?? "No finalized Base Sepolia observation has been requested yet.");
  const [observation, setObservation] = createSignal<EmailOracleReadinessObservation>();

  const assessment = createMemo(() => {
    const value = observation();
    return value && config.release ? assessEmailOracleReadiness(value, config.release) : undefined;
  });

  const refresh = async (): Promise<void> => {
    if (!config.release || state() === "loading") return;
    setState("loading");
    setMessage("Reading the release contract and KMS binding at one RPC-reported finalized block…");
    setObservation(undefined);
    try {
      const value = await observeEmailOracleReadiness(config.release);
      const result = assessEmailOracleReadiness(value, config.release);
      setObservation(value);
      if (result.ready) {
        setState("ready");
        setMessage("Contract authorization is dynamically ready at the pinned block. This is not an email-delivery or TDX/QVL verdict.");
      } else {
        setState("blocked");
        setMessage(`${result.blockers.length} fail-closed release condition${result.blockers.length === 1 ? " is" : "s are"} not satisfied at the pinned block.`);
      }
    } catch (error) {
      setState("error");
      setMessage(error instanceof Error ? error.message : "Email Oracle readiness could not be observed");
    }
  };

  onMount(() => {
    if (config.release) void refresh();
  });

  const statusTitle = (): string => {
    switch (state()) {
      case "ready": return "Contract auth configuration ready";
      case "blocked": return "Contract auth configuration blocked";
      case "loading": return "Reading finalized release state";
      case "error": return "Readiness observation rejected";
      case "unconfigured": return "Release configuration absent";
      default: return "Readiness not yet observed";
    }
  };

  return (
    <section class="email-oracle-readiness" aria-labelledby="email-oracle-readiness-title">
      <div class="email-oracle-readiness-head">
        <div>
          <p class="overline">Layer · email authorization</p>
          <h2 id="email-oracle-readiness-title">Dynamic Email Oracle readiness</h2>
          <p>Read-only release diagnostics for <code>EmailOracleAuth</code>. Every contract, membership, and KMS fact is read at one RPC-reported finalized Base Sepolia block.</p>
        </div>
        <div class="email-oracle-readiness-actions">
          <span class={`email-oracle-mode-chip ${observation() ? "observed" : "blocked"}`}>
            {observation() ? "LIVE READ · SINGLE RPC" : state() === "loading" || state() === "idle" ? "LIVE READ · PENDING" : "LIVE READ PATH · BLOCKED"}
          </span>
          <span class="read-only-chip"><LockKeyhole size={13} /> READ ONLY</span>
          <button
            class="icon-button"
            type="button"
            aria-label="Refresh Email Oracle readiness"
            aria-controls="email-oracle-readiness-status"
            aria-busy={state() === "loading"}
            disabled={!config.release || state() === "loading"}
            onClick={() => void refresh()}
          >
            <RefreshCw class={state() === "loading" ? "spin" : ""} size={16} />
          </button>
        </div>
      </div>

      <div id="email-oracle-readiness-status" class={`email-oracle-status ${state()}`} role="status" aria-live="polite" aria-atomic="true">
        {state() === "ready"
          ? <ShieldCheck size={22} />
          : state() === "loading" || state() === "idle"
            ? <Fingerprint size={22} />
            : <AlertTriangle size={22} />}
        <div><strong>{statusTitle()}</strong><span>{message()}</span></div>
      </div>

      <Show when={config.release} fallback={
        <div class="email-oracle-unconfigured">
          <KeyRound size={18} />
          <div>
            <strong>Fail closed · no release identity</strong>
            <span>Both a non-zero contract address and exact runtime code-hash pin must be embedded in this frontend release before the browser will query readiness. No previous operator address is inherited.</span>
          </div>
        </div>
      }>
        {(release) => (
          <div class="email-oracle-release-identity">
            <div><small>EMAILORACLEAUTH</small><a href={explorerAddress(release().address)} target="_blank" rel="noreferrer"><code>{release().address}</code><ExternalLink size={12} /></a></div>
            <div><small>RELEASE RUNTIME PIN</small><code>{release().runtimeCodeHash}</code></div>
          </div>
        )}
      </Show>

      <Show when={observation()} keyed>
        {(value) => {
          const proxyRuntimeMatches = value.observedKmsRuntimeCodeHash?.toLowerCase() === value.kmsRuntimeCodeHash.toLowerCase();
          const implementationRuntimeMatches = value.observedKmsImplementationRuntimeCodeHash?.toLowerCase() === value.kmsImplementationRuntimeCodeHash.toLowerCase();
          return (
            <div class="email-oracle-observation">
              <div class="email-oracle-block-pin">
                <Fingerprint size={16} />
                <span><small>RPC-REPORTED FINALIZED OBSERVATION</small><strong>Base Sepolia block {value.blockNumber.toString()}</strong><code>{value.blockHash}</code></span>
              </div>

              <div class="email-oracle-fact-grid">
                <BooleanFact label="CONSTRUCTOR MODE" value={value.productionRelease} trueLabel="Production release" falseLabel="Development release" />
                <BooleanFact label="DYNAMIC CONTRACT READ" value={value.releaseConfigurationReady} trueLabel="releaseConfigurationReady = true" falseLabel="releaseConfigurationReady = false" />
                <BooleanFact label="ORACLE CODE" value={value.oracleCodeFrozen} trueLabel="Compose + device frozen" falseLabel="Additions remain open" />
                <BooleanFact label="CONSUMER MANAGERS" value={value.consumerManagerAdditionsFrozen} trueLabel="Additions frozen" falseLabel="Additions remain open" />
                <BooleanFact label="CONSUMER REGISTRY" value={value.consumerRegistryFrozen} trueLabel="Registry frozen" falseLabel="Registry remains open" />
                <BooleanFact label="KMS BINDING" value={value.kmsBindingFrozen} trueLabel="Binding frozen" falseLabel="Binding remains mutable" />
              </div>

              <div class="email-oracle-detail-grid">
                <article>
                  <div class="email-oracle-detail-head"><MailCheck size={17} /><span><small>CONSUMER AUTHORITY</small><strong>Exact membership, dynamically revocable</strong></span></div>
                  <dl>
                    <div><dt>Oracle compose</dt><dd><code>{shortAddress(value.releaseOracleComposeHash, 8)}</code><span class={value.oracleComposeRegistered ? "pass" : "fail"}>{value.oracleComposeRegistered ? "registered" : "removed"}</span></dd></div>
                    <div><dt>Device</dt><dd><code>{shortAddress(value.releaseDeviceId, 8)}</code><span class={value.deviceRegistered && !value.allowAnyDevice ? "pass" : "fail"}>{value.allowAnyDevice ? "any device allowed" : value.deviceRegistered ? "exact device" : "removed"}</span></dd></div>
                    <div><dt>Consumer app</dt><dd><code>{shortAddress(value.releaseConsumerAppId, 8)}</code><span class={value.consumerComposeRegistered ? "pass" : "fail"}>{value.consumerComposeHashCount.toString()} compose binding</span></dd></div>
                    <div><dt>Consumer compose</dt><dd><code>{shortAddress(value.releaseConsumerComposeHash, 8)}</code><span class={value.consumerComposeRegistered ? "pass" : "fail"}>{value.consumerComposeRegistered ? "registered" : "removed"}</span></dd></div>
                    <div><dt>Consumer manager</dt><dd><code>{shortAddress(value.releaseConsumerManager, 8)}</code><span class={value.consumerManagerActive ? "pass" : "fail"}>{value.consumerManagerActive ? "active" : "removed"}</span></dd></div>
                    <div><dt>Emergency status</dt><dd><strong>{value.consumerEmergencyRevoked ? "Revoked" : "Not revoked"}</strong><span class={value.consumerEmergencyRevoked ? "fail" : "pass"}>{value.consumerAuthorized ? "authorized" : "deny all"}</span></dd></div>
                  </dl>
                </article>

                <article>
                  <div class="email-oracle-detail-head"><KeyRound size={17} /><span><small>KMS BINDING</small><strong>Proxy, implementation, and registration readback</strong></span></div>
                  <dl>
                    <div><dt>KMS proxy</dt><dd><a href={explorerAddress(value.kmsContract)} target="_blank" rel="noreferrer"><code>{shortAddress(value.kmsContract, 8)}</code><ExternalLink size={11} /></a><span class={proxyRuntimeMatches ? "pass" : "fail"}>{proxyRuntimeMatches ? "runtime matches" : "runtime mismatch"}</span></dd></div>
                    <div><dt>Implementation</dt><dd><a href={explorerAddress(value.kmsImplementation)} target="_blank" rel="noreferrer"><code>{shortAddress(value.kmsImplementation, 8)}</code><ExternalLink size={11} /></a><span class={implementationRuntimeMatches ? "pass" : "fail"}>{implementationRuntimeMatches ? "runtime matches" : "runtime mismatch"}</span></dd></div>
                    <div><dt>registeredApps</dt><dd><strong>{value.kmsRegisteredApp ? "true" : "false"}</strong><span class={value.kmsRegisteredApp ? "pass" : "fail"}>single-RPC readback</span></dd></div>
                    <div><dt>Registration commitment</dt><dd><a href={explorerTx(value.kmsRegistrationTxHash)} target="_blank" rel="noreferrer"><code>{shortAddress(value.kmsRegistrationTxHash, 8)}</code><ExternalLink size={11} /></a><span>block {value.kmsRegistrationBlock.toString()}</span></dd></div>
                    <div><dt>Registration block hash</dt><dd><code>{shortAddress(value.kmsRegistrationBlockHash, 8)}</code><span>committed on-chain</span></dd></div>
                    <div><dt>Boot + restart commitments</dt><dd><code>{shortAddress(value.targetBootInfoHash, 6)}</code><span>{shortAddress(value.restartKeyDerivationProofHash, 6)}</span></dd></div>
                  </dl>
                </article>
              </div>

              <Show when={assessment() && !assessment()?.ready}>
                <div class="email-oracle-blockers" role="region" aria-labelledby="email-oracle-blockers-title">
                  <div><AlertTriangle size={17} /><strong id="email-oracle-blockers-title">Why authorization is blocked</strong></div>
                  <ul><For each={assessment()?.blockers ?? []}>{(blocker) => <li>{blocker}</li>}</For></ul>
                </div>
              </Show>
            </div>
          );
        }}
      </Show>

      <div class="email-oracle-boundary">
        <AlertTriangle size={16} />
        <p><strong>Evidence boundary</strong>This panel does not send email, generate or reveal an OTP, exercise owner or consumer-manager powers, validate the historical KMS registration receipt, prove a restart, verify a TDX quote, check Intel collateral, or authenticate a QVL verdict. “Ready” means only that the read-only contract conditions and runtime pins agree at the displayed single-RPC finalized block.</p>
      </div>
    </section>
  );
}

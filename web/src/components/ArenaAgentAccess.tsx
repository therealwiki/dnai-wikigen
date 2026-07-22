import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import {
  Ban,
  Bot,
  Braces,
  Check,
  Copy,
  Eye,
  EyeOff,
  Fingerprint,
  KeyRound,
  LoaderCircle,
  Plus,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  TerminalSquare,
  TriangleAlert,
  X,
} from "lucide-solid";
import { useModalFocus } from "./AppShell";
import {
  ARENA_AGENT_SCOPES,
  ArenaAgentRequestError,
  arenaAgentCurlQuickstart,
  arenaAgentPythonQuickstart,
  createArenaAgentMutationGuard,
  decryptArenaAgentCredentialCapsule,
  generateArenaAgentDeviceKey,
  issueArenaAgentCredential,
  listArenaAgentCredentials,
  revokeArenaAgentCredential,
  rotateArenaAgentCredential,
  type ArenaAgentCredential,
  type ArenaAgentDeviceKey,
  type ArenaAgentDeviceKind,
} from "../lib/arenaAgent";
import type { ArenaAgentManagementTokenResponse } from "../lib/wallet";

function expiryLabel(timestamp: number): string {
  const remaining = timestamp - Math.floor(Date.now() / 1_000);
  if (remaining <= 0) return "expired";
  if (remaining < 3_600) return `${Math.max(1, Math.ceil(remaining / 60))}m left`;
  return `${Math.max(1, Math.ceil(remaining / 3_600))}h left`;
}

function usedLabel(value: number | null): string {
  if (value === null) return "never";
  return new Date(value * 1_000).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function rotateUnavailableReason(credential: ArenaAgentCredential, hasDeviceKey: boolean): string {
  if (credential.status !== "active") {
    return `Rotation is unavailable while this credential is ${credential.status}.`;
  }
  if (!hasDeviceKey) {
    return "Rotation is unavailable in this tab because its non-exportable device key is not here. Revoke this credential and issue a replacement from the device that will use it.";
  }
  return "";
}

export function ArenaAgentAccess(props: {
  challengeId: string;
  challengeVersion: string;
  walletAddress?: string;
  walletAuthorizationVersion: number;
  authorizeManagement: () => Promise<ArenaAgentManagementTokenResponse>;
  deviceKeys: Map<string, ArenaAgentDeviceKey>;
  releaseBoundWorker: boolean;
}) {
  const [credentials, setCredentials] = createSignal<ArenaAgentCredential[]>([]);
  const [state, setState] = createSignal<"locked" | "loading" | "ready" | "error">("locked");
  const [error, setError] = createSignal("");
  const [notice, setNotice] = createSignal("");
  const [busy, setBusy] = createSignal("");
  const [dialogOpen, setDialogOpen] = createSignal(false);
  const [name, setName] = createSignal("dnaseq-agent");
  const [deviceKind, setDeviceKind] = createSignal<ArenaAgentDeviceKind>("autonomous_agent");
  const [ttlHours, setTtlHours] = createSignal("6");
  const [dailyCap, setDailyCap] = createSignal("8");
  const [oneTimeToken, setOneTimeToken] = createSignal("");
  const [oneTimeCredential, setOneTimeCredential] = createSignal<ArenaAgentCredential>();
  const [revealToken, setRevealToken] = createSignal(false);
  const [example, setExample] = createSignal<"curl" | "python">("curl");
  const [copied, setCopied] = createSignal<"token" | "example" | "">("");
  const [copyError, setCopyError] = createSignal("");
  const [managementSession, setManagementSession] = createSignal<ArenaAgentManagementTokenResponse>();
  const [authorizationState, setAuthorizationState] = createSignal<"locked" | "authorizing" | "ready" | "error">("locked");
  const deviceKeys = props.deviceKeys;
  const mutationGuard = createArenaAgentMutationGuard();
  let dialogRef: HTMLElement | undefined;
  let loadGeneration = 0;
  let disposed = false;

  const mutationContext = (token: string, owner: string) => ({
    token,
    owner,
    challengeId: props.challengeId,
    challengeVersion: props.challengeVersion,
    lease: mutationGuard.begin(),
  });

  const mutationIsCurrent = (context: ReturnType<typeof mutationContext>): boolean => (
    !disposed
    && mutationGuard.isCurrent(context.lease)
    && managementSession()?.access_token === context.token
    && props.walletAddress?.toLowerCase() === context.owner.toLowerCase()
    && props.challengeId === context.challengeId
    && props.challengeVersion === context.challengeVersion
  );

  const assertCurrentMutation = (context: ReturnType<typeof mutationContext>): void => {
    if (
      !mutationIsCurrent(context)
    ) {
      const cause = new Error("Arena wallet session changed; authorize this challenge version again");
      cause.name = "AbortError";
      throw cause;
    }
  };

  const mutationFailedText = (cause: unknown, fallback: string): string => {
    const reason = cause instanceof Error ? cause.message : fallback;
    return `${reason}. If the service may have accepted the request, refresh the list and revoke any unexpected active credential.`;
  };

  const sessionMatchesIdentity = (session: ArenaAgentManagementTokenResponse): boolean => (
    session.address.toLowerCase() === props.walletAddress?.toLowerCase()
    && session.challenge_id === props.challengeId
    && session.challenge_version === props.challengeVersion
    && session.expires_at > Math.floor(Date.now() / 1_000) + 5
  );

  function clearManagementAuthorization(message = ""): void {
    ++loadGeneration;
    mutationGuard.invalidate();
    setBusy("");
    setManagementSession(undefined);
    setAuthorizationState(message ? "error" : "locked");
    setCredentials([]);
    setState("locked");
    clearOneTimeSecret();
    if (message) setError(message);
  }

  const load = async (token = managementSession()?.access_token): Promise<void> => {
    if (!token) {
      setCredentials([]);
      setState("locked");
      return;
    }
    const generation = ++loadGeneration;
    setState("loading");
    setError("");
    try {
      const next = await listArenaAgentCredentials(token, props.challengeId, props.challengeVersion);
      if (generation !== loadGeneration || managementSession()?.access_token !== token) return;
      setCredentials(next);
      setState("ready");
    } catch (cause) {
      if (generation !== loadGeneration || managementSession()?.access_token !== token) return;
      if (cause instanceof ArenaAgentRequestError && cause.status === 401) {
        clearManagementAuthorization("Agent-management authorization expired. Sign the exact management request again; device keys for this wallet and challenge remain only in this tab.");
        return;
      }
      setCredentials([]);
      setState("error");
      setError(cause instanceof Error ? cause.message : "Arena agent credentials are unavailable");
    }
  };

  createEffect(() => {
    const identity = `${props.walletAddress?.toLowerCase() ?? ""}:${props.walletAuthorizationVersion}:${props.challengeId}@${props.challengeVersion}`;
    void identity;
    ++loadGeneration;
    mutationGuard.invalidate();
    setBusy("");
    setNotice("");
    setError("");
    setManagementSession(undefined);
    setAuthorizationState("locked");
    setCredentials([]);
    setState("locked");
    clearOneTimeSecret();
  });

  createEffect(() => {
    const session = managementSession();
    if (!session) return;
    const delay = Math.max(0, session.expires_at * 1_000 - Date.now() - 5_000);
    const timer = window.setTimeout(() => {
      if (managementSession()?.access_token !== session.access_token) return;
      clearManagementAuthorization("Agent-management authorization expired. Sign again to manage keys; same-wallet device keys remain in this tab.");
    }, delay);
    onCleanup(() => window.clearTimeout(timer));
  });

  onCleanup(() => {
    disposed = true;
    ++loadGeneration;
    mutationGuard.dispose();
    setManagementSession(undefined);
    clearOneTimeSecret();
  });

  function clearOneTimeSecret(): void {
    setDialogOpen(false);
    setOneTimeToken("");
    setOneTimeCredential(undefined);
    setRevealToken(false);
    setCopied("");
    setCopyError("");
  }

  function closeDialog(): void {
    if (busy()) return;
    clearOneTimeSecret();
  }

  useModalFocus(dialogOpen, () => dialogRef, closeDialog);

  const authorizeManagement = async (): Promise<void> => {
    const owner = props.walletAddress;
    if (!owner || !props.challengeId || !props.challengeVersion) return;
    const version = props.walletAuthorizationVersion;
    const challengeId = props.challengeId;
    const challengeVersion = props.challengeVersion;
    setAuthorizationState("authorizing");
    setError("");
    try {
      const session = await props.authorizeManagement();
      if (
        disposed
        || props.walletAddress?.toLowerCase() !== owner.toLowerCase()
        || props.walletAuthorizationVersion !== version
        || props.challengeId !== challengeId
        || props.challengeVersion !== challengeVersion
        || !sessionMatchesIdentity(session)
      ) return;
      setManagementSession(session);
      setAuthorizationState("ready");
      await load(session.access_token);
    } catch (cause) {
      if (
        disposed
        || props.walletAddress?.toLowerCase() !== owner.toLowerCase()
        || props.walletAuthorizationVersion !== version
        || props.challengeId !== challengeId
        || props.challengeVersion !== challengeVersion
      ) return;
      setAuthorizationState("error");
      setError(cause instanceof Error ? cause.message : "Arena agent management authorization failed");
    }
  };

  const openIssue = (): void => {
    setOneTimeToken("");
    setOneTimeCredential(undefined);
    setRevealToken(false);
    setCopied("");
    setCopyError("");
    setError("");
    setDialogOpen(true);
  };

  const issue = async (): Promise<void> => {
    const token = managementSession()?.access_token;
    const owner = props.walletAddress;
    if (!token || !owner) return;
    const context = mutationContext(token, owner);
    setBusy("issue");
    setError("");
    setNotice("");
    try {
      const key = await generateArenaAgentDeviceKey();
      assertCurrentMutation(context);
      const delivery = await issueArenaAgentCredential(
        token,
        context.challengeId,
        context.challengeVersion,
        {
          deviceLabel: name().trim(),
          deviceKind: deviceKind(),
          publicKey: key.publicKeyHex,
          name: name().trim(),
          expiresInSeconds: Math.max(1, Math.min(24, Number(ttlHours()))) * 3_600,
          dailySubmissionCap: Math.max(1, Math.min(32, Number(dailyCap()))),
        },
        context.lease.signal,
      );
      assertCurrentMutation(context);
      const plaintext = await decryptArenaAgentCredentialCapsule(delivery, key, owner);
      assertCurrentMutation(context);
      deviceKeys.set(delivery.credential.device_id, key);
      setOneTimeCredential(delivery.credential);
      setOneTimeToken(plaintext);
      setRevealToken(true);
      setNotice("Agent credential issued. Its plaintext exists only in this tab and is shown once.");
      await load(token);
    } catch (cause) {
      if (!mutationIsCurrent(context) || (cause instanceof Error && cause.name === "AbortError")) return;
      if (cause instanceof ArenaAgentRequestError && cause.status === 401) {
        clearManagementAuthorization("Agent-management authorization expired. Sign again, then refresh and revoke any unexpected active credential.");
        return;
      }
      setError(mutationFailedText(cause, "Arena agent credential issuance failed"));
    } finally {
      if (mutationGuard.finish(context.lease) && !disposed) setBusy("");
    }
  };

  const rotate = async (credential: ArenaAgentCredential): Promise<void> => {
    const token = managementSession()?.access_token;
    const owner = props.walletAddress;
    const key = deviceKeys.get(credential.device_id);
    if (!token || !owner || !key) {
      setError("This tab does not hold that device key. Issue a new credential instead of exporting or recovering private key material.");
      return;
    }
    const context = mutationContext(token, owner);
    setBusy(`rotate:${credential.credential_id}`);
    setError("");
    try {
      const delivery = await rotateArenaAgentCredential(token, credential, 6 * 3_600, context.lease.signal);
      assertCurrentMutation(context);
      const plaintext = await decryptArenaAgentCredentialCapsule(delivery, key, owner);
      assertCurrentMutation(context);
      setOneTimeCredential(delivery.credential);
      setOneTimeToken(plaintext);
      setRevealToken(true);
      setCopied("");
      setCopyError("");
      setDialogOpen(true);
      setNotice("Prior generation revoked. Copy the rotated token once.");
      await load(token);
    } catch (cause) {
      if (!mutationIsCurrent(context) || (cause instanceof Error && cause.name === "AbortError")) return;
      if (cause instanceof ArenaAgentRequestError && cause.status === 401) {
        clearManagementAuthorization("Agent-management authorization expired. Sign again, then refresh before retrying rotation.");
        return;
      }
      setError(mutationFailedText(cause, "Arena agent credential rotation failed"));
    } finally {
      if (mutationGuard.finish(context.lease) && !disposed) setBusy("");
    }
  };

  const revoke = async (credential: ArenaAgentCredential): Promise<void> => {
    const token = managementSession()?.access_token;
    const owner = props.walletAddress;
    if (!token || !owner) return;
    const context = mutationContext(token, owner);
    setBusy(`revoke:${credential.credential_id}`);
    setError("");
    try {
      await revokeArenaAgentCredential(token, credential, context.lease.signal);
      assertCurrentMutation(context);
      deviceKeys.delete(credential.device_id);
      setNotice(`${credential.name} was revoked for ${credential.challenge_id} ${credential.challenge_version}.`);
      await load(token);
    } catch (cause) {
      if (!mutationIsCurrent(context) || (cause instanceof Error && cause.name === "AbortError")) return;
      if (cause instanceof ArenaAgentRequestError && cause.status === 401) {
        clearManagementAuthorization("Agent-management authorization expired. Sign again, then refresh before retrying revocation.");
        return;
      }
      setError(mutationFailedText(cause, "Arena agent credential revocation failed"));
    } finally {
      if (mutationGuard.finish(context.lease) && !disposed) setBusy("");
    }
  };

  const copy = async (kind: "token" | "example"): Promise<void> => {
    const value = kind === "token"
      ? oneTimeToken()
      : example() === "curl"
        ? arenaAgentCurlQuickstart(props.challengeId, props.challengeVersion)
        : arenaAgentPythonQuickstart(props.challengeId, props.challengeVersion);
    if (!value) return;
    setCopyError("");
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard API unavailable");
      await navigator.clipboard.writeText(value);
      setCopied(kind);
      window.setTimeout(() => setCopied(""), 1_400);
    } catch {
      setCopied("");
      setCopyError("Clipboard access was blocked. Select the visible token or focused code example and copy it manually.");
    }
  };

  const selectExampleFromKeyboard = (event: KeyboardEvent, current: "curl" | "python"): void => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === "Home"
      ? "curl"
      : event.key === "End"
        ? "python"
        : current === "curl" ? "python" : "curl";
    setExample(next);
    document.getElementById(`arena-agent-example-tab-${next}`)?.focus();
  };

  const quickstart = () => example() === "curl"
    ? arenaAgentCurlQuickstart(props.challengeId, props.challengeVersion)
    : arenaAgentPythonQuickstart(props.challengeId, props.challengeVersion);

  return (
    <section class="arena-agent-access" aria-labelledby="arena-agent-access-title">
      <header class="arena-agent-access-head">
        <div class="arena-agent-mark"><Bot size={20} /></div>
        <div>
          <p class="overline">Agent access · exact challenge version</p>
          <h4 id="arena-agent-access-title">Enroll a TTT or autonomous competitor</h4>
          <p>Issue a short-lived device credential for only <code>{props.challengeId}@{props.challengeVersion}</code>. It can submit ciphertext and read this wallet’s bounded results; it cannot use Compute, Deal, Tinker, contract, or payment routes.</p>
        </div>
        <span class="agent-modeled-pill"><TriangleAlert size={12} /> MODELED AUTH</span>
      </header>

      <div class="agent-truth-banner">
        <ShieldCheck size={16} />
        <span><strong>{props.releaseBoundWorker ? "Release-bound worker presence observed; agent credential is still authentication only" : "Modeled agent control plane · execution not connected"}</strong> No credential is Intel TDX evidence, job authorization, a reward promise, or proof that an evaluator ran. The local HMAC store detects tampering but is not rollback protection.</span>
      </div>

      <Show when={notice()}><div class="agent-inline-notice success" role="status"><Check size={14} /> {notice()}</div></Show>
      <Show when={error()}><div class="agent-inline-notice error" role="alert"><TriangleAlert size={14} /> {error()}</div></Show>

      <Show when={managementSession()} fallback={
        <div class="agent-locked">
          {authorizationState() === "authorizing" ? <LoaderCircle class="spin" size={21} /> : <Fingerprint size={21} />}
          <div>
            <strong>Separate agent-management consent required</strong>
            <span>Sign the exact <code>challenge:agents:manage</code> request for <code>{props.challengeId}@{props.challengeVersion}</code>. This short session can issue, list, rotate, or revoke a submit + owner-read bearer lasting up to 24 hours; it cannot submit candidates itself and never requests a transaction or private key.</span>
          </div>
          <button class="primary-button" type="button" onClick={() => void authorizeManagement()} disabled={authorizationState() === "authorizing"}>
            {authorizationState() === "authorizing" ? <LoaderCircle class="spin" size={14} /> : <ShieldCheck size={14} />}
            {authorizationState() === "authorizing" ? "Waiting for signature…" : "Sign to manage agent keys"}
          </button>
        </div>
      }>
        <div class="agent-access-toolbar">
          <div><span>{credentials().length}</span><small>challenge-scoped credentials</small></div>
          <button class="secondary-button" type="button" onClick={() => void load()} disabled={state() === "loading" || Boolean(busy())}><RefreshCw class={state() === "loading" ? "spin" : ""} size={14} /> Refresh</button>
          <button class="primary-button" type="button" onClick={openIssue} disabled={Boolean(busy())}><Plus size={14} /> New agent key</button>
        </div>

        <Show when={state() === "loading" && credentials().length === 0}><div class="agent-loading"><LoaderCircle class="spin" size={17} /> Loading bounded credential records…</div></Show>
        <div class="agent-credential-grid">
          <For each={credentials()}>{(credential) => {
            const rotationReason = () => rotateUnavailableReason(credential, deviceKeys.has(credential.device_id));
            const rotationReasonId = `arena-agent-rotate-reason-${credential.credential_id.replace(/[^a-zA-Z0-9_-]/g, "-")}`;
            return <article class="agent-credential-card">
              <div class="agent-credential-title"><KeyRound size={16} /><span><strong>{credential.name}</strong><code>{credential.prefix}</code></span><em>{credential.status}</em></div>
              <dl>
                <div><dt>Binding</dt><dd>{credential.challenge_id}@{credential.challenge_version}</dd></div>
                <div><dt>Generation</dt><dd>{credential.generation}</dd></div>
                <div><dt>Attempt cap</dt><dd>{credential.submission_attempts_used_today}/{credential.daily_submission_cap} today</dd></div>
                <div><dt>Expires</dt><dd>{expiryLabel(credential.expires_at)}</dd></div>
                <div><dt>Last used</dt><dd>{usedLabel(credential.last_used_at)}</dd></div>
              </dl>
              <div class="agent-scope-list"><For each={credential.scopes}>{(scope) => <span><Braces size={11} /> {scope}</span>}</For></div>
              <Show when={rotationReason()}>
                <p id={rotationReasonId} class="agent-rotate-reason"><TriangleAlert size={12} /> {rotationReason()}</p>
              </Show>
              <div class="agent-card-actions">
                <button type="button" onClick={() => void rotate(credential)} disabled={Boolean(rotationReason()) || Boolean(busy())} aria-describedby={rotationReason() ? rotationReasonId : undefined} title={rotationReason() || "Rotate in this tab"}><RotateCcw size={13} /> Rotate</button>
                <button type="button" onClick={() => void revoke(credential)} disabled={credential.status !== "active" || Boolean(busy())}><Ban size={13} /> Revoke</button>
              </div>
            </article>;
          }}</For>
        </div>
        <Show when={state() === "ready" && credentials().length === 0}><div class="agent-empty"><Bot size={21} /><strong>No agent keys for this version</strong><span>Create one without exporting the browser-generated device private key.</span></div></Show>
      </Show>

      <Show when={dialogOpen()}>
        <div class="dialog-backdrop" onClick={closeDialog}>
          <section ref={(element) => { dialogRef = element; }} class="credential-dialog arena-agent-dialog" role="dialog" aria-modal="true" aria-labelledby="arena-agent-dialog-title" tabindex="-1" onClick={(event) => event.stopPropagation()}>
            <button class="dialog-x" type="button" aria-label="Close agent credential dialog" data-autofocus onClick={closeDialog} disabled={Boolean(busy())}><X size={17} /></button>
            <div class="dialog-mark"><Bot size={22} /></div>
            <p class="overline">MODELED AGENT ACCESS · NO TDX CLAIM</p>
            <h2 id="arena-agent-dialog-title">{oneTimeToken() ? "Copy this agent credential once" : "Enroll an Arena agent"}</h2>
            <Show when={oneTimeToken()} fallback={
              <>
                <p>The browser generates a non-exportable X25519 device key. The service returns the agent token only inside an encrypted capsule for that key. X25519 protects this one delivery only: after decryption, the JWT is an ordinary bearer that anyone who copies it can use until expiry or revocation. It is not per-request proof-of-possession or device attestation.</p>
                <div class="form-grid two">
                  <label><span>Agent + device name</span><input maxlength="64" value={name()} onInput={(event) => setName(event.currentTarget.value)} /></label>
                  <label><span>Device kind</span><select value={deviceKind()} onChange={(event) => setDeviceKind(event.currentTarget.value as ArenaAgentDeviceKind)}><option value="autonomous_agent">Autonomous agent</option><option value="ci_service">CI service</option><option value="developer_device">Developer device</option></select></label>
                </div>
                <div class="form-grid two">
                  <label><span>Expires after</span><select value={ttlHours()} onChange={(event) => setTtlHours(event.currentTarget.value)}><option value="1">1 hour</option><option value="6">6 hours</option><option value="24">24 hours</option></select></label>
                  <label><span>Daily submission-attempt cap</span><input type="number" min="1" max="32" value={dailyCap()} onInput={(event) => setDailyCap(event.currentTarget.value)} /></label>
                </div>
                <fieldset class="scope-picker"><legend>Fixed Arena scopes</legend><For each={ARENA_AGENT_SCOPES}>{(scope) => <label><input type="checkbox" checked disabled /><span><Braces size={13} /> {scope}</span></label>}</For></fieldset>
                <button class="primary-button large full" type="button" onClick={() => void issue()} disabled={!name().trim() || Number(dailyCap()) < 1 || Number(dailyCap()) > 32 || Boolean(busy())}>{busy() === "issue" ? <LoaderCircle class="spin" size={16} /> : <Fingerprint size={16} />} Generate device and issue</button>
                <p class="modeled-note"><TriangleAlert size={13} /> This authorizes API calls only. Every submission still needs the independent registry, ingress, execution-policy, worker, and per-job evidence gates.</p>
              </>
            }>
              <p>The token was decrypted in this tab. Store it in a secret manager or process environment, then close this dialog to clear the plaintext view. If a request loses its response, refresh the wallet-owned list and revoke any credential you cannot account for.</p>
              <div class="one-time-secret live-token"><button type="button" aria-label={revealToken() ? "Hide one-time Arena agent credential" : "Reveal one-time Arena agent credential"} onClick={() => setRevealToken(!revealToken())}>{revealToken() ? <EyeOff size={15} /> : <Eye size={15} />}</button><div><small>ONE-TIME DEVICE-DECRYPTED TOKEN</small><code>{revealToken() ? oneTimeToken() : "••••••••••••••••••••••••••••••"}</code></div><button type="button" aria-label="Copy Arena agent credential" aria-describedby={copyError() ? "arena-agent-copy-error" : undefined} onClick={() => void copy("token")}><Copy size={15} /></button></div>
              <div class="agent-token-binding"><Fingerprint size={14} /><span><strong>{oneTimeCredential()?.name}</strong><code>{oneTimeCredential()?.challenge_id}@{oneTimeCredential()?.challenge_version} · generation {oneTimeCredential()?.generation}</code></span><em>{copied() === "token" ? "Copied" : "Not stored by Wikigen"}</em></div>
              <div class="agent-example-toolbar">
                <div class="agent-example-tabs" role="tablist" aria-label="Agent request examples">
                  <button id="arena-agent-example-tab-curl" type="button" class={example() === "curl" ? "active" : ""} role="tab" aria-selected={example() === "curl"} aria-controls="arena-agent-example-panel" tabindex={example() === "curl" ? 0 : -1} onClick={() => setExample("curl")} onKeyDown={(event) => selectExampleFromKeyboard(event, "curl")}><TerminalSquare size={13} /> curl</button>
                  <button id="arena-agent-example-tab-python" type="button" class={example() === "python" ? "active" : ""} role="tab" aria-selected={example() === "python"} aria-controls="arena-agent-example-panel" tabindex={example() === "python" ? 0 : -1} onClick={() => setExample("python")} onKeyDown={(event) => selectExampleFromKeyboard(event, "python")}><Braces size={13} /> Python</button>
                </div>
                <button class="agent-example-copy" type="button" aria-label={`Copy ${example()} agent request example`} aria-describedby={copyError() ? "arena-agent-copy-error" : undefined} onClick={() => void copy("example")}><Copy size={13} /> {copied() === "example" ? "Copied" : "Copy"}</button>
              </div>
              <pre id="arena-agent-example-panel" class="agent-quickstart" role="tabpanel" aria-labelledby={`arena-agent-example-tab-${example()}`} tabindex="0"><code>{quickstart()}</code></pre>
              <Show when={copyError()}><p id="arena-agent-copy-error" class="agent-copy-error" role="alert" aria-live="assertive"><TriangleAlert size={13} /> {copyError()}</p></Show>
              <p class="modeled-note"><ShieldCheck size={13} /> Examples read the token from <code>WIKIGEN_ARENA_TOKEN</code>; they never paste it into source. This copied JWT is a bearer, not proof-of-possession or device attestation. The submission example accepts only the existing ciphertext envelope schema.</p>
              <button class="primary-button large full" type="button" onClick={closeDialog}><Check size={16} /> I stored it safely; clear this view</button>
            </Show>
          </section>
        </div>
      </Show>
    </section>
  );
}

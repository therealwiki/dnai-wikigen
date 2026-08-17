import { createEffect, createSignal, For, onCleanup, Show, type JSX } from "solid-js";
import {
  Activity,
  Beaker,
  BookOpen,
  ChevronDown,
  CircleDollarSign,
  ClipboardCheck,
  CloudCog,
  Database,
  ExternalLink,
  Fingerprint,
  Handshake,
  HeartPulse,
  KeyRound,
  LockKeyhole,
  Menu,
  Network,
  ShieldCheck,
  WalletCards,
  X,
} from "lucide-solid";
import { BASE_SEPOLIA, deployment, explorerAddress } from "../config";
import { formatEth, shortAddress } from "../lib/contract";
import { wallet, type WalletOption } from "../lib/wallet";

export type RouteKey = "overview" | "health" | "arena" | "deals" | "review" | "vaults" | "compute" | "tinker" | "lab" | "catalog" | "verify" | "collaborate" | "not_found";

interface AppShellProps {
  route: RouteKey;
  navigate: (route: RouteKey) => void;
  children: JSX.Element;
  walletDialogOpen?: boolean;
  onWalletDialogOpenChange?: (open: boolean) => void;
}

const NAV_ITEMS: { route: RouteKey; label: string; icon: typeof Activity }[] = [
  { route: "overview", label: "Overview", icon: Activity },
  { route: "health", label: "Health guide", icon: HeartPulse },
  { route: "arena", label: "Challenge arena", icon: Beaker },
  { route: "deals", label: "Deal room", icon: CircleDollarSign },
  { route: "review", label: "Review", icon: ClipboardCheck },
  { route: "vaults", label: "Data vaults", icon: Database },
  { route: "compute", label: "Compute", icon: CloudCog },
  { route: "tinker", label: "Tinker", icon: KeyRound },
  { route: "lab", label: "Safeguards", icon: BookOpen },
  { route: "catalog", label: "Catalog", icon: Network },
  { route: "verify", label: "Verify", icon: ShieldCheck },
  { route: "collaborate", label: "Collaborate", icon: Handshake },
];

function walletIcon(option: WalletOption): JSX.Element {
  const icon = option.info.icon;
  const safeRasterIcon = icon.length <= 96 * 1024
    && /^data:image\/(?:png|jpeg|webp|gif);base64,[A-Za-z0-9+/]+={0,2}$/.test(icon);
  return safeRasterIcon ? (
    <img src={icon} alt="" class="wallet-option-icon" referrerpolicy="no-referrer" />
  ) : (
    <WalletCards size={19} aria-hidden="true" />
  );
}

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

function focusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    (element) => !element.hasAttribute("hidden") && element.getAttribute("aria-hidden") !== "true" && element.getClientRects().length > 0,
  );
}

export function useModalFocus(
  isOpen: () => boolean,
  container: () => HTMLElement | undefined,
  close: () => void,
): void {
  createEffect(() => {
    if (!isOpen()) return;

    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const handleKeydown = (event: KeyboardEvent): void => {
      if (event.key === "Escape") {
        event.preventDefault();
        close();
        return;
      }
      if (event.key !== "Tab") return;

      const modal = container();
      if (!modal) return;
      const focusable = focusableElements(modal);
      if (focusable.length === 0) {
        event.preventDefault();
        modal.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!(document.activeElement instanceof Node) || !modal.contains(document.activeElement)) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
        return;
      }
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", handleKeydown);
    queueMicrotask(() => {
      const modal = container();
      const focusable = modal ? focusableElements(modal) : [];
      const requested = modal?.querySelector<HTMLElement>("[data-autofocus]");
      const initial = requested && focusable.includes(requested) ? requested : focusable[0];
      (initial ?? modal)?.focus();
    });

    onCleanup(() => {
      document.removeEventListener("keydown", handleKeydown);
      document.body.style.overflow = previousOverflow;
      queueMicrotask(() => {
        if (previouslyFocused?.isConnected) previouslyFocused.focus();
      });
    });
  });
}

function WalletDialog(props: { open: boolean; close: () => void }) {
  const [busyProvider, setBusyProvider] = createSignal<WalletOption["provider"]>();
  let dialogRef: HTMLElement | undefined;

  useModalFocus(() => props.open, () => dialogRef, props.close);

  const connect = async (option: WalletOption) => {
    setBusyProvider(option.provider);
    try {
      await wallet.connect(option);
      props.close();
    } catch {
      // The store exposes a bounded, user-facing error message.
    } finally {
      setBusyProvider(undefined);
    }
  };

  const connectWalletConnect = async () => {
    setBusyProvider(undefined);
    try {
      await wallet.connectWalletConnect();
      props.close();
    } catch {
      // The store exposes a bounded, user-facing error message.
    } finally {
      setBusyProvider(undefined);
    }
  };

  return (
    <Show when={props.open}>
      <div class="dialog-backdrop" role="presentation" onClick={props.close}>
        <section
          ref={(element) => { dialogRef = element; }}
          id="wallet-connection-dialog"
          class="wallet-dialog"
          role="dialog"
          aria-modal="true"
          aria-labelledby="wallet-dialog-title"
          aria-describedby="wallet-dialog-description"
          aria-busy={wallet.connecting()}
          tabindex="-1"
          onClick={(event) => event.stopPropagation()}
        >
          <button class="icon-button dialog-close" type="button" aria-label="Close wallet dialog" data-autofocus onClick={props.close}>
            <X size={18} />
          </button>
          <div class="dialog-mark"><Fingerprint size={23} /></div>
          <p class="overline">Wallet connection</p>
          <h2 id="wallet-dialog-title">Connect a wallet</h2>
          <p id="wallet-dialog-description" class="dialog-copy">
            Choose an EIP-6963 provider or the injected fallback. Connecting shares only the wallet-selected address and active network; it does not switch networks, sign a message, submit a transaction, or give Wikigen custody.
          </p>

          <div class="wallet-options" role="group" aria-label="Discovered wallet providers">
            <For each={wallet.options()}>
              {(option) => (
                <button
                  class={`wallet-option ${option.metadataWarning ? "metadata-warning" : ""}`}
                  type="button"
                  aria-label={`Connect ${option.info.name}. ${option.source === "eip6963" ? `Provider reports ${option.info.rdns}.` : "Legacy injected fallback; identity unverified."}${option.metadataWarning ? " Conflicting provider metadata detected; verify the wallet prompt." : ""}`}
                  onClick={() => void connect(option)}
                  disabled={wallet.connecting()}
                >
                  {walletIcon(option)}
                  <span class="wallet-option-copy">
                    <strong>{option.info.name}</strong>
                    <small>{option.source === "eip6963" ? `${option.info.rdns} · self-reported EIP-6963` : "Legacy injected fallback · identity unverified"}</small>
                    <Show when={option.metadataWarning}>
                      <small class="wallet-option-warning">Metadata collision · verify the wallet prompt</small>
                    </Show>
                  </span>
                  <span class="wallet-option-action">{busyProvider() === option.provider ? "Opening…" : "Connect"}</span>
                </button>
              )}
            </For>

            <Show
              when={deployment.walletConnectProjectId}
              fallback={(
                <button
                  class="wallet-option wallet-option-unavailable"
                  type="button"
                  aria-label="WalletConnect is unavailable because this deployment has no configured connector"
                  disabled
                >
                  <Network size={19} aria-hidden="true" />
                  <span class="wallet-option-copy">
                    <strong>WalletConnect</strong>
                    <small>Mobile and desktop wallets · connector not configured</small>
                  </span>
                  <span class="wallet-option-action">Unavailable</span>
                </button>
              )}
            >
              <button
                class="wallet-option"
                type="button"
                aria-label="Connect with WalletConnect using a QR code"
                onClick={() => void connectWalletConnect()}
                disabled={wallet.connecting()}
              >
                <Network size={19} aria-hidden="true" />
                <span class="wallet-option-copy">
                  <strong>WalletConnect</strong>
                  <small>Configured connector · mobile and desktop wallets</small>
                </span>
                <span class="wallet-option-action">{wallet.connecting() && !busyProvider() ? "Opening…" : "QR code"}</span>
              </button>
            </Show>
          </div>

          <Show when={wallet.options().length === 0}>
            <div class="empty-wallets" role="status" aria-live="polite">
              <WalletCards size={20} />
              <p>{wallet.discovering()
                ? "Checking for EIP-6963 wallet announcements…"
                : deployment.walletConnectProjectId
                  ? "No injected wallet was detected. You can use the configured WalletConnect option above."
                  : "No compatible injected wallet was detected. Install MetaMask, Coinbase Wallet, Rabby, or another EIP-1193 wallet, or ask this deployment's operator to configure WalletConnect."}</p>
            </div>
          </Show>

          <Show when={wallet.error()}>
            <p class="form-error" role="alert" aria-live="assertive">{wallet.error()}</p>
          </Show>

          <div class="wallet-capability-note">
            <ShieldCheck size={17} aria-hidden="true" />
            <p><strong>EOA + smart-account login.</strong> Artifact upload, Arena, Compute, and Collaboration nonce exchanges support EOA <code>personal_sign</code> and deployment-configured EIP-1271 verification on Base Sepolia. Connection alone does not prove account type; without the trusted server RPC, those exchanges remain EOA-only and fail closed. Execution-policy approvals still require an allowlisted recoverable EOA signature.</p>
          </div>
          <p class="wallet-storage-note">Wikigen’s wallet layer does not write private keys, signatures, or short-lived service tokens to browser storage. It never asks for a private key. A configured connector may manage its own pairing or wallet session.</p>
          <p class="dialog-footnote">Base Sepolia · chain ID {BASE_SEPOLIA.id} · testnet funds only</p>
        </section>
      </div>
    </Show>
  );
}

function AccountMenu(props: { disconnect: () => void }) {
  const [open, setOpen] = createSignal(false);
  let wrapRef: HTMLDivElement | undefined;
  let buttonRef: HTMLButtonElement | undefined;

  createEffect(() => {
    if (!open()) return;
    const handlePointerDown = (event: PointerEvent): void => {
      if (event.target instanceof Node && !wrapRef?.contains(event.target)) setOpen(false);
    };
    const handleKeydown = (event: KeyboardEvent): void => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      setOpen(false);
      buttonRef?.focus();
    };
    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeydown);
    onCleanup(() => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeydown);
    });
  });

  return (
    <div ref={(element) => { wrapRef = element; }} class="account-wrap">
      <button
        ref={(element) => { buttonRef = element; }}
        class="account-button"
        type="button"
        aria-label={`Wallet account ${shortAddress(wallet.account() ?? "")}, connected with ${wallet.connectedName()}, ${wallet.isCorrectChain() ? "Base Sepolia" : "wrong network"}. Open account actions.`}
        aria-expanded={open()}
        aria-controls="account-menu-panel"
        aria-haspopup="true"
        onClick={() => setOpen(!open())}
        onKeyDown={(event) => {
          if (event.key !== "ArrowDown") return;
          event.preventDefault();
          setOpen(true);
          queueMicrotask(() => wrapRef?.querySelector<HTMLElement>("#account-menu-panel a, #account-menu-panel button")?.focus());
        }}
      >
        <span class={`network-dot ${wallet.isCorrectChain() ? "online" : "warning"}`} />
        <span class="account-label">
          <strong>{shortAddress(wallet.account() ?? "")}</strong>
          <small>{wallet.connectedName()} · {wallet.connectedSource() === "eip6963" ? "extension-reported" : wallet.connectedSource() === "injected" ? "injected fallback" : "WalletConnect"}</small>
        </span>
        <ChevronDown size={15} />
      </button>
      <Show when={open()}>
        <div id="account-menu-panel" class="account-menu" role="region" aria-label="Wallet account actions">
          <div class="account-menu-head">
            <small>Base Sepolia balance</small>
            <strong>{formatEth(wallet.balance())}</strong>
          </div>
          <Show when={!wallet.isCorrectChain()}>
            <button type="button" onClick={() => void wallet.switchToBase().catch(() => undefined)} disabled={wallet.switchingChain()}>
              <Network size={15} /> {wallet.switchingChain() ? "Confirm in wallet…" : "Switch to Base Sepolia"}
            </button>
          </Show>
          <Show when={wallet.error()}><p class="form-error account-error" role="alert" aria-live="assertive">{wallet.error()}</p></Show>
          <div class="signed-session"><ShieldCheck size={15} /> {wallet.sessionProof() ? `Authorized · ${wallet.sessionProof()}` : "Connected · service authorization is requested per action"}</div>
          <a href={explorerAddress(wallet.account() ?? "")} target="_blank" rel="noreferrer">
            <ExternalLink size={15} /> View on BaseScan
          </a>
          <button type="button" onClick={() => { setOpen(false); props.disconnect(); }}><X size={15} /> Disconnect</button>
        </div>
      </Show>
    </div>
  );
}

export function AppShell(props: AppShellProps) {
  const [mobileOpen, setMobileOpen] = createSignal(false);
  const [internalWalletOpen, setInternalWalletOpen] = createSignal(false);
  let mobileDrawerRef: HTMLElement | undefined;

  const walletOpen = () => props.walletDialogOpen ?? internalWalletOpen();
  const setWalletOpen = (open: boolean): void => {
    if (props.walletDialogOpen === undefined) setInternalWalletOpen(open);
    props.onWalletDialogOpenChange?.(open);
  };

  useModalFocus(() => mobileOpen(), () => mobileDrawerRef, () => setMobileOpen(false));

  const skipToContent = (): void => {
    const main = document.getElementById("page-content");
    main?.focus();
    main?.scrollIntoView({ block: "start" });
  };

  return (
    <div class="app-shell">
      <button class="skip-link" type="button" onClick={skipToContent}>Skip to content</button>
      <header class="topbar">
        <button class="brand" type="button" onClick={() => props.navigate("overview")} aria-label="Wikigen home">
          <span class="brand-glyph" aria-hidden="true"><LockKeyhole size={17} /></span>
          <span class="brand-word">wiki<span>gen</span></span>
          <span class="brand-beta">BETA</span>
        </button>

        <nav class="desktop-nav" aria-label="Primary navigation">
          <For each={NAV_ITEMS}>
            {(item) => (
              <button
                type="button"
                class={props.route === item.route ? "active" : ""}
                aria-current={props.route === item.route ? "page" : undefined}
                onClick={() => props.navigate(item.route)}
              >
                {item.label}
              </button>
            )}
          </For>
        </nav>

        <div class="topbar-actions">
          <div class="chain-pill" title="Required wallet network">
            <span class={`network-dot ${wallet.account() ? wallet.isCorrectChain() ? "online" : "warning" : ""}`} /> {wallet.account() ? wallet.isCorrectChain() ? "Base Sepolia" : "Wrong network" : "Required: Base Sepolia"}
          </div>
          <Show
            when={wallet.account()}
            fallback={
              <button class="primary-button compact" type="button" aria-haspopup="dialog" aria-controls="wallet-connection-dialog" onClick={() => setWalletOpen(true)}>
                <WalletCards size={16} /> Connect wallet
              </button>
            }
          >
            <AccountMenu disconnect={wallet.disconnect} />
          </Show>
          <button class="icon-button mobile-menu-button" type="button" aria-label="Open menu" aria-expanded={mobileOpen()} aria-controls="mobile-navigation-dialog" onClick={() => setMobileOpen(true)}>
            <Menu size={20} />
          </button>
        </div>
      </header>

      <Show when={mobileOpen()}>
        <div class="mobile-drawer-backdrop" role="presentation" onClick={() => setMobileOpen(false)}>
          <nav
            ref={(element) => { mobileDrawerRef = element; }}
            id="mobile-navigation-dialog"
            class="mobile-drawer"
            role="dialog"
            aria-modal="true"
            aria-labelledby="mobile-menu-title"
            tabindex="-1"
            onClick={(event) => event.stopPropagation()}
          >
            <div class="mobile-drawer-head">
              <span id="mobile-menu-title" class="brand-word">wiki<span>gen</span></span>
              <button class="icon-button" type="button" aria-label="Close menu" data-autofocus onClick={() => setMobileOpen(false)}><X size={19} /></button>
            </div>
            <For each={NAV_ITEMS}>
              {(item) => {
                const Icon = item.icon;
                return (
                  <button
                    type="button"
                    class={props.route === item.route ? "active" : ""}
                    aria-current={props.route === item.route ? "page" : undefined}
                    onClick={() => { props.navigate(item.route); setMobileOpen(false); }}
                  >
                    <Icon size={18} /> {item.label}
                  </button>
                );
              }}
            </For>
          </nav>
        </div>
      </Show>

      <main id="page-content" class="page-content" tabindex="-1">{props.children}</main>

      <footer class="site-footer">
        <div>
          <span class="brand-word">wiki<span>gen</span></span>
          <p>Private intelligence. Verifiable outcomes.</p>
        </div>
        <div class="footer-trust">
          <span><ShieldCheck size={14} /> Bounded egress</span>
          <span><Network size={14} /> Base Sepolia</span>
          <span><LockKeyhole size={14} /> Phala TDX target</span>
        </div>
        <p class="footer-note">Experimental software on a test network. Never upload regulated or irreplaceable data until every verification layer passes.</p>
      </footer>

      <WalletDialog open={walletOpen()} close={() => setWalletOpen(false)} />
    </div>
  );
}

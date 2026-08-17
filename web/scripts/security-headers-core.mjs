import { URL as NodeURL } from "node:url";

import {
  exactDistinctPublicHttpsEndpoints,
  exactPublicHttpsEndpoint,
  exactPublicHttpsOrigin,
} from "./public-https-origin-core.mjs";

const BASE_SEPOLIA_RPC_ORIGIN = "https://sepolia.base.org";

// Keep this list pinned to the origins used by the checked-in
// @walletconnect/ethereum-provider and @reown/appkit versions. Wallet and chain
// images are fetched through the AppKit API and rendered from blob: URLs, so
// WalletConnect does not need to broaden img-src, font-src, or script-src.
const WALLETCONNECT_CONNECT_ORIGINS = [
  "https://api.web3modal.org",
  "https://echo.walletconnect.com",
  "https://pulse.walletconnect.org",
  "https://rpc.walletconnect.org",
  "https://verify.walletconnect.com",
  "https://verify.walletconnect.org",
  "wss://relay.walletconnect.org",
];

const WALLETCONNECT_FRAME_ORIGINS = [
  "https://secure.walletconnect.org",
  "https://verify.walletconnect.com",
  "https://verify.walletconnect.org",
];

export function exactDelegateOrigin(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    return exactPublicHttpsOrigin(raw, "delegate CSP value");
  } catch {
    throw new Error("delegate CSP value must be an exact public HTTPS origin");
  }
}

export function exactRpcEndpoints({
  primaryRpcUrl = BASE_SEPOLIA_RPC_ORIGIN,
  secondaryRpcUrl = "",
} = {}) {
  const primary = exactPublicHttpsEndpoint(primaryRpcUrl, "primary Base Sepolia RPC URL");
  if (!String(secondaryRpcUrl || "").trim()) {
    return Object.freeze({ primary, secondary: "" });
  }
  return exactDistinctPublicHttpsEndpoints(primary, secondaryRpcUrl, {
    primaryLabel: "primary Base Sepolia RPC URL",
    secondaryLabel: "secondary Base Sepolia RPC URL",
  });
}

export function renderProductionHeaders({
  delegateUrl = "",
  walletConnectEnabled = false,
  primaryRpcUrl = BASE_SEPOLIA_RPC_ORIGIN,
  secondaryRpcUrl = "",
} = {}) {
  const rpc = exactRpcEndpoints({ primaryRpcUrl, secondaryRpcUrl });
  const connect = ["'self'", new NodeURL(rpc.primary).origin];
  if (rpc.secondary) connect.push(new NodeURL(rpc.secondary).origin);
  const delegateOrigin = exactDelegateOrigin(delegateUrl);
  if (delegateOrigin && !connect.includes(delegateOrigin)) connect.push(delegateOrigin);
  if (walletConnectEnabled) {
    for (const origin of WALLETCONNECT_CONNECT_ORIGINS) {
      if (!connect.includes(origin)) connect.push(origin);
    }
  }
  const frame = walletConnectEnabled ? WALLETCONNECT_FRAME_ORIGINS.join(" ") : "'none'";
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    `connect-src ${connect.join(" ")}`,
    `frame-src ${frame}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self' mailto:",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests",
  ].join("; ");
  return [
    "/*",
    "  X-Content-Type-Options: nosniff",
    "  X-Frame-Options: DENY",
    "  Referrer-Policy: strict-origin-when-cross-origin",
    "  Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
    "  Cross-Origin-Opener-Policy: same-origin-allow-popups",
    `  Content-Security-Policy: ${csp}`,
    "",
    "/assets/*",
    "  Cache-Control: public, max-age=31536000, immutable",
    "",
  ].join("\n");
}

export function renderProductionHeadersForEnv(env = {}) {
  const requiresDelegate = [
    "VITE_ENABLE_ARTIFACT_UPLOAD",
    "VITE_ENABLE_COMPUTE_CONSOLE",
    "VITE_ENABLE_TINKER_CUSTOMER",
    "VITE_ENABLE_COLLABORATION",
    "VITE_ENABLE_ARENA_SUBMISSION",
    "VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD",
  ].some((key) => env[key] === "true");
  if (requiresDelegate && !String(env.VITE_DELEGATE_URL || "").trim()) {
    throw new Error("delegate-backed production feature enabled without VITE_DELEGATE_URL");
  }
  return renderProductionHeaders({
    delegateUrl: env.VITE_DELEGATE_URL,
    primaryRpcUrl: env.VITE_BASE_SEPOLIA_RPC_URL || BASE_SEPOLIA_RPC_ORIGIN,
    secondaryRpcUrl: env.VITE_BASE_SEPOLIA_SECONDARY_RPC_URL,
    walletConnectEnabled: Boolean(String(env.VITE_WALLETCONNECT_PROJECT_ID || "").trim()),
  });
}

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  exactDelegateOrigin,
  exactRpcEndpoints,
  renderProductionHeaders,
  renderProductionHeadersForEnv,
} from "./security-headers-core.mjs";

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("modeled build permits only self and canonical Base Sepolia connections", () => {
  const headers = renderProductionHeaders();
  assert.match(headers, /connect-src 'self' https:\/\/sepolia\.base\.org;/);
  assert.match(headers, /frame-src 'none';/);
  assert.doesNotMatch(headers, /connect-src[^\n]*\*/);
  assert.match(headers, /Permissions-Policy:.*payment=\(\)/);
});

test("live build adds exactly the configured delegate origin", () => {
  const headers = renderProductionHeaders({ delegateUrl: "https://delegate.release.wikigen.me/" });
  assert.match(
    headers,
    /connect-src 'self' https:\/\/sepolia\.base\.org https:\/\/delegate\.release\.wikigen\.me;/,
  );
  assert.equal(headers.match(/https:\/\/delegate\.release\.wikigen\.me/g)?.length, 1);
});

test("live CSP binds the exact validated primary and independent secondary RPC origins", () => {
  const env = {
    VITE_BASE_SEPOLIA_RPC_URL: "https://primary-rpc.wikigen.me/base-sepolia",
    VITE_BASE_SEPOLIA_SECONDARY_RPC_URL: "https://secondary-rpc.wikigen.net/rpc/base-sepolia",
  };
  assert.deepEqual(exactRpcEndpoints({
    primaryRpcUrl: env.VITE_BASE_SEPOLIA_RPC_URL,
    secondaryRpcUrl: env.VITE_BASE_SEPOLIA_SECONDARY_RPC_URL,
  }), {
    primary: env.VITE_BASE_SEPOLIA_RPC_URL,
    secondary: env.VITE_BASE_SEPOLIA_SECONDARY_RPC_URL,
  });
  const headers = renderProductionHeadersForEnv(env);
  assert.match(
    headers,
    /connect-src 'self' https:\/\/primary-rpc\.wikigen\.me https:\/\/secondary-rpc\.wikigen\.net;/,
  );
  assert.doesNotMatch(headers, /\/base-sepolia|\/rpc\/base-sepolia/);
});

test("RPC CSP endpoints reject credentials, query/fragment state, private hosts, and one-provider aliases", () => {
  const primaryRpcUrl = "https://primary-rpc.wikigen.me/base-sepolia";
  for (const secondaryRpcUrl of [
    "https://user:password@secondary-rpc.wikigen.net/rpc",
    "https://secondary-rpc.wikigen.net/rpc?api_key=public",
    "https://secondary-rpc.wikigen.net/rpc#provider",
    "https://127.0.0.1/rpc",
    "https://service.internal/rpc",
    "http://secondary-rpc.wikigen.net/rpc",
    "https://primary-rpc.wikigen.me/independent-in-name-only",
  ]) {
    assert.throws(
      () => renderProductionHeaders({ primaryRpcUrl, secondaryRpcUrl }),
      undefined,
      secondaryRpcUrl,
    );
  }
  for (const primary of [
    "https://user@primary-rpc.wikigen.me/rpc",
    "https://primary-rpc.wikigen.me/rpc?token=value",
    "https://localhost/rpc",
  ]) {
    assert.throws(() => renderProductionHeaders({ primaryRpcUrl: primary }), undefined, primary);
  }
});

test("WalletConnect adds only the exact origins required by the pinned provider", () => {
  const headers = renderProductionHeadersForEnv({
    VITE_WALLETCONNECT_PROJECT_ID: "0123456789abcdef0123456789abcdef",
  });
  assert.match(
    headers,
    /connect-src 'self' https:\/\/sepolia\.base\.org https:\/\/api\.web3modal\.org https:\/\/echo\.walletconnect\.com https:\/\/pulse\.walletconnect\.org https:\/\/rpc\.walletconnect\.org https:\/\/verify\.walletconnect\.com https:\/\/verify\.walletconnect\.org wss:\/\/relay\.walletconnect\.org;/,
  );
  assert.match(
    headers,
    /frame-src https:\/\/secure\.walletconnect\.org https:\/\/verify\.walletconnect\.com https:\/\/verify\.walletconnect\.org;/,
  );
  assert.match(headers, /script-src 'self';/);
  assert.match(headers, /img-src 'self' data: blob:;/);
  assert.match(headers, /font-src 'self' data:;/);
  assert.doesNotMatch(headers, /(?:connect|frame|img|font|script)-src[^\n]*\*/);
  assert.doesNotMatch(headers, /secure-mobile|coinbase|googleapis|gstatic/);
});

test("WalletConnect CSP review is pinned to the exact locked provider and AppKit versions", async () => {
  const lock = JSON.parse(await readFile(path.join(webDir, "package-lock.json"), "utf8"));
  assert.equal(
    lock.packages["node_modules/@walletconnect/ethereum-provider"].version,
    "2.23.10",
  );
  assert.equal(lock.packages["node_modules/@reown/appkit"].version, "1.8.19");
});

test("WalletConnect does not duplicate an origin used by the delegate", () => {
  const headers = renderProductionHeaders({
    delegateUrl: "https://api.web3modal.org",
    walletConnectEnabled: true,
  });
  assert.equal(headers.match(/https:\/\/api\.web3modal\.org/g)?.length, 1);
});

test("delegate CSP origin accepts only canonical public HTTPS hosts and exact ports", () => {
  assert.equal(
    exactDelegateOrigin("https://delegate.release.wikigen.me:443/"),
    "https://delegate.release.wikigen.me",
  );
  assert.equal(
    exactDelegateOrigin("https://delegate.release.wikigen.me:8443/"),
    "https://delegate.release.wikigen.me:8443",
  );
  assert.equal(exactDelegateOrigin("https://8.8.8.8/"), "https://8.8.8.8");
  assert.equal(
    exactDelegateOrigin("https://[2606:4700:4700::1111]/"),
    "https://[2606:4700:4700::1111]",
  );
});

test("delegate CSP origin rejects broadened, private, reserved, and ambiguous hosts", () => {
  for (const value of [
    "http://delegate.example.test",
    "https://*.example.test",
    "https://user:pass@delegate.example.test",
    "https://delegate.example.test/api",
    "https://delegate.example.test?next=evil",
    "https://localhost:8080",
    "https://localhost./",
    "https://service.local/",
    "https://service.internal/",
    "https://service.lan/",
    "https://service.home.arpa/",
    "https://service.onion/",
    "https://service.test/",
    "https://service.invalid/",
    "https://service.example/",
    "https://service.alt/",
    "https://delegate/",
    "https://delegate.release.wikigen.me./",
    "https://%6cocalhost/",
    "https://0.0.0.0/",
    "https://10.0.0.1/",
    "https://100.64.0.1/",
    "https://127.0.0.1/",
    "https://169.254.169.254/",
    "https://172.16.0.1/",
    "https://192.0.0.1/",
    "https://192.0.2.1/",
    "https://192.168.0.1/",
    "https://198.18.0.1/",
    "https://198.51.100.1/",
    "https://203.0.113.1/",
    "https://224.0.0.1/",
    "https://240.0.0.1/",
    "https://255.255.255.255/",
    "https://2130706433/",
    "https://0177.0.0.1/",
    "https://0x7f000001/",
    "https://[::]/",
    "https://[::1]/",
    "https://[::ffff:8.8.8.8]/",
    "https://[64:ff9b::808:808]/",
    "https://[100::1]/",
    "https://[2001:db8::1]/",
    "https://[2002:0808:0808::1]/",
    "https://[3fff::1]/",
    "https://[fc00::1]/",
    "https://[fe80::1]/",
    "https://[ff02::1]/",
    "https://[fe80::1%25en0]/",
  ]) {
    assert.throws(() => exactDelegateOrigin(value), undefined, value);
  }
});

test("delegate-backed feature flags cannot build without a CSP-bound endpoint", () => {
  for (const key of [
    "VITE_ENABLE_ARTIFACT_UPLOAD",
    "VITE_ENABLE_COMPUTE_CONSOLE",
    "VITE_ENABLE_ARENA_SUBMISSION",
    "VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD",
  ]) {
    assert.throws(
      () => renderProductionHeadersForEnv({ [key]: "true" }),
      /enabled without VITE_DELEGATE_URL/,
    );
  }
});

test("generated Pages header rules remain within Cloudflare's per-line limit", () => {
  const headers = renderProductionHeaders({
    delegateUrl: "https://delegate.release.wikigen.me",
    primaryRpcUrl: "https://primary-rpc.wikigen.me/base-sepolia",
    secondaryRpcUrl: "https://secondary-rpc.wikigen.net/base-sepolia",
    walletConnectEnabled: true,
  });
  for (const line of headers.split("\n")) {
    assert.ok(Buffer.byteLength(line, "utf8") <= 2_000, line.slice(0, 80));
  }
});

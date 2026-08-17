import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  open,
  readdir,
  realpath,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA =
  "dnai.cloudflare-external-build-closure.v1";
export const CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS =
  "exact_external_build_inputs";

const AGGREGATE_DOMAIN =
  "dnai.cloudflare-external-build-closure.aggregate.v1";
const RECEIPT_DOMAIN =
  "dnai.cloudflare-external-build-closure.receipt.v1";
const MUTABLE_PROJECTION_AUDIT_DOMAIN =
  "dnai.cloudflare-external-build-closure.mutable-projection-audit.v1";
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_WEB_CONSUMER_BYTES = 4 * 1024 * 1024;
const SHA256 = /^sha256:[0-9a-f]{64}$/;

const MODULE_ENTRYPOINT_PATHS = Object.freeze([
  "scripts/canonical-authority-graph.mjs",
  "scripts/compute-workload-activation-observation-core.mjs",
  "scripts/exact37-model-a-semantic-validator.mjs",
  "scripts/execution-policy-release-core-v3-historical.fixture.mjs",
  "scripts/execution-policy-release-core-v3-historical.mjs",
  "scripts/execution-policy-release-core.fixture.mjs",
  "scripts/execution-policy-release-core.mjs",
  "scripts/operator-policy-packet-core.mjs",
  "scripts/phala-seven-cvm-historical-transcript.mjs",
  "scripts/pre-ceremony-runtime-authority-core.mjs",
  "scripts/release-authority-current-c-v6-core.mjs",
  "scripts/release-authority-historical-core.mjs",
  "scripts/release-manifest-sigstore-verifier.mjs",
  "scripts/royalty-release-authority-core.mjs",
  "scripts/royalty-release-history-receipt-core.mjs",
]);

const MODULE_CLOSURE_PATHS = Object.freeze([
  "scripts/build-tee-image-release.mjs",
  "scripts/canonical-authority-graph.mjs",
  "scripts/canonical-public-https-url-core.mjs",
  "scripts/compute-workload-activation-observation-core.mjs",
  "scripts/cvm-descriptor-runtime-authority-core.mjs",
  "scripts/cvm-descriptor-runtime-authority-v1-policy.mjs",
  "scripts/cvm-descriptor-runtime-authority-v2-core.mjs",
  "scripts/cvm-descriptor-runtime-authority-v2.mjs",
  "scripts/cvm-launch-intent-core.mjs",
  "scripts/cvm-release-descriptor-set-constants.mjs",
  "scripts/cvm-release-descriptor-set-constants-v3.mjs",
  "scripts/cvm-release-descriptor-set-v3.mjs",
  "scripts/ethereum-keccak.mjs",
  "scripts/exact-model-a-dependency-graph.mjs",
  "scripts/exact37-model-a-semantic-validator.mjs",
  "scripts/execution-policy-release-core-v3-historical.fixture.mjs",
  "scripts/execution-policy-release-core-v3-historical.mjs",
  "scripts/execution-policy-release-core.fixture.mjs",
  "scripts/execution-policy-release-core.mjs",
  "scripts/frontend-build-candidate-receipt-core.mjs",
  "scripts/operator-policy-packet-core.mjs",
  "scripts/phala-bootstrap-public-environment-authority-core.mjs",
  "scripts/phala-executor-state-core.mjs",
  "scripts/phala-nonlive-bootstrap-authorization-core.mjs",
  "scripts/phala-nonlive-bootstrap-authorization.mjs",
  "scripts/phala-post-measurement-activation-core.mjs",
  "scripts/phala-post-measurement-activation-receipt-core.mjs",
  "scripts/phala-production-execution-policy.mjs",
  "scripts/phala-production-posture-core.mjs",
  "scripts/phala-production-posture-receipt.mjs",
  "scripts/phala-production-target-authority.mjs",
  "scripts/phala-seven-cvm-historical-evidence-core.mjs",
  "scripts/phala-seven-cvm-historical-release-verification-authority.mjs",
  "scripts/phala-seven-cvm-historical-runtime-binding-core.mjs",
  "scripts/phala-seven-cvm-historical-transcript.mjs",
  "scripts/phala-seven-cvm-launch-completion-core.mjs",
  "scripts/phala-seven-cvm-measurement-policy.mjs",
  "scripts/phala-seven-cvm-opened-fd-runtime-core.mjs",
  "scripts/phala-seven-cvm-release-verification-authority-core.mjs",
  "scripts/phala-seven-cvm-release-verification-authority-v4-core.mjs",
  "scripts/phala-seven-cvm-verifier-evidence.mjs",
  "scripts/pre-ceremony-runtime-authority-core.mjs",
  "scripts/release-authority-current-c-v6-core.mjs",
  "scripts/release-authority-current-reviewer-facade.mjs",
  "scripts/release-authority-historical-core.mjs",
  "scripts/release-authority-signature-verifier-core.mjs",
  "scripts/release-authority-signature-verifier.mjs",
  "scripts/release-authority-stages.mjs",
  "scripts/release-ceremony-authorization.mjs",
  "scripts/release-ceremony-lock-protocol-core.mjs",
  "scripts/release-manifest-descriptor-historical-core.mjs",
  "scripts/release-manifest-sigstore-verifier.mjs",
  "scripts/release-reviewer-authority-core.mjs",
  "scripts/release-reviewer-authority-genesis-acceptance.mjs",
  "scripts/release-reviewer-authority-genesis.mjs",
  "scripts/royalty-release-authority-core.mjs",
  "scripts/royalty-release-history-receipt-core.mjs",
  "scripts/tinker-account-binding-core.mjs",
]);

// The historical signature replay implementation intentionally lives under
// web/scripts so Node resolves its exactly pinned Noble dependencies from the
// web workspace. It is already covered by the web source fingerprint; this
// allowlist only proves that the external pure-core graph reaches that one
// adapter and cannot traverse back into any other web module.
const MODULE_WEB_BACKEDGE_PATHS = Object.freeze([
  "web/scripts/external-five-historical-evidence-core.mjs",
  "web/scripts/frontend-release-historical-core.mjs",
  "web/scripts/independent-eip191-replay-core.mjs",
]);

const MODULE_BARE_PACKAGE_IMPORTS = Object.freeze([
  "@noble/curves/secp256k1",
  "@noble/hashes/sha3",
  "@noble/hashes/utils",
]);

const MODULE_NODE_BUILTIN_IMPORTS = Object.freeze([
  "node:child_process",
  "node:crypto",
  "node:fs",
  "node:fs/promises",
  "node:os",
  "node:path",
  "node:url",
  "node:util",
]);

const MODULE_PRIVILEGED_NODE_IMPORTERS = Object.freeze({
  "node:child_process": Object.freeze([
    "scripts/cvm-release-descriptor-set-v3.mjs",
    "scripts/phala-seven-cvm-opened-fd-runtime-core.mjs",
    "scripts/phala-seven-cvm-verifier-evidence.mjs",
    "scripts/release-authority-signature-verifier.mjs",
    "scripts/release-manifest-sigstore-verifier.mjs",
  ]),
});

// These are exact upper bounds for static imports in the build-time web
// modules. Package bytes are independently bound by the installed dependency
// projection; this list prevents an already-installed transitive dependency
// from silently becoming a new build input.
const WEB_MODULE_BARE_PACKAGE_IMPORTS = Object.freeze([
  "@noble/curves/secp256k1",
  "@noble/hashes/sha3",
  "@noble/hashes/utils",
  "typescript",
  "viem",
  "viem/accounts",
  "vite",
]);

const WEB_MODULE_NODE_BUILTIN_IMPORTS = Object.freeze([
  "node:assert/strict",
  "node:child_process",
  "node:crypto",
  "node:fs",
  "node:fs/promises",
  "node:net",
  "node:os",
  "node:path",
  "node:process",
  "node:test",
  "node:url",
  "node:util",
  "node:vm",
]);

const WEB_MODULE_PRIVILEGED_NODE_IMPORTERS = Object.freeze({
  "node:child_process": Object.freeze([
    "web/scripts/build-release-env.mjs",
    "web/scripts/cloudflare-build-sandbox-core.mjs",
    "web/scripts/cloudflare-build-sandbox-core.test.mjs",
    "web/scripts/cloudflare-external-build-closure-core.mjs",
    "web/scripts/deploy-cloudflare.mjs",
    "web/scripts/frontend-build-candidate-producer-core.mjs",
    "web/scripts/release-env-core.test.mjs",
    "web/scripts/release-runtime-pins-core.mjs",
  ]),
  "node:process": Object.freeze([
    "web/scripts/durable-private-file-core.mjs",
  ]),
  "node:vm": Object.freeze([
    "web/scripts/bootstrap-retirement.test.mjs",
  ]),
});

const WEB_MODULE_IMPORT_META_URLS = Object.freeze({
  "scripts/build-tee-image-release.mjs": Object.freeze([
    "./build-tee-image-release.mjs",
  ]),
  "scripts/cvm-release-descriptor-set-v3.mjs": Object.freeze([
    "./cvm-release-descriptor-set-v3.mjs",
  ]),
  "scripts/phala-seven-cvm-verifier-evidence.mjs": Object.freeze([
    "./phala-seven-cvm-dcap-verify.py",
  ]),
  "web/scripts/bootstrap-retirement.test.mjs": Object.freeze([
    "./bootstrap-retirement.test.mjs",
  ]),
  "web/scripts/build-release-env.mjs": Object.freeze([
    "./build-release-env.mjs",
  ]),
  "web/scripts/build-release-env.test.mjs": Object.freeze([
    "./build-release-env.test.mjs",
  ]),
  "web/scripts/build-security-headers.mjs": Object.freeze([
    "./build-security-headers.mjs",
  ]),
  "web/scripts/cloudflare-build-sandbox-core.test.mjs": Object.freeze([
    "./cloudflare-build-sandbox-core.test.mjs",
  ]),
  "web/scripts/cloudflare-external-build-closure-core.mjs": Object.freeze([
    "../node_modules/typescript/lib/typescript.js",
  ]),
  "web/scripts/cloudflare-external-build-closure-core.test.mjs": Object.freeze([
    "../..",
    "../node_modules/typescript/lib/typescript.js",
  ]),
  "web/scripts/cloudflare-release-artifact-core.test.mjs": Object.freeze([
    "../..",
  ]),
  "web/scripts/deploy-cloudflare-runner.test.mjs": Object.freeze([
    "../node_modules/wrangler/wrangler-dist/cli.js",
    "../package-lock.json",
    "../package.json",
  ]),
  "web/scripts/deploy-cloudflare.mjs": Object.freeze([
    "./deploy-cloudflare.mjs",
  ]),
  "web/scripts/external-five-historical-evidence-core.test.mjs": Object.freeze([
    "../../scripts/canonical-authority-graph.mjs",
    "./external-five-historical-evidence-core.mjs",
  ]),
  "web/scripts/frontend-release-historical-core.test.mjs": Object.freeze([
    "./frontend-release-historical-core.mjs",
  ]),
  "web/scripts/frontend-build-candidate-producer-core.mjs": Object.freeze([
    "./frontend-build-candidate-producer-core.mjs",
  ]),
  "web/scripts/independent-eip191-replay-core.test.mjs": Object.freeze([
    "../package-lock.json",
    "../package.json",
    "./independent-eip191-replay-core.mjs",
  ]),
  "web/scripts/pitch-assets-provenance.test.mjs": Object.freeze([
    "../..",
    "../../outputs/wikigen-pitch-assets/attested-network.png",
    "../../outputs/wikigen-pitch-assets/private-reward-oracle.png",
  ]),
  "web/scripts/pages-apex-redirect.test.mjs": Object.freeze([
    "./pages-apex-redirect.test.mjs",
  ]),
  "web/scripts/release-env-core.test.mjs": Object.freeze([
    "../RELEASE-MANIFEST.md",
      "../../⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",
  ]),
  "web/scripts/security-headers-core.test.mjs": Object.freeze([
    "./security-headers-core.test.mjs",
  ]),
});

const WEB_SOURCE_BARE_PACKAGE_IMPORTS = Object.freeze([
  "@fontsource-variable/jetbrains-mono",
  "@fontsource-variable/manrope",
  "@walletconnect/ethereum-provider",
  "lucide-solid",
  "solid-js",
  "solid-js/web",
  "viem",
  "viem/accounts",
  "viem/chains",
  "vitest",
]);

const WEB_CONFIG_MODULES = Object.freeze({
  "web/vite.config.ts": Object.freeze({
    barePackages: Object.freeze(["vite", "vite-plugin-solid"]),
    sha256: "f8e3310ba29644759402cc83c0046cb71bdc060eee37d172d15cf70338691895",
  }),
  "web/vitest.config.ts": Object.freeze({
    barePackages: Object.freeze(["vite-plugin-solid", "vitest/config"]),
    sha256: "8d1ec483a5a18b15bc16c0033cdd3eed5d9096922481cbeacc49f8d5d7c1153c",
  }),
});

const WEB_PUBLIC_PATHS = Object.freeze([
  "web/public/_headers",
  "web/public/favicon.svg",
  "web/public/wikigen-bootstrap-v3.js",
]);
const WEB_PUBLIC_BOOTSTRAP_SHA256 =
  "fcc80927a0b1e9267844533d26e8a24d77f5c9750252357b4c929c0bde66151c";

const WEB_BUILD_CONTROL_PATHS = Object.freeze([
  "web/index.html",
  "web/tsconfig.json",
  ...Object.keys(WEB_CONFIG_MODULES),
]);

const WEB_AUXILIARY_SOURCE_TARGET_PATHS = Object.freeze([
  "web/README.md",
]);

const WEB_CSS_DATA_URLS = Object.freeze({
  "web/src/styles.css": Object.freeze([
    "data:image/svg+xml,%3Csvg viewBox='0 0 180 180' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.92' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.12'/%3E%3C/svg%3E",
  ]),
});

const WEB_SOURCE_CODE_EXTENSIONS = Object.freeze([
  ".cjs",
  ".cts",
  ".js",
  ".jsx",
  ".mjs",
  ".mts",
  ".ts",
  ".tsx",
]);

const WEB_SOURCE_TARGET_EXTENSIONS = Object.freeze([
  ...WEB_SOURCE_CODE_EXTENSIONS,
  ".css",
  ".json",
  ".md",
  ".png",
  ".svg",
  ".webp",
]);

// This file is imported by a build-time test but lives outside web/scripts.
// Keeping the target explicit lets relative imports be checked against a
// complete enumerated set rather than accepting every path below web/.
const WEB_STATIC_MODULE_PATHS = Object.freeze([
  "web/functions/_middleware.js",
]);

const RESOURCE_DEFINITIONS = Object.freeze([
  Object.freeze({ kind: "sandbox_config", path: ".gitignore", maximumBytes: 64 * 1024 }),
  Object.freeze({ kind: "verification_input", path: "ARCHITECTURE.md", maximumBytes: 4 * 1024 * 1024 }),
  Object.freeze({ kind: "verification_input", path: "PROJECT.md", maximumBytes: 4 * 1024 * 1024 }),
  Object.freeze({ kind: "verification_input", path: "README.md", maximumBytes: 4 * 1024 * 1024 }),
  Object.freeze({ kind: "verification_input", path: "docs/compute-console-api.md", maximumBytes: 4 * 1024 * 1024 }),
  Object.freeze({ kind: "verification_input", path: "scripts/phala-seven-cvm-dcap-verify.py", maximumBytes: 128 * 1024 }),
  Object.freeze({ kind: "asset_provenance_input", path: "outputs/wikigen-pitch-assets/attested-network.png", maximumBytes: 4 * 1024 * 1024 }),
  Object.freeze({ kind: "asset_provenance_input", path: "outputs/wikigen-pitch-assets/private-reward-oracle.png", maximumBytes: 4 * 1024 * 1024 }),
  Object.freeze({ kind: "verification_input", path: "⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq", maximumBytes: 1024 * 1024 }),
]);

const RESOURCE_CONSUMER_BINDINGS = Object.freeze([
  Object.freeze({
    consumer: "scripts/phala-seven-cvm-verifier-evidence.mjs",
    externalPath: "scripts/phala-seven-cvm-dcap-verify.py",
    query: "",
    requestKind: "import_meta_url",
    specifier: "./phala-seven-cvm-dcap-verify.py",
  }),
  Object.freeze({
    consumer: "web/src/components/ComputeWorkloadPanel.test.ts",
    externalPath: "docs/compute-console-api.md",
    query: "?raw",
    requestKind: "static_import",
    specifier: "../../../docs/compute-console-api.md?raw",
  }),
  Object.freeze({
    consumer: "web/src/productTruth.test.ts",
    externalPath: "ARCHITECTURE.md",
    query: "?raw",
    requestKind: "static_import",
    specifier: "../../ARCHITECTURE.md?raw",
  }),
  Object.freeze({
    consumer: "web/src/productTruth.test.ts",
    externalPath: "PROJECT.md",
    query: "?raw",
    requestKind: "static_import",
    specifier: "../../PROJECT.md?raw",
  }),
  Object.freeze({
    consumer: "web/src/productTruth.test.ts",
    externalPath: "README.md",
    query: "?raw",
    requestKind: "static_import",
    specifier: "../../README.md?raw",
  }),
  Object.freeze({
    consumer: "web/scripts/release-env-core.test.mjs",
    externalPath:
      "⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",
    query: "",
    requestKind: "import_meta_url",
    specifier:
      "../../⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",
  }),
  Object.freeze({
    consumer: "web/scripts/pitch-assets-provenance.test.mjs",
    externalPath: "outputs/wikigen-pitch-assets/attested-network.png",
    query: "",
    requestKind: "import_meta_url",
    specifier: "../../outputs/wikigen-pitch-assets/attested-network.png",
  }),
  Object.freeze({
    consumer: "web/scripts/pitch-assets-provenance.test.mjs",
    externalPath: "outputs/wikigen-pitch-assets/private-reward-oracle.png",
    query: "",
    requestKind: "import_meta_url",
    specifier: "../../outputs/wikigen-pitch-assets/private-reward-oracle.png",
  }),
]);

function compareCanonical(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an exact object`);
  }
  const keys = Object.keys(value).sort(compareCanonical);
  const wanted = [...expected].sort(compareCanonical);
  if (JSON.stringify(keys) !== JSON.stringify(wanted)) {
    throw new Error(`${label} has an unexpected shape`);
  }
  return value;
}

function parseDuplicateFreeJson(bytes, label) {
  if (!Buffer.isBuffer(bytes)) throw new Error(`${label} is not bytes`);
  const source = bytes.toString("utf8");
  if (!Buffer.from(source, "utf8").equals(bytes) || source.startsWith("\uFEFF")) {
    throw new Error(`${label} is not canonical UTF-8 JSON`);
  }
  let index = 0;
  function whitespace() {
    while (/[\x20\x09\x0a\x0d]/.test(source[index] || "")) index += 1;
  }
  function string() {
    if (source[index] !== '"') throw new Error(`${label} contains a non-string key or value`);
    const start = index;
    index += 1;
    while (index < source.length) {
      const code = source.charCodeAt(index);
      if (source[index] === '"') {
        index += 1;
        return JSON.parse(source.slice(start, index));
      }
      if (source[index] === "\\") {
        index += 1;
        if (index >= source.length || !'["\\/bfnrtu]'.includes(source[index])) {
          throw new Error(`${label} contains an invalid string escape`);
        }
        if (source[index] === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(source.slice(index + 1, index + 5))) {
            throw new Error(`${label} contains an invalid Unicode escape`);
          }
          index += 4;
        }
      } else if (code < 0x20) {
        throw new Error(`${label} contains an unescaped control character`);
      }
      index += 1;
    }
    throw new Error(`${label} contains an unterminated string`);
  }
  function value(depth = 0) {
    if (depth > 64) throw new Error(`${label} exceeds its nesting bound`);
    whitespace();
    if (source[index] === '"') return string();
    if (source[index] === "{") {
      index += 1;
      // A null prototype makes keys such as `__proto__` ordinary enumerable
      // input, so the exact-schema check cannot silently absorb prototype
      // mutation through assignment.
      const result = Object.create(null);
      const keys = new Set();
      whitespace();
      if (source[index] === "}") {
        index += 1;
        return result;
      }
      while (index < source.length) {
        whitespace();
        const key = string();
        if (keys.has(key)) throw new Error(`${label} contains a duplicate object key`);
        keys.add(key);
        whitespace();
        if (source[index] !== ":") throw new Error(`${label} contains malformed object syntax`);
        index += 1;
        result[key] = value(depth + 1);
        whitespace();
        if (source[index] === "}") {
          index += 1;
          return result;
        }
        if (source[index] !== ",") throw new Error(`${label} contains malformed object syntax`);
        index += 1;
      }
      throw new Error(`${label} contains an unterminated object`);
    }
    if (source[index] === "[") {
      index += 1;
      const result = [];
      whitespace();
      if (source[index] === "]") {
        index += 1;
        return result;
      }
      while (index < source.length) {
        result.push(value(depth + 1));
        whitespace();
        if (source[index] === "]") {
          index += 1;
          return result;
        }
        if (source[index] !== ",") throw new Error(`${label} contains malformed array syntax`);
        index += 1;
      }
      throw new Error(`${label} contains an unterminated array`);
    }
    for (const [token, parsed] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(token, index)) {
        index += token.length;
        return parsed;
      }
    }
    const number = source.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (number) {
      index += number[0].length;
      return JSON.parse(number[0]);
    }
    throw new Error(`${label} contains invalid JSON syntax`);
  }
  const parsed = value();
  whitespace();
  if (index !== source.length) throw new Error(`${label} contains trailing content`);
  return parsed;
}

function assertExactWebTsconfig(bytes) {
  const root = exactKeys(
    parseDuplicateFreeJson(bytes, "Cloudflare web tsconfig"),
    ["compilerOptions", "include"],
    "Cloudflare web tsconfig",
  );
  const options = exactKeys(root.compilerOptions, [
    "esModuleInterop",
    "isolatedModules",
    "jsx",
    "jsxImportSource",
    "lib",
    "module",
    "moduleResolution",
    "noEmit",
    "noFallthroughCasesInSwitch",
    "noUnusedLocals",
    "noUnusedParameters",
    "skipLibCheck",
    "strict",
    "target",
    "types",
    "verbatimModuleSyntax",
  ], "Cloudflare web tsconfig compilerOptions");
  const expected = {
    esModuleInterop: true,
    isolatedModules: true,
    jsx: "preserve",
    jsxImportSource: "solid-js",
    lib: ["ES2022", "DOM", "DOM.Iterable"],
    module: "ESNext",
    moduleResolution: "bundler",
    noEmit: true,
    noFallthroughCasesInSwitch: true,
    noUnusedLocals: true,
    noUnusedParameters: true,
    skipLibCheck: true,
    strict: true,
    target: "ES2020",
    types: ["vite/client"],
    verbatimModuleSyntax: true,
  };
  if (
    Object.entries(expected).some(
      ([key, value]) => JSON.stringify(options[key]) !== JSON.stringify(value),
    )
    || JSON.stringify(root.include) !== JSON.stringify(["src"])
    || new Set(options.lib).size !== options.lib.length
    || new Set(options.types).size !== options.types.length
  ) {
    throw new Error("Cloudflare web tsconfig resolution policy is not exact");
  }
}

function assertExactWebIndexHtml(bytes) {
  const source = bytes.toString("utf8");
  if (!Buffer.from(source, "utf8").equals(bytes)) {
    throw new Error("Cloudflare web index is not canonical UTF-8");
  }
  const lowerSource = source.toLowerCase();
  const stack = [];
  const references = [];
  const voidElements = new Set([
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
  ]);
  const urlAttributes = new Set([
    "action", "data", "formaction", "href", "poster", "src", "srcset", "xlink:href",
  ]);
  const allowedElements = new Set([
    "body", "div", "head", "html", "link", "meta", "script", "title",
  ]);
  let index = 0;
  let sawDoctype = false;
  function parseStartTag(raw) {
    let cursor = 0;
    const nameMatch = raw.slice(cursor).match(/^[A-Za-z][A-Za-z0-9:-]*/);
    if (!nameMatch) throw new Error("Cloudflare web index contains a malformed tag");
    const name = nameMatch[0].toLowerCase();
    cursor += nameMatch[0].length;
    const attributes = {};
    let selfClosing = false;
    while (cursor < raw.length) {
      while (/\s/.test(raw[cursor] || "")) cursor += 1;
      if (cursor >= raw.length) break;
      if (raw[cursor] === "/" && /^\/\s*$/.test(raw.slice(cursor))) {
        selfClosing = true;
        break;
      }
      const attributeMatch = raw.slice(cursor).match(/^[^\s"'<>/=]+/);
      if (!attributeMatch) throw new Error("Cloudflare web index contains malformed attributes");
      const attribute = attributeMatch[0].toLowerCase();
      cursor += attributeMatch[0].length;
      while (/\s/.test(raw[cursor] || "")) cursor += 1;
      if (raw[cursor] !== "=") {
        throw new Error("Cloudflare web index refuses boolean or unquoted attributes");
      }
      cursor += 1;
      while (/\s/.test(raw[cursor] || "")) cursor += 1;
      const quote = raw[cursor];
      if (quote !== '"' && quote !== "'") {
        throw new Error("Cloudflare web index refuses unquoted attributes");
      }
      cursor += 1;
      const end = raw.indexOf(quote, cursor);
      if (end < 0) throw new Error("Cloudflare web index contains an unterminated attribute");
      const value = raw.slice(cursor, end);
      cursor = end + 1;
      if (Object.hasOwn(attributes, attribute)) {
        throw new Error("Cloudflare web index contains duplicate attributes");
      }
      if (attribute.startsWith("on") || attribute === "style") {
        throw new Error("Cloudflare web index contains unaudited executable markup");
      }
      attributes[attribute] = value;
    }
    return { attributes, name, selfClosing };
  }
  while (index < source.length) {
    const next = source.indexOf("<", index);
    if (next < 0) break;
    index = next;
    if (source.startsWith("<!--", index)) {
      const end = source.indexOf("-->", index + 4);
      if (end < 0 || source.slice(index + 4, end).includes("<!--")) {
        throw new Error("Cloudflare web index contains a malformed comment");
      }
      index = end + 3;
      continue;
    }
    if (lowerSource.startsWith("<!doctype", index)) {
      const end = source.indexOf(">", index + 2);
      if (
        end < 0
        || sawDoctype
        || source.slice(index, end + 1).trim().toLowerCase() !== "<!doctype html>"
      ) {
        throw new Error("Cloudflare web index contains an invalid doctype");
      }
      sawDoctype = true;
      index = end + 1;
      continue;
    }
    if (source.startsWith("</", index)) {
      const end = source.indexOf(">", index + 2);
      if (end < 0) throw new Error("Cloudflare web index contains an unterminated closing tag");
      const name = source.slice(index + 2, end).trim().toLowerCase();
      if (!/^[a-z][a-z0-9:-]*$/.test(name) || stack.pop() !== name) {
        throw new Error("Cloudflare web index contains mismatched closing tags");
      }
      index = end + 1;
      continue;
    }
    if (source.startsWith("<!", index) || source.startsWith("<?", index)) {
      throw new Error("Cloudflare web index contains unsupported markup declarations");
    }
    let end = index + 1;
    let quote = null;
    for (; end < source.length; end += 1) {
      const character = source[end];
      if (quote) {
        if (character === quote) quote = null;
      } else if (character === '"' || character === "'") {
        quote = character;
      } else if (character === ">") {
        break;
      } else if (character === "<") {
        throw new Error("Cloudflare web index contains malformed nested markup");
      }
    }
    if (end >= source.length || quote) {
      throw new Error("Cloudflare web index contains an unterminated tag");
    }
    const { attributes, name, selfClosing } = parseStartTag(
      source.slice(index + 1, end),
    );
    if (!allowedElements.has(name)) {
      throw new Error("Cloudflare web index contains an unsupported markup element");
    }
    if (name === "base" || name === "style") {
      throw new Error("Cloudflare web index contains unsupported resolver markup");
    }
    if (name === "script") {
      const attributeKeys = Object.keys(attributes).sort(compareCanonical);
      const classic = JSON.stringify(attributeKeys) === JSON.stringify(["src"])
        && attributes.src === "/wikigen-bootstrap-v3.js";
      const module = JSON.stringify(attributeKeys) === JSON.stringify(["src", "type"])
        && attributes.type === "module"
        && attributes.src === "/src/index.tsx";
      if (!classic && !module) {
        throw new Error("Cloudflare web index contains an undeclared script reference");
      }
      const closing = lowerSource.indexOf("</script>", end + 1);
      if (closing < 0 || source.slice(end + 1, closing).trim()) {
        throw new Error("Cloudflare web index contains inline or unterminated script");
      }
      references.push({
        kind: module ? "module_script" : "classic_script",
        specifier: attributes.src,
        target: module
          ? "web/src/index.tsx"
          : "web/public/wikigen-bootstrap-v3.js",
      });
      index = closing + "</script>".length;
      continue;
    }
    if (name === "link") {
      const keys = Object.keys(attributes).sort(compareCanonical);
      const favicon = JSON.stringify(keys) === JSON.stringify(["href", "rel", "type"])
        && attributes.rel === "icon"
        && attributes.href === "/favicon.svg"
        && attributes.type === "image/svg+xml";
      const canonical = JSON.stringify(keys) === JSON.stringify(["href", "rel"])
        && attributes.rel === "canonical"
        && attributes.href === "https://www.wikigen.me/";
      if (!favicon && !canonical) {
        throw new Error("Cloudflare web index contains an undeclared link reference");
      }
      references.push({
        kind: favicon ? "icon" : "canonical",
        specifier: attributes.href,
        target: favicon ? "web/public/favicon.svg" : "https://www.wikigen.me/",
      });
    } else {
      for (const attribute of Object.keys(attributes)) {
        if (urlAttributes.has(attribute)) {
          throw new Error("Cloudflare web index contains an undeclared local asset reference");
        }
      }
      if (name === "meta" && Object.hasOwn(attributes, "http-equiv")) {
        throw new Error("Cloudflare web index contains an unaudited HTTP-equivalent directive");
      }
    }
    index = end + 1;
    if (!selfClosing && !voidElements.has(name)) stack.push(name);
  }
  if (!sawDoctype || stack.length) {
    throw new Error("Cloudflare web index structure is incomplete");
  }
  const expected = [
    { kind: "icon", specifier: "/favicon.svg", target: "web/public/favicon.svg" },
    { kind: "canonical", specifier: "https://www.wikigen.me/", target: "https://www.wikigen.me/" },
    { kind: "classic_script", specifier: "/wikigen-bootstrap-v3.js", target: "web/public/wikigen-bootstrap-v3.js" },
    { kind: "module_script", specifier: "/src/index.tsx", target: "web/src/index.tsx" },
  ];
  if (JSON.stringify(references) !== JSON.stringify(expected)) {
    throw new Error("Cloudflare web index references are not exact and ordered");
  }
}

function assertClosedCssResourceGraph(bytes, filePath) {
  const source = bytes.toString("utf8");
  if (!Buffer.from(source, "utf8").equals(bytes)) {
    throw new Error(`Cloudflare CSS source is not canonical UTF-8: ${filePath}`);
  }
  let index = 0;
  const observedDataUrls = [];
  const forbiddenResourceFunctions = new Set([
    "-webkit-image-set",
    "cross-fade",
    "image",
    "image-set",
    "src",
  ]);
  function comment() {
    if (!source.startsWith("/*", index)) return false;
    const end = source.indexOf("*/", index + 2);
    if (end < 0) throw new Error(`Cloudflare CSS contains an unterminated comment: ${filePath}`);
    index = end + 2;
    return true;
  }
  function trivia() {
    while (index < source.length) {
      if (/\s/.test(source[index])) index += 1;
      else if (!comment()) break;
    }
  }
  function escape() {
    if (source[index] !== "\\") return null;
    index += 1;
    if (index >= source.length || /[\r\n\f]/.test(source[index])) {
      throw new Error(`Cloudflare CSS contains an invalid escape: ${filePath}`);
    }
    const hexadecimal = source.slice(index).match(/^[0-9a-fA-F]{1,6}/)?.[0];
    if (hexadecimal) {
      index += hexadecimal.length;
      if (/\s/.test(source[index] || "")) index += 1;
      const code = Number.parseInt(hexadecimal, 16);
      if (code === 0 || code > 0x10ffff) {
        throw new Error(`Cloudflare CSS contains an invalid Unicode escape: ${filePath}`);
      }
      return String.fromCodePoint(code);
    }
    const value = source[index];
    index += 1;
    return value;
  }
  function identifier() {
    let value = "";
    while (index < source.length) {
      const character = source[index];
      if (/[A-Za-z0-9_-]/.test(character) || character.codePointAt(0) >= 0x80) {
        value += character;
        index += 1;
      } else if (character === "\\") {
        value += escape();
      } else {
        break;
      }
    }
    return value;
  }
  function string() {
    const quote = source[index];
    index += 1;
    let value = "";
    while (index < source.length) {
      if (source[index] === quote) {
        index += 1;
        return value;
      }
      if (source[index] === "\\") value += escape();
      else {
        if (/[\r\n\f]/.test(source[index])) {
          throw new Error(`Cloudflare CSS contains an unterminated string: ${filePath}`);
        }
        value += source[index];
        index += 1;
      }
    }
    throw new Error(`Cloudflare CSS contains an unterminated string: ${filePath}`);
  }
  while (index < source.length) {
    if (comment()) continue;
    if (source[index] === '"' || source[index] === "'") {
      string();
      continue;
    }
    if (source[index] === "@") {
      index += 1;
      const rule = identifier().toLowerCase();
      if (rule === "import") {
        throw new Error(`Cloudflare CSS refuses @import resolution: ${filePath}`);
      }
      continue;
    }
    if (
      /[A-Za-z_-]/.test(source[index])
      || source[index] === "\\"
      || source[index].codePointAt(0) >= 0x80
    ) {
      const name = identifier().toLowerCase();
      const afterName = index;
      trivia();
      if (source[index] === "(" && forbiddenResourceFunctions.has(name)) {
        throw new Error(`Cloudflare CSS refuses an unsupported resource function: ${filePath}`);
      }
      if (name !== "url" || source[index] !== "(") {
        index = Math.max(index, afterName);
        continue;
      }
      index += 1;
      trivia();
      if (source[index] !== '"' && source[index] !== "'") {
        throw new Error(`Cloudflare CSS refuses unquoted or non-data url(): ${filePath}`);
      }
      const target = string();
      trivia();
      if (source[index] !== ")") {
        throw new Error(`Cloudflare CSS contains malformed url(): ${filePath}`);
      }
      index += 1;
      if (!target.toLowerCase().startsWith("data:")) {
        throw new Error(`Cloudflare CSS refuses non-data url(): ${filePath}`);
      }
      observedDataUrls.push(target);
      continue;
    }
    index += 1;
  }
  const expectedDataUrls = WEB_CSS_DATA_URLS[filePath] || [];
  if (
    observedDataUrls.length !== new Set(observedDataUrls).size
    || JSON.stringify(observedDataUrls) !== JSON.stringify(expectedDataUrls)
  ) {
    throw new Error(`Cloudflare CSS data URL graph is not exact: ${filePath}`);
  }
}

function canonicalText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function domainHash(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update("\0", "ascii")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

function safeMode(mode) {
  return Number.isSafeInteger(mode)
    && mode >= 0
    && mode <= 0o777
    && (mode & 0o400) !== 0
    && (mode & 0o133) === 0;
}

function entrypointDefinitions() {
  return [
    ...RESOURCE_DEFINITIONS.map(({ kind, path: filePath }) => ({
      kind,
      path: filePath,
    })),
    ...MODULE_ENTRYPOINT_PATHS.map((filePath) => ({
      kind: "module",
      path: filePath,
    })),
  ]
    .sort((left, right) => compareCanonical(left.path, right.path))
    .map((entry) => Object.freeze(entry));
}

function fileDefinitions() {
  const resources = RESOURCE_DEFINITIONS.map((entry) => ({ ...entry }));
  const modules = MODULE_CLOSURE_PATHS.map((filePath) => ({
    kind: "module",
    path: filePath,
    maximumBytes: 4 * 1024 * 1024,
  }));
  return [...resources, ...modules]
    .sort((left, right) => compareCanonical(left.path, right.path))
    .map((entry) => Object.freeze(entry));
}

export const CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS = Object.freeze(
  entrypointDefinitions(),
);
export const CLOUDFLARE_EXTERNAL_BUILD_FILES = Object.freeze(
  fileDefinitions(),
);

function aggregatePayload({ entrypoints, files }) {
  return {
    schema: CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA,
    truth_status: CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS,
    entrypoints,
    files,
    raw_secret_egress: false,
  };
}

export function normalizeCloudflareExternalBuildClosure(value) {
  const parsed = exactKeys(value, [
    "aggregate_sha256",
    "entrypoints",
    "files",
    "raw_secret_egress",
    "schema",
    "truth_status",
  ], "Cloudflare external build closure");
  if (
    parsed.schema !== CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA
    || parsed.truth_status !== CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS
    || parsed.raw_secret_egress !== false
    || !Array.isArray(parsed.entrypoints)
    || !Array.isArray(parsed.files)
  ) {
    throw new Error("Cloudflare external build closure truth boundary is invalid");
  }

  const entrypoints = parsed.entrypoints.map((entry, index) => {
    const normalized = exactKeys(
      entry,
      ["kind", "path"],
      `Cloudflare external build entrypoint ${index}`,
    );
    const expected = CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS[index];
    if (
      !expected
      || normalized.kind !== expected.kind
      || normalized.path !== expected.path
    ) {
      throw new Error("Cloudflare external build entrypoints are not exact and ordered");
    }
    return Object.freeze({ kind: normalized.kind, path: normalized.path });
  });
  if (entrypoints.length !== CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS.length) {
    throw new Error("Cloudflare external build entrypoints are incomplete");
  }

  const files = parsed.files.map((file, index) => {
    const normalized = exactKeys(
      file,
      ["kind", "mode", "path", "sha256", "size"],
      `Cloudflare external build file ${index}`,
    );
    const expected = CLOUDFLARE_EXTERNAL_BUILD_FILES[index];
    if (
      !expected
      || normalized.kind !== expected.kind
      || normalized.path !== expected.path
      || !safeMode(normalized.mode)
      || !Number.isSafeInteger(normalized.size)
      || normalized.size < 1
      || normalized.size > expected.maximumBytes
      || !SHA256.test(String(normalized.sha256 || ""))
    ) {
      throw new Error("Cloudflare external build files are unsafe or not exact and ordered");
    }
    return Object.freeze({
      kind: normalized.kind,
      path: normalized.path,
      mode: normalized.mode,
      size: normalized.size,
      sha256: normalized.sha256,
    });
  });
  if (files.length !== CLOUDFLARE_EXTERNAL_BUILD_FILES.length) {
    throw new Error("Cloudflare external build file closure is incomplete");
  }

  const payload = aggregatePayload({ entrypoints, files });
  const aggregateSha256 = domainHash(AGGREGATE_DOMAIN, payload);
  if (parsed.aggregate_sha256 !== aggregateSha256) {
    throw new Error("Cloudflare external build closure aggregate is invalid");
  }
  return Object.freeze({
    schema: payload.schema,
    truth_status: payload.truth_status,
    entrypoints: Object.freeze(entrypoints),
    files: Object.freeze(files),
    aggregate_sha256: aggregateSha256,
    raw_secret_egress: false,
  });
}

export function canonicalCloudflareExternalBuildClosureText(value) {
  return canonicalText(normalizeCloudflareExternalBuildClosure(value));
}

export function cloudflareExternalBuildClosureSha256(value) {
  return domainHash(
    RECEIPT_DOMAIN,
    normalizeCloudflareExternalBuildClosure(value),
  );
}

async function canonicalRepositoryRoot(repoRoot) {
  if (
    typeof repoRoot !== "string"
    || !path.isAbsolute(repoRoot)
    || path.resolve(repoRoot) !== repoRoot
    || path.normalize(repoRoot) !== repoRoot
  ) {
    throw new Error("Cloudflare external build closure root must be canonical and absolute");
  }
  const canonical = await realpath(repoRoot);
  if (canonical !== repoRoot) {
    throw new Error("Cloudflare external build closure root is aliased");
  }
  return canonical;
}

function repositoryPath(repoRoot, relative) {
  if (
    typeof relative !== "string"
    || !relative
    || relative.startsWith("/")
    || relative.includes("\\")
    || path.posix.normalize(relative) !== relative
    || relative === ".."
    || relative.startsWith("../")
  ) {
    throw new Error("Cloudflare external build path is not canonical and relative");
  }
  const absolute = path.join(repoRoot, ...relative.split("/"));
  if (!absolute.startsWith(`${repoRoot}${path.sep}`)) {
    throw new Error("Cloudflare external build path escapes the repository");
  }
  return absolute;
}

async function readStableRepositoryFile(
  repoRoot,
  relative,
  maximumBytes,
  label,
  testHooks = null,
) {
  const absolute = repositoryPath(repoRoot, relative);
  let canonical;
  try {
    canonical = await realpath(absolute);
  } catch {
    throw new Error(`${label} is missing`);
  }
  if (canonical !== absolute) {
    throw new Error(`${label} path is symlinked or aliased`);
  }
  const named = await lstat(absolute, { bigint: true });
  const expectedUid = typeof process.geteuid === "function"
    ? BigInt(process.geteuid())
    : named.uid;
  const mode = Number(named.mode & 0o777n);
  if (
    !named.isFile()
    || named.isSymbolicLink()
    || named.nlink !== 1n
    || named.uid !== expectedUid
    || !safeMode(mode)
    || named.size < 1n
    || named.size > BigInt(maximumBytes)
  ) {
    throw new Error(`${label} is not a bounded owner-controlled single-link file`);
  }
  const handle = await open(
    absolute,
    constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
  );
  try {
    const before = await handle.stat({ bigint: true });
    for (const field of ["dev", "ino", "size", "nlink", "uid", "gid", "mode"]) {
      if (before[field] !== named[field]) {
        throw new Error(`${label} changed while opening`);
      }
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    for (const field of [
      "dev", "ino", "size", "nlink", "uid", "gid", "mode", "mtimeNs", "ctimeNs",
    ]) {
      if (before[field] !== after[field]) {
        throw new Error(`${label} changed during its stable read`);
      }
    }
    if (BigInt(bytes.length) !== before.size) {
      throw new Error(`${label} changed size during its stable read`);
    }
    if (testHooks?.afterRead) await testHooks.afterRead({ absolute, relative });
    let namedAfter;
    let canonicalAfter;
    try {
      [namedAfter, canonicalAfter] = await Promise.all([
        lstat(absolute, { bigint: true }),
        realpath(absolute),
      ]);
    } catch {
      throw new Error(`${label} pathname disappeared after its stable read`);
    }
    if (canonicalAfter !== absolute || namedAfter.isSymbolicLink()) {
      throw new Error(`${label} pathname became symlinked or aliased after its stable read`);
    }
    for (const field of [
      "dev", "ino", "size", "nlink", "uid", "gid", "mode", "mtimeNs", "ctimeNs",
    ]) {
      if (namedAfter[field] !== after[field]) {
        throw new Error(`${label} pathname was replaced after its stable read`);
      }
    }
    return Object.freeze({ absolute, bytes, mode, size: bytes.length });
  } finally {
    await handle.close();
  }
}

async function collectFiles(repoRoot, relativeDirectory, extensions) {
  const root = repositoryPath(repoRoot, relativeDirectory);
  const output = [];
  async function visit(directory) {
    const metadata = await lstat(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error("Cloudflare external build consumer tree is not a real directory");
    }
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => compareCanonical(left.name, right.name));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error("Cloudflare external build consumer tree contains a symlink");
      }
      if (entry.isDirectory()) {
        await visit(absolute);
      } else if (
        entry.isFile()
        && (extensions === null || extensions.has(path.extname(entry.name)))
      ) {
        output.push(path.relative(repoRoot, absolute).split(path.sep).join("/"));
      }
    }
  }
  await visit(root);
  return output.sort(compareCanonical);
}

const MODULE_PARSER_SOURCE = String.raw`
import fs from "node:fs";
import acorn from "internal/deps/acorn/acorn/dist/acorn";
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const output = input.map((entry) => {
  const source = Buffer.from(entry.base64, "base64").toString("utf8");
  const ast = acorn.parse(source, {
    allowHashBang: true,
    ecmaVersion: "latest",
    preserveParens: true,
    sourceType: "module",
  });
  const requests = [];
  const resourceRequests = [];
  const runtimeRequests = [];
  const allowedGlobalUrlReferences = new Set();
  const allowedImportMetaProperties = new Set();
  const rootBindings = new Map([
    ["global", "global"],
    ["globalThis", "global"],
    ["process", "process"],
    ["Reflect", "reflect"],
    ["self", "global"],
    ["window", "global"],
  ]);
  const directCapabilities = new Set([
    "AsyncFunction",
    "AsyncGeneratorFunction",
    "Function",
    "GeneratorFunction",
    "SharedWorker",
    "SourceTextModule",
    "SyntheticModule",
    "Worker",
    "compileFunction",
    "createRequire",
    "eval",
    "getBuiltinModule",
    "importScripts",
    "require",
  ]);
  const forbiddenMemberCapabilities = new Set([
    "AsyncFunction",
    "AsyncGeneratorFunction",
    "Function",
    "GeneratorFunction",
    "SharedWorker",
    "SourceTextModule",
    "SyntheticModule",
    "Worker",
    "compileFunction",
    "construct",
    "constructor",
    "createRequire",
    "eval",
    "getBuiltinModule",
    "importActual",
    "importMock",
    "importScripts",
    "register",
    "registerHooks",
    "require",
    "unstable_mockModule",
  ]);
  const allowedProcessMembers = new Set([
    "arch",
    "argv",
    "env",
    "execPath",
    "exit",
    "exitCode",
    "geteuid",
    "getuid",
    "pid",
    "platform",
    "stderr",
    "stdout",
    "version",
  ]);
  const allowedReflectMembers = new Set([
    "getOwnPropertyDescriptor",
    "ownKeys",
  ]);
  function recordCapability(specifier = null) {
    runtimeRequests.push({
      kind: "runtime_module_capability",
      literal: typeof specifier === "string",
      specifier,
    });
  }
  function unwrap(node) {
    let current = node;
    while (current && new Set([
      "AwaitExpression",
      "ChainExpression",
    ]).has(current.type)) {
      current = current.argument || current.expression;
    }
    return current;
  }
  function staticString(node) {
    const current = unwrap(node);
    if (current?.type === "Literal" && typeof current.value === "string") {
      return current.value;
    }
    if (
      current?.type === "TemplateLiteral"
      && current.expressions?.length === 0
      && current.quasis?.length === 1
    ) {
      return current.quasis[0].value?.cooked ?? current.quasis[0].value?.raw ?? null;
    }
    if (current?.type === "BinaryExpression" && current.operator === "+") {
      const left = staticString(current.left);
      const right = staticString(current.right);
      return typeof left === "string" && typeof right === "string"
        ? left + right
        : null;
    }
    if (current?.type === "SequenceExpression" && current.expressions?.length) {
      return staticString(current.expressions.at(-1));
    }
    return null;
  }
  function memberName(node) {
    if (!node || (node.type !== "MemberExpression"
      && node.type !== "OptionalMemberExpression")) return null;
    if (!node.computed && node.property?.type === "Identifier") {
      return node.property.name;
    }
    return node.computed ? staticString(node.property) : null;
  }
  function patternPropertyName(node) {
    if (node?.type !== "Property") return null;
    if (!node.computed && node.key?.type === "Identifier") return node.key.name;
    return node.computed ? staticString(node.key) : staticString(node.key);
  }
  function rootCapability(node) {
    const current = unwrap(node);
    if (!current) return null;
    if (current.type === "Identifier") {
      return rootBindings.get(current.name) || null;
    }
    if (current.type === "SequenceExpression" && current.expressions?.length) {
      return rootCapability(current.expressions.at(-1));
    }
    if (
      new Set(["ConditionalExpression", "LogicalExpression"]).has(current.type)
    ) {
      const candidates = current.type === "ConditionalExpression"
        ? [current.consequent, current.alternate]
        : [current.left, current.right];
      const roots = candidates.map(rootCapability).filter(Boolean);
      return roots.length && roots.every((value) => value === roots[0])
        ? roots[0]
        : null;
    }
    if (
      current.type === "MemberExpression"
      || current.type === "OptionalMemberExpression"
    ) {
      const root = rootCapability(current.object);
      const property = memberName(current);
      if (root === "global" && property === "process") return "process";
      if (root === "global" && property === "Reflect") return "reflect";
    }
    return null;
  }
  function memberCapability(node) {
    const property = memberName(node);
    const root = rootCapability(node.object);
    if (property === null) {
      return root ? "computed privileged member" : null;
    }
    if (forbiddenMemberCapabilities.has(property)) {
      return property;
    }
    if (root === "process") {
      return allowedProcessMembers.has(property)
        ? null
        : "unaudited process capability";
    }
    if (root === "global") return "global capability access";
    if (root === "reflect") {
      return allowedReflectMembers.has(property)
        ? null
        : "reflective capability access";
    }
    if (root === "vm") {
      return property === "runInNewContext"
        ? "vm.runInNewContext"
        : "unaudited VM capability";
    }
    return null;
  }
  function isExactAllowedVmCall(node) {
    const callee = unwrap(node?.callee);
    return entry.path === "web/scripts/bootstrap-retirement.test.mjs"
      && node?.type === "CallExpression"
      && callee?.type === "MemberExpression"
      && callee.computed === false
      && memberName(callee) === "runInNewContext"
      && rootCapability(callee.object) === "vm"
      && node.arguments?.length === 3
      && node.arguments[0]?.type === "Identifier"
      && node.arguments[0].name === "bootstrapSource"
      && node.arguments[1]?.type === "Identifier"
      && node.arguments[1].name === "context"
      && node.arguments[2]?.type === "ObjectExpression"
      && node.arguments[2].properties?.length === 1
      && node.arguments[2].properties[0]?.type === "Property"
      && node.arguments[2].properties[0].kind === "init"
      && node.arguments[2].properties[0].computed === false
      && node.arguments[2].properties[0].key?.type === "Identifier"
      && node.arguments[2].properties[0].key.name === "filename"
      && node.arguments[2].properties[0].value?.type === "Identifier"
      && node.arguments[2].properties[0].value.name === "bootstrapPath";
  }
  function isImportMeta(node) {
    return Boolean(
      node?.type === "MetaProperty"
      && node.meta?.name === "import"
      && node.property?.name === "meta"
    );
  }
  function isImportMetaUrl(node) {
    return Boolean(
      node?.type === "MemberExpression"
      && node.computed === false
      && node.optional !== true
      && node.property?.type === "Identifier"
      && node.property.name === "url"
      && isImportMeta(node.object)
    );
  }
  function isExactAllowedMiddlewareRequestUrl(node) {
    const argument = node?.arguments?.[0];
    return entry.path === "web/functions/_middleware.js"
      && node?.type === "NewExpression"
      && node.callee?.type === "Identifier"
      && node.callee.name === "URL"
      && node.arguments?.length === 1
      && argument?.type === "MemberExpression"
      && argument.computed === false
      && argument.optional !== true
      && argument.object?.type === "Identifier"
      && argument.object.name === "request"
      && argument.property?.type === "Identifier"
      && argument.property.name === "url";
  }
  function isExactAllowedDynamicDescriptorCall(node) {
    const callee = unwrap(node?.callee);
    return entry.path === "web/scripts/independent-eip191-replay-core.test.mjs"
      && node?.type === "CallExpression"
      && callee?.type === "MemberExpression"
      && callee.computed === false
      && memberName(callee) === "getOwnPropertyDescriptor"
      && rootCapability(callee.object) === "reflect"
      && node.arguments?.length === 2
      && node.arguments[0]?.type === "Identifier"
      && node.arguments[0].name === "target"
      && node.arguments[1]?.type === "Identifier"
      && node.arguments[1].name === "property";
  }
  function isUnsafeDescriptorLookup(node) {
    const callee = unwrap(node?.callee);
    if (
      node?.type !== "CallExpression"
      || (callee?.type !== "MemberExpression"
        && callee?.type !== "OptionalMemberExpression")
      || memberName(callee) !== "getOwnPropertyDescriptor"
      || node.arguments?.length !== 2
    ) return false;
    const object = unwrap(callee.object);
    const isReflect = rootCapability(object) === "reflect";
    const isObject = object?.type === "Identifier" && object.name === "Object";
    if (!isReflect && !isObject) return false;
    const property = staticString(node.arguments[1]);
    if (property === null) return !isExactAllowedDynamicDescriptorCall(node);
    return forbiddenMemberCapabilities.has(property);
  }
  function rootReferenceIsQualified(node, parent) {
    return Boolean(
      parent
      && (
        (parent.type === "MemberExpression"
          || parent.type === "OptionalMemberExpression")
        && parent.object === node
      )
    ) || new Set([
      "ImportDefaultSpecifier",
      "ImportNamespaceSpecifier",
      "ImportSpecifier",
    ]).has(parent?.type);
  }
  function identifierIsReference(node, parent) {
    if (!parent) return true;
    if (
      (parent.type === "MemberExpression"
        || parent.type === "OptionalMemberExpression")
      && parent.property === node
      && parent.computed === false
    ) return false;
    if (
      parent.type === "Property"
      && parent.key === node
      && parent.computed === false
      && parent.shorthand === false
    ) return false;
    if (
      new Set(["MethodDefinition", "PropertyDefinition"]).has(parent.type)
      && parent.key === node
      && parent.computed === false
    ) return false;
    if (
      (parent.type === "VariableDeclarator" && parent.id === node)
      || (new Set([
        "ArrowFunctionExpression",
        "FunctionDeclaration",
        "FunctionExpression",
      ]).has(parent.type)
        && (parent.id === node || parent.params?.includes(node)))
      || new Set([
        "BreakStatement",
        "CatchClause",
        "ClassDeclaration",
        "ClassExpression",
        "ContinueStatement",
        "ImportDefaultSpecifier",
        "ImportNamespaceSpecifier",
        "ImportSpecifier",
        "LabeledStatement",
      ]).has(parent.type)
    ) return false;
    return true;
  }
  function bindingPatternContainsUrl(pattern) {
    if (!pattern) return false;
    if (pattern.type === "Identifier") return pattern.name === "URL";
    if (pattern.type === "AssignmentPattern") {
      return bindingPatternContainsUrl(pattern.left);
    }
    if (pattern.type === "RestElement") {
      return bindingPatternContainsUrl(pattern.argument);
    }
    if (pattern.type === "ArrayPattern") {
      return pattern.elements?.some(bindingPatternContainsUrl) || false;
    }
    if (pattern.type === "ObjectPattern") {
      return pattern.properties?.some((property) => (
        property.type === "RestElement"
          ? bindingPatternContainsUrl(property.argument)
          : bindingPatternContainsUrl(property.value)
      )) || false;
    }
    return false;
  }
  function declaresUrlBinding(node) {
    if (node.type === "AssignmentExpression") {
      return bindingPatternContainsUrl(node.left);
    }
    if (node.type === "UpdateExpression") {
      return bindingPatternContainsUrl(node.argument);
    }
    if (node.type === "VariableDeclarator") {
      return bindingPatternContainsUrl(node.id);
    }
    if (new Set([
      "ArrowFunctionExpression",
      "FunctionDeclaration",
      "FunctionExpression",
    ]).has(node.type)) {
      return bindingPatternContainsUrl(node.id)
        || node.params?.some(bindingPatternContainsUrl);
    }
    if (new Set(["ClassDeclaration", "ClassExpression"]).has(node.type)) {
      return bindingPatternContainsUrl(node.id);
    }
    if (node.type === "CatchClause") {
      return bindingPatternContainsUrl(node.param);
    }
    if (
      new Set([
        "ImportDefaultSpecifier",
        "ImportNamespaceSpecifier",
        "ImportSpecifier",
      ]).has(node.type)
    ) {
      return bindingPatternContainsUrl(node.local);
    }
    return false;
  }
  function registerModuleBindings() {
    for (const node of ast.body) {
      if (node.type !== "ImportDeclaration") continue;
      const specifier = node.source?.value;
      if (specifier === "node:process") {
        if (
          node.specifiers?.length !== 1
          || node.specifiers[0].type !== "ImportDefaultSpecifier"
        ) {
          recordCapability(specifier);
        } else {
          rootBindings.set(node.specifiers[0].local.name, "process");
        }
      }
      if (specifier === "node:vm") {
        if (
          entry.path !== "web/scripts/bootstrap-retirement.test.mjs"
          || node.specifiers?.length !== 1
          || node.specifiers[0].type !== "ImportDefaultSpecifier"
          || node.specifiers[0].local.name !== "vm"
        ) {
          recordCapability(specifier);
        } else {
          rootBindings.set("vm", "vm");
        }
      }
    }
  }
  registerModuleBindings();
  function visit(node, parent = null) {
    if (!node || typeof node !== "object") return;
    if (declaresUrlBinding(node)) recordCapability("URL");
    if (
      node.type === "ImportDeclaration"
      || node.type === "ExportAllDeclaration"
      || (node.type === "ExportNamedDeclaration" && node.source)
    ) {
      const attributes = [
        ...(Array.isArray(node.attributes) ? node.attributes : []),
        ...(Array.isArray(node.assertions) ? node.assertions : []),
      ];
      requests.push({
        specifier: node.source?.value,
        attributes: attributes.length ? { unsupported: true } : {},
        phase: "evaluation",
      });
      if (new Set([
        "module",
        "node:module",
        "node:worker_threads",
        "worker_threads",
      ])
        .has(node.source?.value)) {
        recordCapability(node.source.value);
      }
      if (
        node.type !== "ImportDeclaration"
        && new Set(["node:process", "node:vm"]).has(node.source?.value)
      ) {
        recordCapability(node.source.value);
      }
    } else if (node.type === "ImportExpression") {
      runtimeRequests.push({
        kind: "dynamic_import",
        literal: node.source?.type === "Literal"
          && typeof node.source.value === "string",
        specifier: node.source?.type === "Literal"
          && typeof node.source.value === "string"
          ? node.source.value
          : null,
      });
    }
    const exactMiddlewareRequestUrl = isExactAllowedMiddlewareRequestUrl(node);
    if (exactMiddlewareRequestUrl) {
      allowedGlobalUrlReferences.add(node.callee);
    }
    const importMetaUrlTuple = node.type === "NewExpression"
      && node.callee?.type === "Identifier"
      && node.callee.name === "URL"
      && node.arguments?.length === 2
      && isImportMetaUrl(node.arguments[1]);
    if (importMetaUrlTuple) {
      const literalSpecifier = node.arguments[0]?.type === "Literal"
        && typeof node.arguments[0].value === "string";
      allowedGlobalUrlReferences.add(node.callee);
      allowedImportMetaProperties.add(node.arguments[1].object);
      resourceRequests.push({
        kind: "import_meta_url",
        literal: literalSpecifier,
        specifier: literalSpecifier ? node.arguments[0].value : null,
      });
    }
    if (
      isImportMeta(node)
      && !allowedImportMetaProperties.has(node)
    ) {
      recordCapability("import.meta");
    }
    if (
      node.type === "Identifier"
      && node.name === "URL"
      && identifierIsReference(node, parent)
      && !allowedGlobalUrlReferences.has(node)
    ) {
      recordCapability("URL");
    }
    if (
      (node.type === "MemberExpression"
        || node.type === "OptionalMemberExpression")
      && memberCapability(node)
      && !(
        memberCapability(node) === "vm.runInNewContext"
        && parent?.callee === node
        && isExactAllowedVmCall(parent)
      )
    ) {
      recordCapability();
    }
    if (
      node.type === "Property"
      && parent?.type === "ObjectPattern"
      && forbiddenMemberCapabilities.has(patternPropertyName(node))
    ) {
      recordCapability();
    }
    if (
      node.type === "Identifier"
      && directCapabilities.has(node.name)
      && identifierIsReference(node, parent)
    ) {
      recordCapability();
    }
    if (
      node.type === "Identifier"
      && rootBindings.has(node.name)
      && identifierIsReference(node, parent)
      && !rootReferenceIsQualified(node, parent)
    ) {
      recordCapability();
    }
    if (
      (node.type === "CallExpression" || node.type === "NewExpression")
      && !isExactAllowedVmCall(node)
    ) {
      const callee = unwrap(node.callee);
      if (callee?.type === "Identifier" && directCapabilities.has(callee.name)) {
        recordCapability();
      }
      if (
        (callee?.type === "MemberExpression"
          || callee?.type === "OptionalMemberExpression")
        && memberCapability(callee)
      ) {
        recordCapability();
      }
      if (isUnsafeDescriptorLookup(node)) recordCapability();
    }
    for (const [key, value] of Object.entries(node)) {
      if (key === "start" || key === "end" || key === "loc") continue;
      if (Array.isArray(value)) {
        for (const child of value) visit(child, node);
      } else if (value && typeof value === "object") {
        visit(value, node);
      }
    }
  }
  visit(ast);
  return {
    path: entry.path,
    requests,
    resource_requests: resourceRequests,
    runtime_requests: runtimeRequests,
  };
});
process.stdout.write(JSON.stringify(output));
`;

function parseStaticModuleRequests(modules) {
  for (const module of modules) {
    const source = module.bytes.toString("utf8");
    if (!Buffer.from(source, "utf8").equals(module.bytes)) {
      throw new Error("Cloudflare external module source is not canonical UTF-8");
    }
  }
  const input = modules.map((module) => ({
    path: module.path,
    base64: module.bytes.toString("base64"),
  }));
  const parsed = spawnSync(
    process.execPath,
    [
      "--no-warnings",
      "--expose-internals",
      "--input-type=module",
      "-e",
      MODULE_PARSER_SOURCE,
    ],
    {
      input: JSON.stringify(input),
      encoding: "utf8",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        NODE_NO_WARNINGS: "1",
      },
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: 16 * 1024 * 1024,
      timeout: 15_000,
    },
  );
  if (parsed.error || parsed.status !== 0 || parsed.signal || parsed.stderr) {
    throw new Error("Cloudflare external module closure could not be parsed safely");
  }
  let value;
  try {
    value = JSON.parse(parsed.stdout);
  } catch {
    throw new Error("Cloudflare external module parser returned invalid output");
  }
  if (!Array.isArray(value) || value.length !== modules.length) {
    throw new Error("Cloudflare external module parser returned an incomplete graph");
  }
  const moduleRequests = new Map();
  const resourceRequests = new Map();
  for (let index = 0; index < value.length; index += 1) {
    const entry = exactKeys(
      value[index],
      ["path", "requests", "resource_requests", "runtime_requests"],
      "Cloudflare parsed module",
    );
    if (
      entry.path !== modules[index].path
      || moduleRequests.has(entry.path)
      || !Array.isArray(entry.requests)
      || !Array.isArray(entry.resource_requests)
      || !Array.isArray(entry.runtime_requests)
    ) {
      throw new Error("Cloudflare external module parser reordered or duplicated the graph");
    }
    const requests = entry.requests.map((request) => {
      const normalized = exactKeys(
        request,
        ["attributes", "phase", "specifier"],
        "Cloudflare parsed module request",
      );
      if (
        typeof normalized.specifier !== "string"
        || normalized.phase !== "evaluation"
        || !normalized.attributes
        || typeof normalized.attributes !== "object"
        || Array.isArray(normalized.attributes)
        || Object.keys(normalized.attributes).length !== 0
      ) {
        throw new Error("Cloudflare external module request is nonliteral or attributed");
      }
      return normalized.specifier;
    });
    const resources = entry.resource_requests.map((request) => {
      const normalized = exactKeys(
        request,
        ["kind", "literal", "specifier"],
        "Cloudflare parsed resource request",
      );
      if (
        normalized.kind !== "import_meta_url"
        || normalized.literal !== true
        || typeof normalized.specifier !== "string"
      ) {
        throw new Error("Cloudflare resource request is nonliteral or unsupported");
      }
      return normalized;
    });
    for (const request of entry.runtime_requests) {
      const normalized = exactKeys(
        request,
        ["kind", "literal", "specifier"],
        "Cloudflare parsed runtime module request",
      );
      if (
        !new Set([
          "dynamic_import",
          "commonjs_require",
          "runtime_module_capability",
        ]).has(normalized.kind)
        || typeof normalized.literal !== "boolean"
        || (
          normalized.literal
          && typeof normalized.specifier !== "string"
        )
        || (!normalized.literal && normalized.specifier !== null)
      ) {
        throw new Error("Cloudflare runtime module parser returned an invalid request");
      }
    }
    if (entry.runtime_requests.length) {
      throw new Error(
        `Cloudflare external module closure refuses dynamic import or CommonJS require in any consumer: ${entry.path}`,
      );
    }
    moduleRequests.set(entry.path, requests);
    resourceRequests.set(entry.path, resources);
  }
  return Object.freeze({ moduleRequests, resourceRequests });
}

const STATIC_SPECIFIER_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;

function classifyStaticModuleSpecifier(specifier, {
  allowedBarePackages,
  allowedNodeBuiltins,
  label,
  allowRelativeSuffix = false,
}) {
  if (
    typeof specifier !== "string"
    || specifier.length < 1
    || specifier.includes("\0")
    || specifier.includes("\\")
  ) {
    throw new Error(`${label} contains an invalid static module specifier`);
  }
  if (specifier.startsWith(".")) {
    if (
      !allowRelativeSuffix
      && (specifier.includes("?") || specifier.includes("#"))
    ) {
      throw new Error(`${label} contains a suffixed relative module specifier`);
    }
    return "relative";
  }
  if (specifier.startsWith("/") || specifier.startsWith("//")) {
    throw new Error(`${label} contains an absolute static module specifier`);
  }
  if (STATIC_SPECIFIER_SCHEME.test(specifier)) {
    if (
      specifier.startsWith("node:")
      && allowedNodeBuiltins.has(specifier)
    ) {
      return "node";
    }
    throw new Error(`${label} contains an unsupported or unaudited URI module specifier`);
  }
  if (allowedBarePackages.has(specifier)) return "bare";
  throw new Error(`${label} contains an unaudited bare package import`);
}

function resolveRelativeModule(importer, specifier) {
  if (
    specifier.includes("\\")
    || specifier.includes("?")
    || specifier.includes("#")
  ) {
    throw new Error("Cloudflare external module request is not a canonical file specifier");
  }
  const resolved = path.posix.normalize(path.posix.join(
    path.posix.dirname(importer),
    specifier,
  ));
  if (
    resolved === ".."
    || resolved.startsWith("../")
    || !resolved.endsWith(".mjs")
  ) {
    throw new Error("Cloudflare external module request escapes or is not an exact module");
  }
  return resolved;
}

function assertPrivilegedNodeImporter(importer, specifier, policy, label) {
  if (!Object.hasOwn(policy, specifier)) return;
  if (!policy[specifier].includes(importer)) {
    throw new Error(`${label} grants ${specifier} only to its exact reviewed importers`);
  }
}

function assertExactExternalModuleGraph(moduleRequests) {
  const graphPaths = [
    ...MODULE_CLOSURE_PATHS,
    ...MODULE_WEB_BACKEDGE_PATHS,
  ];
  const allowed = new Set(graphPaths);
  const allowedBarePackages = new Set(MODULE_BARE_PACKAGE_IMPORTS);
  const allowedNodeBuiltins = new Set(MODULE_NODE_BUILTIN_IMPORTS);
  const discoveredBarePackages = new Set();
  const discoveredNodeBuiltins = new Set();
  const graph = new Map();
  for (const modulePath of graphPaths) {
    const requests = moduleRequests.get(modulePath);
    if (!requests) {
      throw new Error("Cloudflare external module graph is missing a closure file");
    }
    const edges = [];
    for (const specifier of requests) {
      const kind = classifyStaticModuleSpecifier(specifier, {
        allowedBarePackages,
        allowedNodeBuiltins,
        label: "Cloudflare external module graph",
      });
      if (kind === "node") {
        discoveredNodeBuiltins.add(specifier);
        assertPrivilegedNodeImporter(
          modulePath,
          specifier,
          MODULE_PRIVILEGED_NODE_IMPORTERS,
          "Cloudflare external module graph",
        );
        continue;
      }
      if (kind === "bare") {
        discoveredBarePackages.add(specifier);
        continue;
      }
      const resolved = resolveRelativeModule(modulePath, specifier);
      if (!allowed.has(resolved)) {
        throw new Error(
          `Cloudflare external module graph contains an undeclared import or web back-edge: ${modulePath} -> ${resolved}`,
        );
      }
      edges.push(resolved);
    }
    graph.set(modulePath, [...new Set(edges)].sort(compareCanonical));
  }

  const reached = new Set();
  const visiting = new Set();
  function visit(modulePath) {
    if (visiting.has(modulePath)) {
      throw new Error("Cloudflare external module graph contains a cycle");
    }
    if (reached.has(modulePath)) return;
    visiting.add(modulePath);
    for (const dependency of graph.get(modulePath) || []) visit(dependency);
    visiting.delete(modulePath);
    reached.add(modulePath);
  }
  for (const entrypoint of MODULE_ENTRYPOINT_PATHS) visit(entrypoint);
  if (
    reached.size !== graphPaths.length
    || graphPaths.some((modulePath) => !reached.has(modulePath))
  ) {
    throw new Error("Cloudflare external module allowlist contains an unreachable extra");
  }
  if (
    discoveredBarePackages.size !== allowedBarePackages.size
    || [...allowedBarePackages].some(
      (specifier) => !discoveredBarePackages.has(specifier),
    )
  ) {
    throw new Error("Cloudflare external package allowlist contains an unreachable extra");
  }
  if (
    discoveredNodeBuiltins.size !== allowedNodeBuiltins.size
    || [...allowedNodeBuiltins].some(
      (specifier) => !discoveredNodeBuiltins.has(specifier),
    )
  ) {
    throw new Error("Cloudflare external Node builtin allowlist contains an unreachable extra");
  }
}

function resolveConsumerSpecifier(consumer, specifier) {
  const withoutQuery = specifier.split(/[?#]/, 1)[0];
  return path.posix.normalize(path.posix.join(
    path.posix.dirname(consumer),
    withoutQuery,
  ));
}

function assertExactWebScriptEntrypoints(moduleRequests, webModulePaths) {
  const discovered = new Set();
  const expected = new Set(MODULE_ENTRYPOINT_PATHS);
  const allowedWebModules = new Set(webModulePaths);
  const allowedBarePackages = new Set(WEB_MODULE_BARE_PACKAGE_IMPORTS);
  const allowedNodeBuiltins = new Set(WEB_MODULE_NODE_BUILTIN_IMPORTS);
  for (const consumer of webModulePaths) {
    const requests = moduleRequests.get(consumer) || [];
    for (const specifier of requests) {
      const kind = classifyStaticModuleSpecifier(specifier, {
        allowedBarePackages,
        allowedNodeBuiltins,
        label: "Cloudflare web module",
      });
      if (kind === "node") {
        assertPrivilegedNodeImporter(
          consumer,
          specifier,
          WEB_MODULE_PRIVILEGED_NODE_IMPORTERS,
          "Cloudflare web module",
        );
        continue;
      }
      if (kind !== "relative") continue;
      const resolved = resolveConsumerSpecifier(consumer, specifier);
      if (resolved.startsWith("web/")) {
        if (!allowedWebModules.has(resolved)) {
          throw new Error("Cloudflare web module contains a relative import outside the enumerated module set");
        }
        continue;
      }
      if (!expected.has(resolved)) {
        throw new Error("Cloudflare web script contains an undeclared external import");
      }
      discovered.add(resolved);
    }
  }
  if (
    discovered.size !== expected.size
    || [...expected].some((modulePath) => !discovered.has(modulePath))
  ) {
    const missing = [...expected]
      .filter((modulePath) => !discovered.has(modulePath))
      .sort(compareCanonical);
    throw new Error(
      `Cloudflare external module entrypoints do not match web consumers; missing: ${missing.join(",")}`,
    );
  }
}

const TYPESCRIPT_PARSER_RUNTIME_PATH = fileURLToPath(new URL(
  "../node_modules/typescript/lib/typescript.js",
  import.meta.url,
));
const TYPESCRIPT_PARSER_RUNTIME_BYTES = 9_112_572;
const TYPESCRIPT_PARSER_RUNTIME_SHA256 =
  "3ae902c92cc44dace175c0e69e13a4b0899f6983c6121d76b9ab8dd5795e7675";

function assertPinnedTypeScriptParserBytes(bytes) {
  if (
    !Buffer.isBuffer(bytes)
    || bytes.length !== TYPESCRIPT_PARSER_RUNTIME_BYTES
    || createHash("sha256").update(bytes).digest("hex")
      !== TYPESCRIPT_PARSER_RUNTIME_SHA256
  ) {
    throw new Error("Cloudflare TypeScript parser runtime bytes do not match the reviewed pin");
  }
  return bytes;
}

function resolveEnumeratedWebSpecifier(consumer, specifier, enumeratedTargets) {
  if (
    typeof specifier !== "string"
    || specifier.includes("#")
    || specifier.includes("%")
    || specifier.includes("\\")
    || (specifier.match(/\?/g) || []).length > 1
  ) {
    throw new Error("Cloudflare web source contains a noncanonical relative specifier");
  }
  const queryIndex = specifier.indexOf("?");
  const requestPath = queryIndex < 0 ? specifier : specifier.slice(0, queryIndex);
  const query = queryIndex < 0 ? "" : specifier.slice(queryIndex);
  if (!new Set(["", "?inline", "?raw"]).has(query)) {
    throw new Error("Cloudflare web source contains an unsupported import query");
  }
  const base = path.posix.normalize(path.posix.join(
    path.posix.dirname(consumer),
    requestPath,
  ));
  if (
    !requestPath.startsWith(".")
    || base === "."
    || base === ".."
    || base.startsWith("../")
    || base.endsWith("/")
  ) {
    throw new Error("Cloudflare web source relative specifier escapes its graph");
  }
  const exact = enumeratedTargets.has(base) ? [base] : [];
  const inferred = exact.length || path.posix.extname(base)
    ? []
    : [
      ...[".ts", ".tsx", ".js", ".jsx", ".mjs", ".json"].map(
        (extension) => `${base}${extension}`,
      ),
      ...[".ts", ".tsx", ".js", ".jsx", ".mjs"].map(
        (extension) => `${base}/index${extension}`,
      ),
    ].filter((candidate) => enumeratedTargets.has(candidate));
  const matches = exact.length ? exact : inferred;
  if (matches.length !== 1) {
    throw new Error("Cloudflare web source relative target is missing or ambiguous in the enumerated graph");
  }
  if (query === "?inline" && path.posix.extname(matches[0]) !== ".css") {
    throw new Error("Cloudflare web source inline query is limited to CSS");
  }
  return Object.freeze({ query, target: matches[0] });
}

async function readPinnedTypeScriptParserBytes() {
  if (await realpath(TYPESCRIPT_PARSER_RUNTIME_PATH)
    !== TYPESCRIPT_PARSER_RUNTIME_PATH) {
    throw new Error("Cloudflare TypeScript parser runtime path is aliased");
  }
  const named = await lstat(TYPESCRIPT_PARSER_RUNTIME_PATH, { bigint: true });
  const expectedUid = typeof process.geteuid === "function"
    ? BigInt(process.geteuid())
    : named.uid;
  const mode = Number(named.mode & 0o777n);
  if (
    !named.isFile()
    || named.isSymbolicLink()
    || named.nlink !== 1n
    || named.uid !== expectedUid
    || !safeMode(mode)
    || named.size !== BigInt(TYPESCRIPT_PARSER_RUNTIME_BYTES)
  ) {
    throw new Error("Cloudflare TypeScript parser runtime is not the exact bounded owner-controlled file");
  }
  const handle = await open(
    TYPESCRIPT_PARSER_RUNTIME_PATH,
    constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
  );
  try {
    const before = await handle.stat({ bigint: true });
    for (const field of ["dev", "ino", "size", "nlink", "uid", "gid", "mode"]) {
      if (before[field] !== named[field]) {
        throw new Error("Cloudflare TypeScript parser runtime changed while opening");
      }
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    for (const field of [
      "dev", "ino", "size", "nlink", "uid", "gid", "mode", "mtimeNs", "ctimeNs",
    ]) {
      if (before[field] !== after[field]) {
        throw new Error("Cloudflare TypeScript parser runtime changed during its stable read");
      }
    }
    return assertPinnedTypeScriptParserBytes(bytes);
  } finally {
    await handle.close();
  }
}

const TYPESCRIPT_MODULE_PARSER_SOURCE = String.raw`
import fs from "node:fs";
import * as crypto from "node:crypto";
import * as inspector from "node:inspector";
import * as os from "node:os";
import * as path from "node:path";
import * as performanceHooks from "node:perf_hooks";
import vm from "node:vm";
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const typescriptSource = Buffer.from(input.typescript_base64, "base64").toString("utf8");
const allowedRequires = new Map([
  ["crypto", crypto],
  ["fs", fs],
  ["inspector", inspector],
  ["os", os],
  ["path", path],
  ["perf_hooks", performanceHooks],
]);
function exactRequire(specifier) {
  if (!allowedRequires.has(specifier)) {
    throw new Error("TypeScript parser requested an unaudited runtime module");
  }
  return allowedRequires.get(specifier);
}
const typescriptModule = { exports: {} };
const compileTypeScript = vm.compileFunction(
  typescriptSource,
  ["exports", "require", "module", "__filename", "__dirname"],
  { filename: "/dnai/pinned/typescript.js" },
);
compileTypeScript(
  typescriptModule.exports,
  exactRequire,
  typescriptModule,
  "/dnai/pinned/typescript.js",
  "/dnai/pinned",
);
const ts = typescriptModule.exports;
const output = input.modules.map((entry) => {
  const source = Buffer.from(entry.base64, "base64").toString("utf8");
  const extension = entry.path.slice(entry.path.lastIndexOf(".")).toLowerCase();
  const scriptKind = extension === ".tsx"
    ? ts.ScriptKind.TSX
    : extension === ".jsx"
      ? ts.ScriptKind.JSX
      : new Set([".js", ".mjs", ".cjs"]).has(extension)
        ? ts.ScriptKind.JS
        : ts.ScriptKind.TS;
  const sourceFile = ts.createSourceFile(
    entry.path,
    source,
    ts.ScriptTarget.Latest,
    true,
    scriptKind,
  );
  const requests = [];
  const violations = [];
  const directCapabilities = new Set([
    "AsyncFunction",
    "AsyncGeneratorFunction",
    "Function",
    "GeneratorFunction",
    "SharedWorker",
    "SourceTextModule",
    "SyntheticModule",
    "Worker",
    "compileFunction",
    "createRequire",
    "eval",
    "getBuiltinModule",
    "importScripts",
    "require",
  ]);
  const forbiddenMemberCapabilities = new Set([
    "AsyncFunction",
    "AsyncGeneratorFunction",
    "Function",
    "GeneratorFunction",
    "SharedWorker",
    "SourceTextModule",
    "SyntheticModule",
    "Worker",
    "compileFunction",
    "construct",
    "constructor",
    "createRequire",
    "eval",
    "getBuiltinModule",
    "importActual",
    "importMock",
    "importScripts",
    "mainModule",
    "register",
    "registerHooks",
    "require",
    "unstable_mockModule",
  ]);
  const safeGlobalThisMembers = new Set(["crypto", "fetch"]);
  const capabilityRoots = new Set([
    "global",
    "module",
    "process",
    "Reflect",
  ]);
  const browserGlobalRoots = new Set([
    "document",
    "navigator",
    "self",
    "window",
  ]);
  const bootstrapBrowserMembers = new Map([
    ["document", new Set(["documentElement"])],
    ["navigator", new Set(["serviceWorker"])],
    ["self", new Set()],
    ["window", new Set(["location"])],
  ]);
  const bootstrapGlobalIdentifiers = new Set([
    "Promise",
    "URL",
    "document",
    "navigator",
    "window",
  ]);
  function recordViolation(node, reason) {
    const position = typeof node?.getStart === "function"
      ? node.getStart(sourceFile, false)
      : -1;
    violations.push(reason + "@" + String(position));
  }
  function unwrap(expression) {
    let current = expression;
    while (
      current
      && (
        ts.isParenthesizedExpression(current)
        || ts.isAsExpression(current)
        || ts.isTypeAssertionExpression(current)
        || ts.isNonNullExpression(current)
        || ts.isSatisfiesExpression(current)
        || ts.isAwaitExpression(current)
      )
    ) {
      current = current.expression;
    }
    return current;
  }
  function staticString(expression) {
    const current = unwrap(expression);
    if (!current) return null;
    if (ts.isStringLiteralLike(current)) return current.text;
    if (
      ts.isBinaryExpression(current)
      && current.operatorToken.kind === ts.SyntaxKind.PlusToken
    ) {
      const left = staticString(current.left);
      const right = staticString(current.right);
      return typeof left === "string" && typeof right === "string"
        ? left + right
        : null;
    }
    if (
      ts.isBinaryExpression(current)
      && current.operatorToken.kind === ts.SyntaxKind.CommaToken
    ) {
      return staticString(current.right);
    }
    return null;
  }
  function memberName(node) {
    if (ts.isPropertyAccessExpression(node)) return node.name.text;
    if (ts.isElementAccessExpression(node)) {
      return staticString(node.argumentExpression);
    }
    return null;
  }
  function bindingPropertyName(node) {
    if (!ts.isBindingElement(node) || !node.propertyName) return null;
    if (ts.isIdentifier(node.propertyName) || ts.isStringLiteralLike(node.propertyName)) {
      return node.propertyName.text;
    }
    if (ts.isComputedPropertyName(node.propertyName)) {
      return staticString(node.propertyName.expression);
    }
    return null;
  }
  function declarationNames(name, callback) {
    if (!name) return;
    if (ts.isIdentifier(name)) {
      callback(name);
      return;
    }
    if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
      for (const element of name.elements) {
        if (ts.isBindingElement(element)) declarationNames(element.name, callback);
      }
    }
  }
  function makeScope(parent) {
    return { parent, bindings: new Map() };
  }
  function declare(scope, identifier, kind = "local") {
    if (!scope.bindings.has(identifier.text)) {
      scope.bindings.set(identifier.text, kind);
    }
  }
  function localBindingKind(identifier, initializer, declarationKind) {
    if (!directCapabilities.has(identifier.text)) return "local";
    if (
      declarationKind === "function"
      || (initializer
        && (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)))
    ) {
      return "local_callable";
    }
    return "unsafe_capability_shadow";
  }
  function declareVariableDeclaration(scope, declaration) {
    declarationNames(declaration.name, (identifier) => {
      declare(
        scope,
        identifier,
        localBindingKind(identifier, declaration.initializer, "variable"),
      );
    });
  }
  function declareImportBindings(scope, statement) {
    const clause = statement.importClause;
    if (!clause) return;
    if (clause.name) declare(scope, clause.name, "imported");
    const bindings = clause.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) {
      declare(scope, bindings.name, "imported");
    } else if (bindings && ts.isNamedImports(bindings)) {
      for (const element of bindings.elements) {
        declare(scope, element.name, "imported");
      }
    }
  }
  function predeclareStatements(scope, statements) {
    if (!statements) return;
    for (const statement of statements) {
      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          declareVariableDeclaration(scope, declaration);
        }
      } else if (ts.isFunctionDeclaration(statement) && statement.name) {
        declare(
          scope,
          statement.name,
          localBindingKind(statement.name, statement, "function"),
        );
      } else if (ts.isClassDeclaration(statement) && statement.name) {
        declare(scope, statement.name);
      } else if (ts.isImportDeclaration(statement)) {
        declareImportBindings(scope, statement);
      } else if (ts.isImportEqualsDeclaration(statement)) {
        declare(scope, statement.name, "imported");
      }
    }
  }
  function lookup(scope, name) {
    for (let current = scope; current; current = current.parent) {
      if (current.bindings.has(name)) return current.bindings.get(name);
    }
    return null;
  }
  function scopeFor(node, parentScope) {
    if (ts.isSourceFile(node) || ts.isBlock(node) || ts.isModuleBlock(node)) {
      const scope = makeScope(parentScope);
      predeclareStatements(scope, node.statements);
      return scope;
    }
    if (ts.isFunctionLike(node)) {
      const scope = makeScope(parentScope);
      if (node.name && ts.isIdentifier(node.name)) declare(scope, node.name);
      for (const parameter of node.parameters || []) {
        declarationNames(parameter.name, (identifier) => {
          declare(
            scope,
            identifier,
            directCapabilities.has(identifier.text)
              ? "unsafe_capability_shadow"
              : "local",
          );
        });
      }
      return scope;
    }
    if (ts.isCatchClause(node)) {
      const scope = makeScope(parentScope);
      if (node.variableDeclaration) {
        declarationNames(node.variableDeclaration.name, (identifier) => {
          declare(scope, identifier);
        });
      }
      return scope;
    }
    if (
      ts.isForStatement(node)
      || ts.isForInStatement(node)
      || ts.isForOfStatement(node)
    ) {
      const scope = makeScope(parentScope);
      if (node.initializer && ts.isVariableDeclarationList(node.initializer)) {
        for (const declaration of node.initializer.declarations) {
          declareVariableDeclaration(scope, declaration);
        }
      }
      return scope;
    }
    return parentScope;
  }
  function identifierIsDeclarationName(node) {
    const parent = node.parent;
    return Boolean(
      parent
      && (
        ((ts.isVariableDeclaration(parent)
          || ts.isParameter(parent)
          || ts.isBindingElement(parent)
          || ts.isFunctionDeclaration(parent)
          || ts.isFunctionExpression(parent)
          || ts.isClassDeclaration(parent)
          || ts.isClassExpression(parent)
          || ts.isImportClause(parent)
          || ts.isImportSpecifier(parent)
          || ts.isNamespaceImport(parent)
          || ts.isImportEqualsDeclaration(parent))
          && parent.name === node)
        || ((ts.isPropertyAccessExpression(parent)
          || ts.isPropertyAssignment(parent)
          || ts.isMethodDeclaration(parent)
          || ts.isPropertyDeclaration(parent)
          || ts.isPropertySignature(parent)
          || ts.isMethodSignature(parent))
          && parent.name === node)
      )
    );
  }
  function inspectIdentifier(node, scope) {
    if (!ts.isExpressionNode(node) || identifierIsDeclarationName(node)) return;
    const binding = lookup(scope, node.text);
    if (
      entry.path === "web/public/wikigen-bootstrap-v3.js"
      && binding === null
      && !bootstrapGlobalIdentifiers.has(node.text)
    ) {
      recordViolation(node, "unaudited public-bootstrap global identifier");
      return;
    }
    if (directCapabilities.has(node.text)) {
      if (binding !== "local_callable" && binding !== "local") {
        recordViolation(node, "runtime module capability identifier");
      }
      return;
    }
    if (capabilityRoots.has(node.text) && binding === null) {
      recordViolation(node, "runtime module capability root");
      return;
    }
    if (browserGlobalRoots.has(node.text) && binding === null) {
      const parent = node.parent;
      const propertyMember = parent
        && (ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent))
        && parent.expression === node
        ? memberName(parent)
        : null;
      const membershipMember = entry.path === "web/public/wikigen-bootstrap-v3.js"
        && parent
        && ts.isBinaryExpression(parent)
        && parent.operatorToken.kind === ts.SyntaxKind.InKeyword
        && parent.right === node
        ? staticString(parent.left)
        : null;
      const directMember = propertyMember ?? membershipMember;
      const bootstrapMembers = entry.path === "web/public/wikigen-bootstrap-v3.js"
        ? bootstrapBrowserMembers.get(node.text)
        : null;
      const exactBootstrapSyntax = !bootstrapMembers
        || (
          (ts.isPropertyAccessExpression(parent) && parent.expression === node)
          || membershipMember !== null
        );
      if (
        directMember === null
        || !exactBootstrapSyntax
        || (bootstrapMembers && !bootstrapMembers.has(directMember))
      ) {
        recordViolation(node, "computed or aliased browser-global capability access");
      }
      return;
    }
    if (node.text !== "globalThis" || binding !== null) return;
    const parent = node.parent;
    const directMember = parent
      && (ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent))
      && parent.expression === node
      ? memberName(parent)
      : null;
    const exactVitestFetchSpy = parent
      && ts.isCallExpression(parent)
      && parent.arguments?.[0] === node
      && parent.arguments?.length === 2
      && staticString(parent.arguments[1]) === "fetch"
      && ts.isPropertyAccessExpression(parent.expression)
      && parent.expression.name.text === "spyOn"
      && ts.isIdentifier(parent.expression.expression)
      && parent.expression.expression.text === "vi"
      && entry.path.endsWith(".test.ts");
    const exactConfigLocationSnapshot = entry.path === "web/src/config.ts"
      && directMember === "location"
      && ts.isPropertyAccessExpression(parent)
      && parent.expression === node
      && ts.isVariableDeclaration(parent.parent)
      && parent.parent.initializer === parent
      && ts.isIdentifier(parent.parent.name)
      && parent.parent.name.text === "location"
      && ts.isVariableDeclarationList(parent.parent.parent)
      && parent.parent.parent.declarations.length === 1
      && (parent.parent.parent.flags & ts.NodeFlags.Const) !== 0
      && ts.isVariableStatement(parent.parent.parent.parent)
      && !parent.parent.parent.parent.modifiers?.length;
    if (
      !safeGlobalThisMembers.has(directMember)
      && !exactVitestFetchSpy
      && !exactConfigLocationSnapshot
    ) {
      recordViolation(node, "unaudited globalThis capability access");
    }
  }
  function inspectMember(node) {
    const property = memberName(node);
    if (property === null) {
      const base = unwrap(node.expression);
      if (
        base
        && ts.isIdentifier(base)
        && new Set([
          "globalThis",
          "global",
          "module",
          "process",
          "Reflect",
          "self",
          "window",
        ])
          .has(base.text)
      ) {
        recordViolation(node, "computed runtime module capability access");
      }
      return;
    }
    if (forbiddenMemberCapabilities.has(property)) {
      recordViolation(node, "runtime module member capability");
    }
  }
  function isImportMeta(node) {
    return Boolean(
      node
      && ts.isMetaProperty(node)
      && node.keywordToken === ts.SyntaxKind.ImportKeyword
      && node.name?.text === "meta"
    );
  }
  function isImportMetaMember(node, property) {
    return Boolean(
      node
      && ts.isPropertyAccessExpression(node)
      && isImportMeta(node.expression)
      && node.name.text === property
    );
  }
  function inspectBuildResolvedExpression(node) {
    if (
      ts.isCallExpression(node)
      && (
        isImportMetaMember(node.expression, "glob")
        || isImportMetaMember(node.expression, "globEager")
      )
    ) {
      recordViolation(node, "Vite import.meta glob resolution is forbidden");
    }
    if (
      isImportMetaMember(node, "url")
    ) {
      recordViolation(node, "Vite import-meta URL asset resolution is forbidden");
    }
    if (
      ts.isModuleDeclaration(node)
      && ts.isStringLiteralLike(node.name)
    ) {
      recordViolation(node, "external string module augmentation is forbidden");
    }
  }
  function inspectReflectiveCall(node) {
    if (
      !ts.isCallExpression(node)
      || (!ts.isPropertyAccessExpression(node.expression)
        && !ts.isElementAccessExpression(node.expression))
    ) return;
    const method = memberName(node.expression);
    if (new Set([
      "getOwnPropertyDescriptors",
      "getOwnPropertyNames",
      "getOwnPropertySymbols",
      "getPrototypeOf",
    ]).has(method)) {
      recordViolation(node, "reflective constructor recovery is forbidden");
      return;
    }
    if (method !== "getOwnPropertyDescriptor" || node.arguments?.length !== 2) return;
    const property = staticString(node.arguments[1]);
    if (property === null || forbiddenMemberCapabilities.has(property)) {
      recordViolation(node, "reflective descriptor capability access is forbidden");
    }
  }
  function request(kind, expression) {
    const literal = Boolean(expression && ts.isStringLiteralLike(expression));
    requests.push({
      kind,
      literal,
      specifier: literal ? expression.text : null,
    });
  }
  function visit(node, parentScope = null) {
    const scope = scopeFor(node, parentScope);
    if (ts.isImportDeclaration(node)) {
      request("static_import", node.moduleSpecifier);
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier) {
      request("static_export", node.moduleSpecifier);
    } else if (
      ts.isCallExpression(node)
      && node.expression?.kind === ts.SyntaxKind.ImportKeyword
    ) {
      request("dynamic_import", node.arguments?.length === 1 ? node.arguments[0] : null);
    } else if (ts.isImportEqualsDeclaration(node)) {
      if (ts.isExternalModuleReference(node.moduleReference)) {
        request("import_equals", node.moduleReference.expression);
      }
      recordViolation(node, "TypeScript import-equals runtime loader is forbidden");
    } else if (ts.isImportTypeNode(node)) {
      const argument = node.argument;
      request(
        "import_type",
        ts.isLiteralTypeNode(argument) ? argument.literal : null,
      );
    }
    if (ts.isIdentifier(node)) inspectIdentifier(node, scope);
    inspectBuildResolvedExpression(node);
    inspectReflectiveCall(node);
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      inspectMember(node);
    }
    if (
      ts.isBindingElement(node)
      && forbiddenMemberCapabilities.has(bindingPropertyName(node))
    ) {
      recordViolation(node, "runtime module capability is destructured");
    }
    if (
      ts.isBinaryExpression(node)
      && new Set([
        ts.SyntaxKind.EqualsToken,
        ts.SyntaxKind.PlusEqualsToken,
        ts.SyntaxKind.MinusEqualsToken,
        ts.SyntaxKind.AsteriskEqualsToken,
        ts.SyntaxKind.SlashEqualsToken,
      ]).has(node.operatorToken.kind)
      && ts.isIdentifier(unwrap(node.left))
      && directCapabilities.has(unwrap(node.left).text)
    ) {
      recordViolation(node.left, "runtime module capability binding is reassigned");
    }
    ts.forEachChild(node, (child) => visit(child, scope));
  }
  for (const [kind, directives] of [
    ["path", sourceFile.referencedFiles],
    ["types", sourceFile.typeReferenceDirectives],
    ["lib", sourceFile.libReferenceDirectives],
    ["amd-dependency", sourceFile.amdDependencies],
  ]) {
    if (Array.isArray(directives) && directives.length) {
      violations.push("TypeScript triple-slash " + kind + " directive is forbidden@"
        + String(directives[0].pos ?? -1));
    }
  }
  if (sourceFile.hasNoDefaultLib) {
    violations.push("TypeScript no-default-lib directive is forbidden@0");
  }
  const jsxPragmas = new Set(["jsx", "jsxfrag", "jsximportsource", "jsxruntime"]);
  if (
    sourceFile.pragmas
    && [...sourceFile.pragmas.keys()].some((pragma) => jsxPragmas.has(String(pragma).toLowerCase()))
  ) {
    violations.push("TypeScript JSX resolver pragma is forbidden@0");
  }
  function inspectJsDoc(node) {
    if (ts.isJSDocImportTag(node) || ts.isImportTypeNode(node)) {
      recordViolation(node, "JSDoc import resolution is forbidden");
    }
    ts.forEachChild(node, inspectJsDoc);
  }
  function inspectAttachedJsDoc(node) {
    for (const document of node.jsDoc || []) {
      for (const tag of document.tags || []) inspectJsDoc(tag);
    }
    ts.forEachChild(node, inspectAttachedJsDoc);
  }
  inspectAttachedJsDoc(sourceFile);
  visit(sourceFile);
  return {
    path: entry.path,
    parse_error: sourceFile.parseDiagnostics.length !== 0,
    requests,
    violations,
  };
});
process.stdout.write(JSON.stringify(output));
`;

async function parseTypeScriptModuleRequests(modules) {
  for (const module of modules) {
    const source = module.bytes.toString("utf8");
    if (!Buffer.from(source, "utf8").equals(module.bytes)) {
      throw new Error("Cloudflare TypeScript source is not canonical UTF-8");
    }
  }
  const typescriptBytes = await readPinnedTypeScriptParserBytes();
  const parsed = spawnSync(
    process.execPath,
    [
      "--no-warnings",
      "--input-type=module",
      "-e",
      TYPESCRIPT_MODULE_PARSER_SOURCE,
    ],
    {
      input: JSON.stringify({
        typescript_base64: typescriptBytes.toString("base64"),
        modules: modules.map((module) => ({
          path: module.path,
          base64: module.bytes.toString("base64"),
        })),
      }),
      encoding: "utf8",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        NODE_NO_WARNINGS: "1",
      },
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: 32 * 1024 * 1024,
      // The complete release suite intentionally runs several isolated
      // parser processes in parallel. Keep this denial-of-service boundary
      // finite while allowing the pinned parser to finish on a contended
      // release host; capability and graph validation remain fail-closed.
      timeout: 120_000,
    },
  );
  if (parsed.error || parsed.status !== 0 || parsed.signal || parsed.stderr) {
    throw new Error("Cloudflare TypeScript module graph could not be parsed safely");
  }
  let value;
  try {
    value = JSON.parse(parsed.stdout);
  } catch {
    throw new Error("Cloudflare TypeScript module parser returned invalid output");
  }
  if (!Array.isArray(value) || value.length !== modules.length) {
    throw new Error("Cloudflare TypeScript module parser returned an incomplete graph");
  }
  const result = new Map();
  for (let index = 0; index < value.length; index += 1) {
    const entry = exactKeys(
      value[index],
      ["parse_error", "path", "requests", "violations"],
      "Cloudflare parsed TypeScript module",
    );
    if (
      entry.path !== modules[index].path
      || result.has(entry.path)
      || entry.parse_error !== false
      || !Array.isArray(entry.requests)
      || !Array.isArray(entry.violations)
      || entry.violations.length !== 0
    ) {
      const violationSummary = entry.violations.length
        ? ` (${entry.violations.join(", ")})`
        : "";
      throw new Error(
        `Cloudflare TypeScript module graph is invalid or uses a runtime module capability: ${entry.path}${violationSummary}`,
      );
    }
    const requests = entry.requests.map((request) => {
      const normalized = exactKeys(
        request,
        ["kind", "literal", "specifier"],
        "Cloudflare parsed TypeScript request",
      );
      if (
        !new Set([
          "dynamic_import",
          "import_type",
          "import_equals",
          "static_export",
          "static_import",
        ]).has(normalized.kind)
        || normalized.literal !== true
        || typeof normalized.specifier !== "string"
      ) {
        throw new Error("Cloudflare TypeScript module graph contains a nonliteral module request");
      }
      return normalized;
    });
    result.set(entry.path, requests);
  }
  return result;
}

async function assertExactResourceConsumers({
  enumeratedTargets,
  moduleResourceRequests,
  sourceConsumers,
}) {
  const allowedNodeBuiltins = new Set();
  const parsedCodePaths = new Set(sourceConsumers.map((entry) => entry.path));
  const typedRequests = await parseTypeScriptModuleRequests(
    [...sourceConsumers].sort((left, right) => compareCanonical(left.path, right.path)),
  );
  const exactExternalBindings = new Set(RESOURCE_CONSUMER_BINDINGS.map((binding) => (
    `${binding.consumer}\0${binding.requestKind}\0${binding.specifier}\0${binding.query}\0${binding.externalPath}`
  )));
  if (exactExternalBindings.size !== RESOURCE_CONSUMER_BINDINGS.length) {
    throw new Error("Cloudflare external resource binding policy contains duplicates");
  }
  const observedExternalBindings = new Map(
    RESOURCE_CONSUMER_BINDINGS.map((binding) => [
      `${binding.consumer}\0${binding.requestKind}\0${binding.specifier}\0${binding.query}\0${binding.externalPath}`,
      0,
    ]),
  );
  for (const consumer of sourceConsumers.map((entry) => entry.path)) {
    const requests = typedRequests.get(consumer);
    if (!requests) {
      throw new Error("Cloudflare typed source consumer is missing from its parsed graph");
    }
    if (consumer === "web/public/wikigen-bootstrap-v3.js" && requests.length !== 0) {
      throw new Error("Cloudflare public bootstrap refuses module requests");
    }
    const config = WEB_CONFIG_MODULES[consumer];
    const allowedBarePackages = new Set(
      config ? config.barePackages : WEB_SOURCE_BARE_PACKAGE_IMPORTS,
    );
    const observedConfigPackages = [];
    for (const request of requests) {
      const kind = classifyStaticModuleSpecifier(request.specifier, {
        allowedBarePackages,
        allowedNodeBuiltins,
        label: config ? "Cloudflare web config" : "Cloudflare web source",
        allowRelativeSuffix: true,
      });
      if (kind === "bare") {
        if (config) {
          if (request.kind !== "static_import") {
            throw new Error("Cloudflare web config package request is not a static import");
          }
          observedConfigPackages.push(request.specifier);
        }
        continue;
      }
      if (kind !== "relative") continue;
      const resolved = resolveEnumeratedWebSpecifier(
        consumer,
        request.specifier,
        enumeratedTargets,
      );
      if (!resolved.target.startsWith("web/")) {
        const bindingKey = `${consumer}\0${request.kind}\0${request.specifier}\0${resolved.query}\0${resolved.target}`;
        if (!exactExternalBindings.has(bindingKey)) {
          throw new Error("Cloudflare web source contains an undeclared external resource import");
        }
        observedExternalBindings.set(
          bindingKey,
          (observedExternalBindings.get(bindingKey) || 0) + 1,
        );
      } else if (
        new Set(WEB_SOURCE_CODE_EXTENSIONS).has(path.posix.extname(resolved.target))
        && !parsedCodePaths.has(resolved.target)
      ) {
        throw new Error("Cloudflare web source code target is outside the enumerated parsed set");
      }
      if (config && !parsedCodePaths.has(resolved.target)) {
        throw new Error("Cloudflare web config relative target is outside the enumerated parsed set");
      }
    }
    if (config) {
      const actual = [...observedConfigPackages].sort(compareCanonical);
      const expected = [...config.barePackages].sort(compareCanonical);
      if (
        actual.length !== new Set(actual).size
        || JSON.stringify(actual) !== JSON.stringify(expected)
      ) {
        throw new Error("Cloudflare web config package graph is not exact");
      }
    }
  }

  for (const [consumer, requests] of moduleResourceRequests) {
    const actual = requests.map((request) => request.specifier).sort(compareCanonical);
    const expected = [...(WEB_MODULE_IMPORT_META_URLS[consumer] || [])]
      .sort(compareCanonical);
    if (
      actual.length !== new Set(actual).size
      || JSON.stringify(actual) !== JSON.stringify(expected)
    ) {
      throw new Error(`Cloudflare web module import-meta URL graph is not exact: ${consumer}`);
    }
    for (const request of requests) {
      const query = request.specifier.includes("?")
        ? request.specifier.slice(request.specifier.indexOf("?"))
        : "";
      const target = resolveConsumerSpecifier(consumer, request.specifier);
      const bindingKey = `${consumer}\0${request.kind}\0${request.specifier}\0${query}\0${target}`;
      if (exactExternalBindings.has(bindingKey)) {
        observedExternalBindings.set(
          bindingKey,
          (observedExternalBindings.get(bindingKey) || 0) + 1,
        );
      }
    }
  }
  for (const consumer of Object.keys(WEB_MODULE_IMPORT_META_URLS)) {
    if (!moduleResourceRequests.has(consumer)) {
      throw new Error(`Cloudflare reviewed import-meta URL consumer is missing: ${consumer}`);
    }
  }
  for (const [binding, count] of observedExternalBindings) {
    if (count !== 1) {
      throw new Error(`Cloudflare external resource AST binding is missing or duplicated: ${binding.split("\0", 1)[0]}`);
    }
  }
  return typedRequests;
}

function mutableProjectionAudit(files) {
  const projected = [...files.entries()]
    .sort(([left], [right]) => compareCanonical(left, right))
    .map(([filePath, file]) => ({
      mode: file.mode,
      path: filePath,
      sha256: `sha256:${createHash("sha256").update(file.bytes).digest("hex")}`,
      size: file.size,
    }));
  return domainHash(MUTABLE_PROJECTION_AUDIT_DOMAIN, { files: projected });
}

async function projectCloudflareExternalBuildClosureOnce(repoRoot) {
  const canonicalRoot = await canonicalRepositoryRoot(repoRoot);
  const projectedFiles = [];
  const sourceFiles = new Map();
  const auditedFiles = new Map();
  function audit(filePath, file) {
    if (auditedFiles.has(filePath)) {
      throw new Error("Cloudflare mutable projection read a file more than once");
    }
    auditedFiles.set(filePath, file);
  }
  let totalBytes = 0;
  for (const definition of CLOUDFLARE_EXTERNAL_BUILD_FILES) {
    const file = await readStableRepositoryFile(
      canonicalRoot,
      definition.path,
      definition.maximumBytes,
      "Cloudflare external build input",
    );
    totalBytes += file.size;
    if (totalBytes > MAX_TOTAL_BYTES) {
      throw new Error("Cloudflare external build closure exceeds its bounded total size");
    }
    sourceFiles.set(definition.path, file);
    audit(definition.path, file);
    projectedFiles.push(Object.freeze({
      kind: definition.kind,
      path: definition.path,
      mode: file.mode,
      size: file.size,
      sha256: `sha256:${createHash("sha256").update(file.bytes).digest("hex")}`,
    }));
  }

  const webScriptPaths = await collectFiles(
    canonicalRoot,
    "web/scripts",
    new Set([".mjs"]),
  );
  const webScriptFiles = [];
  for (const consumerPath of webScriptPaths) {
    const file = await readStableRepositoryFile(
      canonicalRoot,
      consumerPath,
      MAX_WEB_CONSUMER_BYTES,
      "Cloudflare web script consumer",
    );
    audit(consumerPath, file);
    webScriptFiles.push({ path: consumerPath, bytes: file.bytes });
  }
  const webStaticModuleFiles = [];
  for (const modulePath of WEB_STATIC_MODULE_PATHS) {
    const file = await readStableRepositoryFile(
      canonicalRoot,
      modulePath,
      MAX_WEB_CONSUMER_BYTES,
      "Cloudflare enumerated web module",
    );
    audit(modulePath, file);
    webStaticModuleFiles.push({ path: modulePath, bytes: file.bytes });
  }
  const webModuleFiles = [...webScriptFiles, ...webStaticModuleFiles]
    .sort((left, right) => compareCanonical(left.path, right.path));
  const webModulePaths = webModuleFiles.map((entry) => entry.path);
  const parsedRequests = parseStaticModuleRequests([
    ...MODULE_CLOSURE_PATHS.map((modulePath) => ({
      path: modulePath,
      bytes: sourceFiles.get(modulePath).bytes,
    })),
    ...webModuleFiles,
  ]);
  assertExactExternalModuleGraph(parsedRequests.moduleRequests);
  assertExactWebScriptEntrypoints(parsedRequests.moduleRequests, webModulePaths);

  const webSourcePaths = await collectFiles(
    canonicalRoot,
    "web/src",
    null,
  );
  const targetExtensions = new Set(WEB_SOURCE_TARGET_EXTENSIONS);
  const webSourceConsumers = [];
  for (const consumerPath of webSourcePaths) {
    if (!targetExtensions.has(path.posix.extname(consumerPath))) {
      throw new Error(`Cloudflare web source has an unsupported build-target extension: ${consumerPath}`);
    }
    const file = await readStableRepositoryFile(
      canonicalRoot,
      consumerPath,
      MAX_WEB_CONSUMER_BYTES,
      "Cloudflare web source consumer",
    );
    audit(consumerPath, file);
    if (path.posix.extname(consumerPath) === ".css") {
      assertClosedCssResourceGraph(file.bytes, consumerPath);
    }
    if (new Set(WEB_SOURCE_CODE_EXTENSIONS).has(path.posix.extname(consumerPath))) {
      webSourceConsumers.push({ path: consumerPath, bytes: file.bytes });
    }
  }

  const publicPaths = await collectFiles(canonicalRoot, "web/public", null);
  if (JSON.stringify(publicPaths) !== JSON.stringify(WEB_PUBLIC_PATHS)) {
    throw new Error("Cloudflare public directory contains an undeclared build input");
  }
  const publicFiles = new Map();
  for (const publicPath of publicPaths) {
    const file = await readStableRepositoryFile(
      canonicalRoot,
      publicPath,
      MAX_WEB_CONSUMER_BYTES,
      "Cloudflare public build input",
    );
    audit(publicPath, file);
    publicFiles.set(publicPath, file);
  }

  const controlFiles = new Map();
  for (const controlPath of WEB_BUILD_CONTROL_PATHS) {
    const file = await readStableRepositoryFile(
      canonicalRoot,
      controlPath,
      MAX_WEB_CONSUMER_BYTES,
      "Cloudflare web build control",
    );
    audit(controlPath, file);
    controlFiles.set(controlPath, file);
  }
  assertExactWebTsconfig(controlFiles.get("web/tsconfig.json").bytes);
  assertExactWebIndexHtml(controlFiles.get("web/index.html").bytes);
  for (const [configPath, config] of Object.entries(WEB_CONFIG_MODULES)) {
    const digest = createHash("sha256")
      .update(controlFiles.get(configPath).bytes)
      .digest("hex");
    if (digest !== config.sha256) {
      throw new Error(`Cloudflare web config semantics changed outside its reviewed pin: ${configPath}`);
    }
  }

  const auxiliaryFiles = new Map();
  for (const auxiliaryPath of WEB_AUXILIARY_SOURCE_TARGET_PATHS) {
    const file = await readStableRepositoryFile(
      canonicalRoot,
      auxiliaryPath,
      MAX_WEB_CONSUMER_BYTES,
      "Cloudflare auxiliary web source target",
    );
    audit(auxiliaryPath, file);
    auxiliaryFiles.set(auxiliaryPath, file);
  }
  const configConsumers = Object.keys(WEB_CONFIG_MODULES).map((configPath) => ({
    path: configPath,
    bytes: controlFiles.get(configPath).bytes,
  }));
  const bootstrapConsumer = {
    path: "web/public/wikigen-bootstrap-v3.js",
    bytes: publicFiles.get("web/public/wikigen-bootstrap-v3.js").bytes,
  };
  const enumeratedTargets = new Set([
    ...webSourcePaths,
    ...WEB_PUBLIC_PATHS,
    ...WEB_AUXILIARY_SOURCE_TARGET_PATHS,
    ...Object.keys(WEB_CONFIG_MODULES),
    ...CLOUDFLARE_EXTERNAL_BUILD_FILES.map((entry) => entry.path),
  ]);
  await assertExactResourceConsumers({
    enumeratedTargets,
    moduleResourceRequests: parsedRequests.resourceRequests,
    sourceConsumers: [
      ...webSourceConsumers,
      ...configConsumers,
      bootstrapConsumer,
    ],
  });
  const bootstrapSha256 = createHash("sha256")
    .update(bootstrapConsumer.bytes)
    .digest("hex");
  if (bootstrapSha256 !== WEB_PUBLIC_BOOTSTRAP_SHA256) {
    throw new Error("Cloudflare public bootstrap bytes changed outside their reviewed pin");
  }

  const entrypoints = CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS.map((entry) => ({
    kind: entry.kind,
    path: entry.path,
  }));
  const payload = aggregatePayload({ entrypoints, files: projectedFiles });
  const closure = normalizeCloudflareExternalBuildClosure({
    schema: payload.schema,
    truth_status: payload.truth_status,
    entrypoints,
    files: projectedFiles,
    aggregate_sha256: domainHash(AGGREGATE_DOMAIN, payload),
    raw_secret_egress: false,
  });
  return Object.freeze({
    auditSha256: mutableProjectionAudit(auditedFiles),
    closure,
  });
}

async function projectCloudflareExternalBuildClosureGenerations(
  repoRoot,
  betweenGenerations = null,
) {
  const first = await projectCloudflareExternalBuildClosureOnce(repoRoot);
  if (betweenGenerations) await betweenGenerations();
  const second = await projectCloudflareExternalBuildClosureOnce(repoRoot);
  if (
    first.auditSha256 !== second.auditSha256
    || canonicalCloudflareExternalBuildClosureText(first.closure)
      !== canonicalCloudflareExternalBuildClosureText(second.closure)
  ) {
    throw new Error("Cloudflare mutable source changed across complete closure projections");
  }
  return second.closure;
}

export async function projectCloudflareExternalBuildClosure(repoRoot) {
  return projectCloudflareExternalBuildClosureGenerations(repoRoot);
}

export const __test = Object.freeze({
  AGGREGATE_DOMAIN,
  assertPinnedTypeScriptParserBytes,
  MODULE_BARE_PACKAGE_IMPORTS,
  MODULE_CLOSURE_PATHS,
  MODULE_ENTRYPOINT_PATHS,
  MODULE_NODE_BUILTIN_IMPORTS,
  MODULE_PRIVILEGED_NODE_IMPORTERS,
  MODULE_WEB_BACKEDGE_PATHS,
  RECEIPT_DOMAIN,
  readStableRepositoryFile,
  RESOURCE_CONSUMER_BINDINGS,
  RESOURCE_DEFINITIONS,
  projectCloudflareExternalBuildClosureGenerations,
  WEB_CONFIG_MODULES,
  WEB_CSS_DATA_URLS,
  WEB_MODULE_IMPORT_META_URLS,
  WEB_MODULE_BARE_PACKAGE_IMPORTS,
  WEB_MODULE_NODE_BUILTIN_IMPORTS,
  WEB_MODULE_PRIVILEGED_NODE_IMPORTERS,
  WEB_SOURCE_BARE_PACKAGE_IMPORTS,
  WEB_PUBLIC_PATHS,
  WEB_PUBLIC_BOOTSTRAP_SHA256,
  WEB_STATIC_MODULE_PATHS,
  parseStaticModuleRequests,
});

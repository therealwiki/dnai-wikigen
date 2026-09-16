const FORBIDDEN_EXACT_ENVIRONMENT = new Set([
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "CF_API_KEY",
  "CF_API_TOKEN",
  "CF_PAGES_UPLOAD_JWT",
  "CLOUDFLARE_API_KEY",
  "CLOUDFLARE_API_TOKEN",
  "CLOUDFLARE_EMAIL",
  "DNAI_PORTABLE_CI_AUTHORITY",
  "GH_TOKEN",
  "GITHUB_TOKEN",
  "DYLD_INSERT_LIBRARIES",
  "LD_PRELOAD",
  "NODE_EXTRA_CA_CERTS",
  "NODE_AUTH_TOKEN",
  "NODE_OPTIONS",
  "NODE_PATH",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "NODE_USE_ENV_PROXY",
  "NPM_TOKEN",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "SSLKEYLOGFILE",
]);
const PROJECT_CREDENTIAL_PREFIX =
  /^(?:ACTIVATION|ANVIL|AWS|BASE|CF|CLOUDFLARE|COMPUTE|DEV|DILIGENCE|DOCKER|EMAIL|ESCROW|ETHERSCAN|EXECUTION|FOUNDRY|JUDGE|JWT|KMS|METERING|NEKO|OPENROUTER|ORACLE|PG|PHALA|QVL|RELEASE|ROYALTY|TELEGRAM|TINKER|VITE)_/;
const CREDENTIAL_SUFFIX =
  /(?:API_KEY|AUTH_KEY(?:_B64|_PATH)?|AUTH_TAG|AUTH_TOKEN|B64|BASE_URL(?:_SECONDARY)?|BOT_TOKEN|CLIENT_SECRET|CREDENTIALS?(?:_KEY_PATH|_SIGNING_KEY)?|INTEGRITY_KEY(?:_PATH)?|KEY(?:_B64|_FILE|_HEX|_PATH)?|KEYSTORE(?:_ACCOUNT)?|MNEMONIC|PASSWORD(?:_ADMIN)?|PRIVATE_KEY(?:_HEX)?|RPC_URL(?:_SECONDARY)?|SECRET|SIGNER_KEY_PATH|SIGNING_KEY|TOKEN)$/;

export function forbiddenPortableProfileEnvironmentNames(environment = process.env) {
  return Object.entries(environment)
    .filter(([, value]) => typeof value === "string" && value !== "")
    .map(([name]) => name)
    .filter((name) => FORBIDDEN_EXACT_ENVIRONMENT.has(name)
      || (PROJECT_CREDENTIAL_PREFIX.test(name) && CREDENTIAL_SUFFIX.test(name)))
    .sort();
}

export function assertPlainPortableTestProcess({
  argv = process.argv.slice(2),
  environment = process.env,
  execArgv = process.execArgv,
} = {}) {
  if (!Array.isArray(argv) || argv.length !== 0) {
    throw new Error("portable root test runner does not accept caller-selected entrypoints");
  }
  if (!Array.isArray(execArgv) || execArgv.length !== 0) {
    throw new Error("portable root test runner requires ordinary Node without runtime hooks");
  }
  const forbidden = forbiddenPortableProfileEnvironmentNames(environment);
  if (forbidden.length !== 0) {
    throw new Error(
      `portable root test runner rejects authority or credential environment: ${forbidden.join(",")}`,
    );
  }
  return true;
}

const isMain = (() => {
  if (!process.argv[1]) return false;
  try {
    return fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    throw new Error("portable profile entrypoint must resolve to its canonical module");
  }
})();
if (isMain) assertPlainPortableTestProcess();
import fs from "node:fs";
import { fileURLToPath } from "node:url";

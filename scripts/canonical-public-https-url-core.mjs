const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const PRIVATE_SUFFIXES = Object.freeze([
  "localhost",
  "local",
  "localdomain",
  "internal",
  "lan",
  "home.arpa",
  "onion",
  "test",
  "invalid",
  "example",
  "alt",
]);
const PATH_CHARACTER = /^[A-Za-z0-9._~!$&'()*+,;=:@/-]*$/;

function fail(label) {
  throw new TypeError(`${label} must be a canonical public HTTPS endpoint`);
}

function canonicalPath(value, label) {
  if (!value.startsWith("/")
    || !PATH_CHARACTER.test(value)
    || value.includes("//")
    || value.split("/").some((segment, index) => (
      index > 0 && (segment === "." || segment === "..")
    ))) {
    fail(label);
  }
  return value;
}

/**
 * Parse the deliberately narrow URL grammar used by signed release artifacts.
 *
 * This is not a general URL parser: it accepts only lowercase `https://`, a
 * public lowercase DNS name, an optional non-default numeric port, and an
 * already-canonical ASCII path. Credentials, IP literals, queries, fragments,
 * backslashes, dot segments, and URL-normalization ambiguities are rejected.
 */
export function parseCanonicalPublicHttpsUrl(value, {
  label = "URL",
  allowPort = false,
  requirePath = false,
  originOnly = false,
  maximumBytes = 4_096,
} = {}) {
  if (typeof value !== "string"
    || value !== value.trim()
    || value.length < 9
    || Buffer.byteLength(value, "utf8") > maximumBytes
    || /[^\x21-\x7e]/.test(value)
    || value.includes("\\")
    || value.includes("@")
    || value.includes("?")
    || value.includes("#")
    || value.includes("*")) {
    fail(label);
  }
  const match = /^https:\/\/([^/:]+)(?::([0-9]+))?(\/.*)?$/.exec(value);
  if (!match) fail(label);
  const [, hostname, rawPort, rawPath] = match;
  const labels = hostname.split(".");
  if (hostname.length > 253
    || hostname.endsWith(".")
    || /^\d+(?:\.\d+){3}$/.test(hostname)
    || labels.length < 2
    || labels.some((entry) => !DNS_LABEL.test(entry))
    || PRIVATE_SUFFIXES.some((suffix) => (
      hostname === suffix || hostname.endsWith(`.${suffix}`)
    ))) {
    fail(label);
  }
  let port = "";
  if (rawPort !== undefined) {
    const numeric = Number(rawPort);
    if (!allowPort
      || !/^[1-9][0-9]{0,4}$/.test(rawPort)
      || !Number.isSafeInteger(numeric)
      || numeric > 65_535
      || numeric === 443) {
      fail(label);
    }
    port = rawPort;
  }
  const path = rawPath === undefined ? "" : canonicalPath(rawPath, label);
  if ((requirePath && (path === "" || path === "/"))
    || (originOnly && path !== "")) {
    fail(label);
  }
  const origin = `https://${hostname}${port ? `:${port}` : ""}`;
  return Object.freeze({
    href: `${origin}${path || "/"}`,
    hostname,
    origin,
    pathname: path || "/",
    port,
  });
}

export function canonicalPublicHttpsOrigin(value, label = "URL") {
  return parseCanonicalPublicHttpsUrl(value, { label, originOnly: true }).origin;
}

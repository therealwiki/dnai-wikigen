import { isIP } from "node:net";
import { URL as NodeURL } from "node:url";

const PRIVATE_DNS_SUFFIXES = Object.freeze([
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

const RESERVED_IPV4_CIDRS = Object.freeze([
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.31.196.0", 24],
  ["192.52.193.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["192.175.48.0", 24],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
]);

const RESERVED_IPV6_CIDRS = Object.freeze([
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["3fff::", 20],
]);

function ipv4Integer(value) {
  return value.split(".").reduce(
    (result, part) => ((result << 8) | Number(part)) >>> 0,
    0,
  );
}

function ipv4InCidr(value, base, prefix) {
  const shift = 32 - prefix;
  return (ipv4Integer(value) >>> shift) === (ipv4Integer(base) >>> shift);
}

function ipv6Integer(value) {
  const halves = value.toLowerCase().split("::");
  if (halves.length > 2 || value.includes(".")) {
    throw new Error("ambiguous IPv6 literal");
  }
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const omitted = 8 - left.length - right.length;
  if (omitted < 0 || (halves.length === 1 && omitted !== 0)) {
    throw new Error("invalid IPv6 literal");
  }
  const words = [...left, ...Array(omitted).fill("0"), ...right];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) {
    throw new Error("invalid IPv6 literal");
  }
  return words.reduce(
    (result, word) => (result << 16n) | BigInt(`0x${word}`),
    0n,
  );
}

function ipv6InCidr(value, base, prefix) {
  const shift = BigInt(128 - prefix);
  return (ipv6Integer(value) >> shift) === (ipv6Integer(base) >> shift);
}

function canonicalRawHostname(raw) {
  const schemeEnd = raw.indexOf("//");
  if (schemeEnd < 0) return "";
  const authority = raw.slice(schemeEnd + 2).split(/[/?#]/, 1)[0];
  if (!authority || authority.includes("@") || authority.includes("%")) return "";
  if (authority.startsWith("[")) {
    const closing = authority.indexOf("]");
    if (closing < 0 || !/^(?:|:[0-9]+)$/.test(authority.slice(closing + 1))) return "";
    return authority.slice(1, closing);
  }
  const colon = authority.lastIndexOf(":");
  if (colon < 0) return authority;
  if (authority.indexOf(":") !== colon || !/^[0-9]+$/.test(authority.slice(colon + 1))) return "";
  return authority.slice(0, colon);
}

function isPublicIpv4(hostname, rawHostname) {
  if (rawHostname !== hostname) return false;
  return !RESERVED_IPV4_CIDRS.some(([base, prefix]) => ipv4InCidr(hostname, base, prefix));
}

function isPublicIpv6(hostname, rawHostname) {
  if (rawHostname.includes(".")) return false;
  if (!ipv6InCidr(hostname, "2000::", 3)) return false;
  return !RESERVED_IPV6_CIDRS.some(([base, prefix]) => ipv6InCidr(hostname, base, prefix));
}

function isPublicDnsHostname(hostname, rawHostname) {
  if (
    rawHostname.toLowerCase() !== hostname
    || !/^[\x21-\x7e]+$/.test(rawHostname)
    || hostname.endsWith(".")
    || hostname.length > 253
  ) return false;
  const labels = hostname.split(".");
  if (
    labels.length < 2
    || labels.some((label) => (
      !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
    ))
  ) return false;
  return !PRIVATE_DNS_SUFFIXES.some((suffix) => (
    hostname === suffix || hostname.endsWith(`.${suffix}`)
  ));
}

export function parseExactPublicHttpsUrl(value, label = "URL") {
  const raw = String(value ?? "").trim();
  if (!raw || raw.includes("*")) {
    throw new Error(`${label} must be an exact public HTTPS origin or endpoint`);
  }
  let parsed;
  try {
    parsed = new NodeURL(raw);
  } catch {
    throw new Error(`${label} must be an exact public HTTPS origin or endpoint`);
  }
  if (
    parsed.protocol !== "https:"
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
  ) {
    throw new Error(`${label} must be an exact public HTTPS origin or endpoint`);
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const rawHostname = canonicalRawHostname(raw).toLowerCase();
  const family = isIP(hostname);
  let publicHostname = false;
  try {
    publicHostname = family === 4
      ? isPublicIpv4(hostname, rawHostname)
      : family === 6
        ? isPublicIpv6(hostname, rawHostname)
        : isPublicDnsHostname(hostname, rawHostname);
  } catch {
    publicHostname = false;
  }
  if (!publicHostname) {
    throw new Error(`${label} must be an exact public HTTPS origin or endpoint`);
  }
  return parsed;
}

export function exactPublicHttpsOrigin(value, label = "URL") {
  const parsed = parseExactPublicHttpsUrl(value, label);
  if (parsed.pathname !== "/") {
    throw new Error(`${label} must be an exact public HTTPS origin`);
  }
  return parsed.origin;
}

export function exactPublicHttpsEndpoint(value, label = "URL") {
  const raw = String(value ?? "").trim();
  if (Buffer.byteLength(raw, "utf8") > 4_096) {
    throw new Error(`${label} must be a bounded exact public HTTPS endpoint`);
  }
  const parsed = parseExactPublicHttpsUrl(raw, label);
  return parsed.pathname === "/" ? parsed.origin : parsed.href;
}

export function exactDistinctPublicHttpsEndpoints(
  primaryValue,
  secondaryValue,
  {
    primaryLabel = "primary endpoint",
    secondaryLabel = "secondary endpoint",
  } = {},
) {
  const primary = exactPublicHttpsEndpoint(primaryValue, primaryLabel);
  const secondary = exactPublicHttpsEndpoint(secondaryValue, secondaryLabel);
  if (
    primary === secondary
    || new NodeURL(primary).origin.toLowerCase() === new NodeURL(secondary).origin.toLowerCase()
  ) {
    throw new Error(`${secondaryLabel} must use a different public provider origin`);
  }
  return Object.freeze({ primary, secondary });
}

export const __test = Object.freeze({
  PRIVATE_DNS_SUFFIXES,
  RESERVED_IPV4_CIDRS,
  RESERVED_IPV6_CIDRS,
});

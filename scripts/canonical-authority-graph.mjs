import { types as utilTypes } from "node:util";

const ARRAY_INDEX = /^(?:0|[1-9][0-9]*)$/;

function fail(label, reason) {
  throw new Error(`${label} is not a canonical plain-data graph: ${reason}`);
}

export function assertCanonicalPlainDataGraph(value, {
  label = "authority value",
  maximumDepth = 64,
  maximumNodes = 100_000,
} = {}) {
  const active = new WeakSet();
  const visited = new WeakSet();
  let nodes = 0;

  function visit(entry, depth) {
    if (entry === null || typeof entry === "string" || typeof entry === "boolean") {
      return;
    }
    if (typeof entry === "number") {
      if (!Number.isFinite(entry) || Object.is(entry, -0)) {
        fail(label, "numbers must be finite and must not be negative zero");
      }
      return;
    }
    if (typeof entry !== "object") {
      fail(label, "only JSON data types are allowed");
    }
    // Node's native Proxy predicate does not invoke user-controlled traps,
    // including on revoked proxies. Reject before any prototype, key, or
    // descriptor introspection so validation and later projection cannot see
    // different views of the same authority value.
    if (utilTypes.isProxy(entry)) {
      fail(label, "Proxy objects are forbidden");
    }
    if (depth > maximumDepth) fail(label, "maximum depth exceeded");
    if (active.has(entry)) fail(label, "cycles are forbidden");
    if (visited.has(entry)) return;
    nodes += 1;
    if (nodes > maximumNodes) fail(label, "maximum node count exceeded");
    if (ArrayBuffer.isView(entry) || entry instanceof ArrayBuffer
      || (typeof SharedArrayBuffer !== "undefined"
        && entry instanceof SharedArrayBuffer)) {
      fail(label, "typed, binary, or shared mutable buffers are forbidden");
    }
    const isArray = Array.isArray(entry);
    const prototype = Object.getPrototypeOf(entry);
    if (isArray ? prototype !== Array.prototype
      : prototype !== Object.prototype && prototype !== null) {
      fail(label, "custom prototypes are forbidden");
    }
    const keys = Reflect.ownKeys(entry);
    if (keys.some((key) => typeof key === "symbol")) {
      fail(label, "symbol keys are forbidden");
    }
    const descriptors = Object.getOwnPropertyDescriptors(entry);
    if (isArray) {
      const stringKeys = keys.filter((key) => key !== "length");
      if (stringKeys.length !== entry.length
        || stringKeys.some((key, index) => (
          !ARRAY_INDEX.test(key) || Number(key) !== index
        ))) {
        fail(label, "arrays must be dense and cannot have extra properties");
      }
      const lengthDescriptor = descriptors.length;
      if (!lengthDescriptor || lengthDescriptor.enumerable
        || !Object.hasOwn(lengthDescriptor, "value")) {
        fail(label, "array length descriptor is invalid");
      }
    }
    for (const key of keys) {
      if (isArray && key === "length") continue;
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable
        || !Object.hasOwn(descriptor, "value")
        || typeof descriptor.get === "function"
        || typeof descriptor.set === "function") {
        fail(label, "accessors and non-enumerable data fields are forbidden");
      }
    }
    active.add(entry);
    for (const key of keys) {
      if (isArray && key === "length") continue;
      visit(descriptors[key].value, depth + 1);
    }
    active.delete(entry);
    visited.add(entry);
  }

  visit(value, 0);
  return value;
}

export function deepFreezeCanonicalPlainDataGraph(value, options = {}) {
  assertCanonicalPlainDataGraph(value, options);
  const visited = new WeakSet();
  function freeze(entry) {
    if (!entry || typeof entry !== "object" || visited.has(entry)) return;
    visited.add(entry);
    const descriptors = Object.getOwnPropertyDescriptors(entry);
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (Array.isArray(entry) && key === "length") continue;
      freeze(descriptor.value);
    }
    Object.freeze(entry);
  }
  freeze(value);
  return value;
}

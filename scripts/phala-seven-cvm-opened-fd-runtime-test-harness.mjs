import {
  OPENED_FD_RUNTIME_AUTHORITY_MODES,
  createPinnedSevenCvmOpenedFdRuntime,
} from "./phala-seven-cvm-opened-fd-runtime-core.mjs";
import {
  PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER,
} from "./phala-seven-cvm-verifier-evidence.mjs";

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, keys, label) {
  if (!isRecord(value)) throw new Error(`${label} must contain exactly the fixture fields`);
  const prototype = Object.getPrototypeOf(value);
  const ownKeys = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if ((prototype !== Object.prototype && prototype !== null)
    || ownKeys.some((key) => typeof key !== "string")
    || JSON.stringify(ownKeys.sort()) !== JSON.stringify([...keys].sort())
    || Object.values(descriptors).some((descriptor) =>
      !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true)) {
    throw new Error(`${label} must contain exactly the fixture fields`);
  }
  return value;
}

function fixtureRuntime(options = {}) {
  const allowed = [
    "testOnlyBeforeSpawn",
    "testOnlyExtraEnvironment",
    "testOnlyHost",
    "testOnlyPaths",
  ];
  const keys = Object.keys(options);
  if (keys.some((key) => !allowed.includes(key)) || !keys.includes("testOnlyPaths")) {
    throw new Error("unsafe opened-FD fixture harness requires exact fixture paths");
  }
  const parsed = exactRecord(options, keys, "unsafe opened-FD fixture options");
  const paths = exactRecord(
    parsed.testOnlyPaths,
    ["native", "script"],
    "unsafe opened-FD fixture paths",
  );
  const host = parsed.testOnlyHost === undefined
    ? { platform: process.platform, architecture: process.arch }
    : exactRecord(
      parsed.testOnlyHost,
      ["architecture", "platform"],
      "unsafe opened-FD fixture host",
    );
  return createPinnedSevenCvmOpenedFdRuntime({
    authority: PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER,
    host,
    nativeAuthorityMode: OPENED_FD_RUNTIME_AUTHORITY_MODES.operatorOwnedFixture,
    nativePath: paths.native,
    sourcePath: paths.script,
    ...parsed.testOnlyBeforeSpawn === undefined
      ? {}
      : { beforeSpawn: parsed.testOnlyBeforeSpawn },
    ...parsed.testOnlyExtraEnvironment === undefined
      ? {}
      : { extraEnvironment: parsed.testOnlyExtraEnvironment },
  });
}

// These exports are deliberately unauthenticated test utilities. They validate
// the same pinned bytes as production but cannot alter or enter its fixed runner.
export function unsafeAssertPinnedSevenCvmOpenedFdFixtureRuntime(options) {
  return fixtureRuntime(options).assertRuntime();
}

export function unsafeProbePinnedSevenCvmOpenedFdFixtureRuntime(options) {
  return fixtureRuntime(options).probe();
}

import { getAddress, keccak256, type Address, type Hex } from "viem";
import { publicClient } from "./contract";

const BASE_SEPOLIA_CHAIN_ID = 84_532;
const ZERO_ADDRESS = `0x${"0".repeat(40)}` as Address;
const ZERO_BYTES32 = `0x${"0".repeat(64)}` as Hex;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const BYTES32 = /^0x[0-9a-fA-F]{64}$/;

export const EMAIL_ORACLE_AUTH_READ_ABI = [
  { type: "function", name: "productionRelease", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "releaseConfigurationReady", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "oracleCodeFrozen", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "consumerRegistryFrozen", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "consumerManagerAdditionsFrozen", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "kmsBindingFrozen", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "allowAnyDevice", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "pendingOwner", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "address" }] },
  { type: "function", name: "allowedOracleComposeHashCount", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "pendingOracleComposeHashCount", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "allowedDeviceIdCount", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "consumerManagerCount", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "totalConsumerComposeHashCount", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "releaseOracleComposeHash", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bytes32" }] },
  { type: "function", name: "releaseDeviceId", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bytes32" }] },
  { type: "function", name: "releaseConsumerManager", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "address" }] },
  { type: "function", name: "releaseConsumerAppId", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "address" }] },
  { type: "function", name: "releaseConsumerComposeHash", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bytes32" }] },
  { type: "function", name: "allowedOracleComposeHashes", stateMutability: "view", inputs: [{ name: "", type: "bytes32" }], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "allowedDeviceIds", stateMutability: "view", inputs: [{ name: "", type: "bytes32" }], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "consumerManagers", stateMutability: "view", inputs: [{ name: "", type: "address" }], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "consumerComposeHashCount", stateMutability: "view", inputs: [{ name: "", type: "address" }], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "isConsumerComposeHashRegistered", stateMutability: "view", inputs: [{ name: "consumerAppId", type: "address" }, { name: "composeHash", type: "bytes32" }], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "consumerEmergencyRevoked", stateMutability: "view", inputs: [{ name: "", type: "address" }], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "isConsumerAuthorized", stateMutability: "view", inputs: [{ name: "consumerAppId", type: "address" }, { name: "composeHash", type: "bytes32" }], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "kmsContract", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "address" }] },
  { type: "function", name: "kmsRuntimeCodeHash", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bytes32" }] },
  { type: "function", name: "kmsImplementation", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "address" }] },
  { type: "function", name: "kmsImplementationRuntimeCodeHash", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bytes32" }] },
  { type: "function", name: "kmsRegistrationTxHash", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bytes32" }] },
  { type: "function", name: "kmsRegistrationBlock", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint64" }] },
  { type: "function", name: "kmsRegistrationBlockHash", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bytes32" }] },
  { type: "function", name: "targetBootInfoHash", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bytes32" }] },
  { type: "function", name: "restartKeyDerivationProofHash", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "bytes32" }] },
  { type: "function", name: "pendingKmsBindingActivatesAt", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
] as const;

const DSTACK_KMS_READ_ABI = [
  {
    type: "function",
    name: "registeredApps",
    stateMutability: "view",
    inputs: [{ name: "appId", type: "address" }],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

export interface EmailOracleRelease {
  address: Address;
  runtimeCodeHash: Hex;
}

export interface EmailOracleReadinessObservation {
  chainId: number;
  blockNumber: bigint;
  blockHash: Hex;
  runtimeCodeHash: Hex;
  productionRelease: boolean;
  releaseConfigurationReady: boolean;
  oracleCodeFrozen: boolean;
  consumerRegistryFrozen: boolean;
  consumerManagerAdditionsFrozen: boolean;
  kmsBindingFrozen: boolean;
  allowAnyDevice: boolean;
  pendingOwner: Address;
  allowedOracleComposeHashCount: bigint;
  pendingOracleComposeHashCount: bigint;
  allowedDeviceIdCount: bigint;
  consumerManagerCount: bigint;
  totalConsumerComposeHashCount: bigint;
  releaseOracleComposeHash: Hex;
  releaseDeviceId: Hex;
  releaseConsumerManager: Address;
  releaseConsumerAppId: Address;
  releaseConsumerComposeHash: Hex;
  oracleComposeRegistered: boolean;
  deviceRegistered: boolean;
  consumerManagerActive: boolean;
  consumerComposeHashCount: bigint;
  consumerComposeRegistered: boolean;
  consumerEmergencyRevoked: boolean;
  consumerAuthorized: boolean;
  kmsContract: Address;
  kmsRuntimeCodeHash: Hex;
  observedKmsRuntimeCodeHash?: Hex;
  kmsImplementation: Address;
  kmsImplementationRuntimeCodeHash: Hex;
  observedKmsImplementationRuntimeCodeHash?: Hex;
  kmsRegistrationTxHash: Hex;
  kmsRegistrationBlock: bigint;
  kmsRegistrationBlockHash: Hex;
  targetBootInfoHash: Hex;
  restartKeyDerivationProofHash: Hex;
  pendingKmsBindingActivatesAt: bigint;
  kmsRegisteredApp: boolean;
}

export interface EmailOracleReadinessAssessment {
  ready: boolean;
  blockers: readonly string[];
}

function exactAddress(value: unknown, label: string): Address {
  if (typeof value !== "string" || !ADDRESS.test(value)) throw new Error(`${label} did not return an address`);
  return getAddress(value);
}

function exactBytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !BYTES32.test(value)) throw new Error(`${label} did not return bytes32`);
  return value.toLowerCase() as Hex;
}

function exactBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} did not return a boolean`);
  return value;
}

function exactBigint(value: unknown, label: string): bigint {
  if (typeof value !== "bigint" || value < 0n) throw new Error(`${label} did not return uint256`);
  return value;
}

function observedRuntimeCodeHash(bytecode: Hex | undefined, label: string): Hex {
  if (!bytecode || bytecode === "0x") throw new Error(`${label} has no runtime bytecode at the pinned block`);
  return keccak256(bytecode);
}

export function configuredEmailOracleRelease(
  address: Address | undefined,
  runtimeCodeHash: Hex | undefined,
): EmailOracleRelease {
  if (!address || !runtimeCodeHash) {
    throw new Error("EmailOracleAuth address and runtime code-hash pin are both required");
  }
  const normalizedAddress = exactAddress(address, "EmailOracleAuth address");
  const normalizedRuntimeCodeHash = exactBytes32(runtimeCodeHash, "EmailOracleAuth runtime code hash");
  if (normalizedAddress === ZERO_ADDRESS || normalizedRuntimeCodeHash === ZERO_BYTES32) {
    throw new Error("EmailOracleAuth release configuration cannot use zero values");
  }
  return { address: normalizedAddress, runtimeCodeHash: normalizedRuntimeCodeHash };
}

export function assessEmailOracleReadiness(
  observation: EmailOracleReadinessObservation,
  release: EmailOracleRelease,
): EmailOracleReadinessAssessment {
  const blockers: string[] = [];
  const require = (condition: boolean, message: string): void => {
    if (!condition) blockers.push(message);
  };

  require(observation.chainId === BASE_SEPOLIA_CHAIN_ID, "RPC chain is not Base Sepolia");
  require(observation.runtimeCodeHash.toLowerCase() === release.runtimeCodeHash.toLowerCase(), "EmailOracleAuth runtime differs from the release pin");
  require(observation.productionRelease, "contract was not constructed as a production release");
  require(observation.releaseConfigurationReady, "dynamic releaseConfigurationReady() is false");
  require(observation.oracleCodeFrozen, "oracle compose and device additions are not frozen");
  require(observation.consumerManagerAdditionsFrozen, "consumer-manager additions are not frozen");
  require(observation.consumerRegistryFrozen, "consumer registry is not frozen");
  require(observation.kmsBindingFrozen, "KMS binding is not frozen");
  require(!observation.allowAnyDevice, "broad device admission is still enabled");
  require(observation.pendingOwner === ZERO_ADDRESS, "an ownership transfer is pending");
  require(observation.allowedOracleComposeHashCount === 1n, "oracle compose membership is not exactly one");
  require(observation.pendingOracleComposeHashCount === 0n, "an oracle compose proposal is pending");
  require(observation.allowedDeviceIdCount === 1n, "device membership is not exactly one");
  require(observation.consumerManagerCount === 1n, "consumer-manager membership is not exactly one");
  require(observation.totalConsumerComposeHashCount === 1n, "consumer compose membership is not exactly one");
  require(observation.releaseOracleComposeHash !== ZERO_BYTES32 && observation.oracleComposeRegistered, "release oracle compose is absent or removed");
  require(observation.releaseDeviceId !== ZERO_BYTES32 && observation.deviceRegistered, "release device is absent or removed");
  require(observation.releaseConsumerManager !== ZERO_ADDRESS && observation.consumerManagerActive, "release consumer manager is absent or removed");
  require(observation.releaseConsumerManager.toLowerCase() === observation.releaseConsumerAppId.toLowerCase(), "release consumer is not the frozen manager");
  require(observation.releaseConsumerComposeHash !== ZERO_BYTES32 && observation.consumerComposeHashCount === 1n && observation.consumerComposeRegistered, "release consumer compose is absent or removed");
  require(!observation.consumerEmergencyRevoked, "release consumer is emergency revoked");
  require(observation.consumerAuthorized, "release consumer is not actively authorized");
  require(observation.pendingKmsBindingActivatesAt === 0n, "a KMS binding proposal is pending");
  require(observation.kmsContract !== ZERO_ADDRESS, "KMS proxy is not bound");
  require(observation.kmsImplementation !== ZERO_ADDRESS, "KMS implementation is not bound");
  require(
    Boolean(observation.observedKmsRuntimeCodeHash)
      && observation.observedKmsRuntimeCodeHash?.toLowerCase() === observation.kmsRuntimeCodeHash.toLowerCase(),
    "KMS proxy runtime differs from its frozen on-chain pin",
  );
  require(
    Boolean(observation.observedKmsImplementationRuntimeCodeHash)
      && observation.observedKmsImplementationRuntimeCodeHash?.toLowerCase() === observation.kmsImplementationRuntimeCodeHash.toLowerCase(),
    "KMS implementation runtime differs from its frozen on-chain pin",
  );
  require(observation.kmsRegisteredApp, "KMS registeredApps readback is false");
  require(
    observation.kmsRegistrationTxHash !== ZERO_BYTES32
      && observation.kmsRegistrationBlock > 0n
      && observation.kmsRegistrationBlockHash !== ZERO_BYTES32,
    "KMS registration commitment is incomplete",
  );
  require(observation.targetBootInfoHash !== ZERO_BYTES32, "target boot-info commitment is missing");
  require(observation.restartKeyDerivationProofHash !== ZERO_BYTES32, "restart key-derivation commitment is missing");

  return Object.freeze({ ready: blockers.length === 0, blockers: Object.freeze(blockers) });
}

export async function observeEmailOracleReadiness(
  rawRelease: EmailOracleRelease,
): Promise<EmailOracleReadinessObservation> {
  const release = configuredEmailOracleRelease(rawRelease.address, rawRelease.runtimeCodeHash);
  const [chainId, finalizedBlock] = await Promise.all([
    publicClient.getChainId(),
    publicClient.getBlock({ blockTag: "finalized" }),
  ]);
  if (chainId !== BASE_SEPOLIA_CHAIN_ID) throw new Error("Email Oracle readiness requires Base Sepolia (chain 84532)");
  if (finalizedBlock.number === null || !finalizedBlock.hash) throw new Error("RPC did not return a finalized block pin");
  const blockNumber = finalizedBlock.number;
  const blockHash = finalizedBlock.hash;
  const oracleBytecode = await publicClient.getBytecode({ address: release.address, blockNumber });
  const runtimeCodeHash = observedRuntimeCodeHash(oracleBytecode, "EmailOracleAuth");
  if (runtimeCodeHash.toLowerCase() !== release.runtimeCodeHash.toLowerCase()) {
    throw new Error("EmailOracleAuth runtime does not match the release code-hash pin");
  }

  const read = (functionName: typeof EMAIL_ORACLE_AUTH_READ_ABI[number]["name"], args?: readonly unknown[]) => (
    publicClient.readContract({
      address: release.address,
      abi: EMAIL_ORACLE_AUTH_READ_ABI,
      functionName,
      ...(args ? { args } : {}),
      blockNumber,
    } as never) as Promise<unknown>
  );

  const initial = await Promise.all([
    read("productionRelease"),
    read("releaseConfigurationReady"),
    read("oracleCodeFrozen"),
    read("consumerRegistryFrozen"),
    read("consumerManagerAdditionsFrozen"),
    read("kmsBindingFrozen"),
    read("allowAnyDevice"),
    read("pendingOwner"),
    read("allowedOracleComposeHashCount"),
    read("pendingOracleComposeHashCount"),
    read("allowedDeviceIdCount"),
    read("consumerManagerCount"),
    read("totalConsumerComposeHashCount"),
    read("releaseOracleComposeHash"),
    read("releaseDeviceId"),
    read("releaseConsumerManager"),
    read("releaseConsumerAppId"),
    read("releaseConsumerComposeHash"),
    read("kmsContract"),
    read("kmsRuntimeCodeHash"),
    read("kmsImplementation"),
    read("kmsImplementationRuntimeCodeHash"),
    read("kmsRegistrationTxHash"),
    read("kmsRegistrationBlock"),
    read("kmsRegistrationBlockHash"),
    read("targetBootInfoHash"),
    read("restartKeyDerivationProofHash"),
    read("pendingKmsBindingActivatesAt"),
  ]);

  const [
    productionReleaseValue,
    releaseConfigurationReadyValue,
    oracleCodeFrozenValue,
    consumerRegistryFrozenValue,
    consumerManagerAdditionsFrozenValue,
    kmsBindingFrozenValue,
    allowAnyDeviceValue,
    pendingOwnerValue,
    allowedOracleComposeHashCountValue,
    pendingOracleComposeHashCountValue,
    allowedDeviceIdCountValue,
    consumerManagerCountValue,
    totalConsumerComposeHashCountValue,
    releaseOracleComposeHashValue,
    releaseDeviceIdValue,
    releaseConsumerManagerValue,
    releaseConsumerAppIdValue,
    releaseConsumerComposeHashValue,
    kmsContractValue,
    kmsRuntimeCodeHashValue,
    kmsImplementationValue,
    kmsImplementationRuntimeCodeHashValue,
    kmsRegistrationTxHashValue,
    kmsRegistrationBlockValue,
    kmsRegistrationBlockHashValue,
    targetBootInfoHashValue,
    restartKeyDerivationProofHashValue,
    pendingKmsBindingActivatesAtValue,
  ] = initial;

  const releaseOracleComposeHash = exactBytes32(releaseOracleComposeHashValue, "releaseOracleComposeHash");
  const releaseDeviceId = exactBytes32(releaseDeviceIdValue, "releaseDeviceId");
  const releaseConsumerManager = exactAddress(releaseConsumerManagerValue, "releaseConsumerManager");
  const releaseConsumerAppId = exactAddress(releaseConsumerAppIdValue, "releaseConsumerAppId");
  const releaseConsumerComposeHash = exactBytes32(releaseConsumerComposeHashValue, "releaseConsumerComposeHash");
  const kmsContract = exactAddress(kmsContractValue, "kmsContract");
  const kmsRuntimeCodeHash = exactBytes32(kmsRuntimeCodeHashValue, "kmsRuntimeCodeHash");
  const kmsImplementation = exactAddress(kmsImplementationValue, "kmsImplementation");
  const kmsImplementationRuntimeCodeHash = exactBytes32(kmsImplementationRuntimeCodeHashValue, "kmsImplementationRuntimeCodeHash");

  const membership = await Promise.all([
    read("allowedOracleComposeHashes", [releaseOracleComposeHash]),
    read("allowedDeviceIds", [releaseDeviceId]),
    read("consumerManagers", [releaseConsumerManager]),
    read("consumerComposeHashCount", [releaseConsumerAppId]),
    read("isConsumerComposeHashRegistered", [releaseConsumerAppId, releaseConsumerComposeHash]),
    read("consumerEmergencyRevoked", [releaseConsumerAppId]),
    read("isConsumerAuthorized", [releaseConsumerAppId, releaseConsumerComposeHash]),
  ]);

  const [kmsBytecode, kmsImplementationBytecode] = await Promise.all([
    kmsContract === ZERO_ADDRESS
      ? Promise.resolve(undefined)
      : publicClient.getBytecode({ address: kmsContract, blockNumber }),
    kmsImplementation === ZERO_ADDRESS
      ? Promise.resolve(undefined)
      : publicClient.getBytecode({ address: kmsImplementation, blockNumber }),
  ]);
  const observedKmsRuntimeCodeHash = kmsBytecode && kmsBytecode !== "0x" ? keccak256(kmsBytecode) : undefined;
  const observedKmsImplementationRuntimeCodeHash = kmsImplementationBytecode && kmsImplementationBytecode !== "0x"
    ? keccak256(kmsImplementationBytecode)
    : undefined;

  let kmsRegisteredApp = false;
  if (kmsContract !== ZERO_ADDRESS && observedKmsRuntimeCodeHash) {
    try {
      kmsRegisteredApp = exactBoolean(await publicClient.readContract({
        address: kmsContract,
        abi: DSTACK_KMS_READ_ABI,
        functionName: "registeredApps",
        args: [release.address],
        blockNumber,
      }), "KMS registeredApps");
    } catch {
      kmsRegisteredApp = false;
    }
  }

  const canonicalBlock = await publicClient.getBlock({ blockNumber });
  if (!canonicalBlock.hash || canonicalBlock.hash.toLowerCase() !== blockHash.toLowerCase()) {
    throw new Error("Finalized Base Sepolia block pin changed during the readiness read");
  }

  return Object.freeze({
    chainId,
    blockNumber,
    blockHash,
    runtimeCodeHash,
    productionRelease: exactBoolean(productionReleaseValue, "productionRelease"),
    releaseConfigurationReady: exactBoolean(releaseConfigurationReadyValue, "releaseConfigurationReady"),
    oracleCodeFrozen: exactBoolean(oracleCodeFrozenValue, "oracleCodeFrozen"),
    consumerRegistryFrozen: exactBoolean(consumerRegistryFrozenValue, "consumerRegistryFrozen"),
    consumerManagerAdditionsFrozen: exactBoolean(consumerManagerAdditionsFrozenValue, "consumerManagerAdditionsFrozen"),
    kmsBindingFrozen: exactBoolean(kmsBindingFrozenValue, "kmsBindingFrozen"),
    allowAnyDevice: exactBoolean(allowAnyDeviceValue, "allowAnyDevice"),
    pendingOwner: exactAddress(pendingOwnerValue, "pendingOwner"),
    allowedOracleComposeHashCount: exactBigint(allowedOracleComposeHashCountValue, "allowedOracleComposeHashCount"),
    pendingOracleComposeHashCount: exactBigint(pendingOracleComposeHashCountValue, "pendingOracleComposeHashCount"),
    allowedDeviceIdCount: exactBigint(allowedDeviceIdCountValue, "allowedDeviceIdCount"),
    consumerManagerCount: exactBigint(consumerManagerCountValue, "consumerManagerCount"),
    totalConsumerComposeHashCount: exactBigint(totalConsumerComposeHashCountValue, "totalConsumerComposeHashCount"),
    releaseOracleComposeHash,
    releaseDeviceId,
    releaseConsumerManager,
    releaseConsumerAppId,
    releaseConsumerComposeHash,
    oracleComposeRegistered: exactBoolean(membership[0], "allowedOracleComposeHashes"),
    deviceRegistered: exactBoolean(membership[1], "allowedDeviceIds"),
    consumerManagerActive: exactBoolean(membership[2], "consumerManagers"),
    consumerComposeHashCount: exactBigint(membership[3], "consumerComposeHashCount"),
    consumerComposeRegistered: exactBoolean(membership[4], "isConsumerComposeHashRegistered"),
    consumerEmergencyRevoked: exactBoolean(membership[5], "consumerEmergencyRevoked"),
    consumerAuthorized: exactBoolean(membership[6], "isConsumerAuthorized"),
    kmsContract,
    kmsRuntimeCodeHash,
    observedKmsRuntimeCodeHash,
    kmsImplementation,
    kmsImplementationRuntimeCodeHash,
    observedKmsImplementationRuntimeCodeHash,
    kmsRegistrationTxHash: exactBytes32(kmsRegistrationTxHashValue, "kmsRegistrationTxHash"),
    kmsRegistrationBlock: exactBigint(kmsRegistrationBlockValue, "kmsRegistrationBlock"),
    kmsRegistrationBlockHash: exactBytes32(kmsRegistrationBlockHashValue, "kmsRegistrationBlockHash"),
    targetBootInfoHash: exactBytes32(targetBootInfoHashValue, "targetBootInfoHash"),
    restartKeyDerivationProofHash: exactBytes32(restartKeyDerivationProofHashValue, "restartKeyDerivationProofHash"),
    pendingKmsBindingActivatesAt: exactBigint(pendingKmsBindingActivatesAtValue, "pendingKmsBindingActivatesAt"),
    kmsRegisteredApp,
  });
}

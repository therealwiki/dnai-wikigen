#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { link, open, realpath, unlink } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  canonicalArtifactSha256,
  canonicalArtifactText,
  createDraftAuthorityReviewEnvelope,
  createDraftDeploymentIntentCore,
  describeAuthorityReviewSubjectText,
  MAX_PACKET_BYTES,
  parseAuthorityReviewEnvelopeText,
  parseDeploymentIntentCoreText,
  parseFreshContractDeploymentReceiptText,
  validationErrorDocument,
} from "./operator-policy-packet-core.mjs";

const USAGE = `Usage:
  node scripts/operator-policy-packet.mjs init-intent --out FILE
  node scripts/operator-policy-packet.mjs check-intent --in FILE [--receipt-out FILE]
  node scripts/operator-policy-packet.mjs hash-intent --in FILE
  node scripts/operator-policy-packet.mjs init-review --subject FILE --out FILE [DEPENDENCIES]
  node scripts/operator-policy-packet.mjs check-review --subject FILE --in FILE [--receipt-out FILE] [DEPENDENCIES]
  node scripts/operator-policy-packet.mjs hash-review --subject FILE --in FILE [DEPENDENCIES]

Review dependencies by subject kind:
  deployment_intent       no dependency flags
  cvm_launch_intent       --deployment-intent FILE --contract-receipt FILE
  final_release_authority --deployment-intent FILE --cvm-launch-intent FILE

Commands:
  init-intent  Create a secret-free, intentionally incomplete immutable
               pre-deployment intent draft. Existing files are never replaced.
  check-intent Validate and hash the exact canonical deployment-intent bytes.
  hash-intent  Validate, then print only the canonical deployment-intent digest.
  init-review  Bind a renewable review-envelope draft to exact canonical subject
               bytes. Subjects may be a deployment intent, CVM launch intent,
               or final authority.
  check-review Validate exact subject binding, action scope, checkpoint, review
               freshness, declaration, and reviewer separation.
  hash-review  Validate subject and envelope, then print only the envelope digest.

The checker never reads .env, unlocks a wallet, verifies signatures, performs
network requests, broadcasts, deploys, or claims TDX/deployment evidence. A
final-release-authority subject must also pass its separate authoritative
semantic validator; this CLI only canonicalizes and hashes that external core.`;

const OPERATION_ERROR_SCHEMA = "dnai.operator-policy-artifact-operation-error.v2";
const DIGEST_DOCUMENT_SCHEMA = "dnai.canonical-artifact-digest.v1";

function parseArgs(argv) {
  const [rawCommand, ...rest] = argv;
  const command = rawCommand === "--help" || rawCommand === "-h" ? "help" : rawCommand;
  const values = {
    command,
    input: "",
    output: "",
    receiptOutput: "",
    subject: "",
    deploymentIntent: "",
    contractReceipt: "",
    cvmLaunchIntent: "",
  };
  const seen = new Set();
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (![
      "--in",
      "--out",
      "--receipt-out",
      "--subject",
      "--deployment-intent",
      "--contract-receipt",
      "--cvm-launch-intent",
      "--help",
      "-h",
    ].includes(argument)) {
      throw new Error("unsupported argument; use --help");
    }
    const flag = argument === "-h" ? "--help" : argument;
    if (seen.has(flag)) throw new Error(`duplicate argument: ${flag}`);
    seen.add(flag);
    if (flag === "--help") {
      values.command = "help";
      continue;
    }
    const next = rest[index + 1];
    if (!next || next.startsWith("-")) throw new Error(`missing value for ${argument}`);
    if (argument === "--in") values.input = next;
    else if (argument === "--out") values.output = next;
    else if (argument === "--receipt-out") values.receiptOutput = next;
    else if (argument === "--subject") values.subject = next;
    else if (argument === "--deployment-intent") values.deploymentIntent = next;
    else if (argument === "--contract-receipt") values.contractReceipt = next;
    else values.cvmLaunchIntent = next;
    index += 1;
  }
  return values;
}

async function writeNewRegularFile(filePath, text) {
  if (!filePath || filePath.includes("\0")) throw new Error("output path is required");
  const resolved = path.resolve(filePath);
  const directory = path.dirname(resolved);
  if (await realpath(directory) !== directory) {
    throw new Error("output path must not contain symbolic links");
  }
  const temporary = path.join(
    directory,
    `.${path.basename(resolved)}.${process.pid}.${randomBytes(16).toString("hex")}.tmp`,
  );
  let handle;
  let published = false;
  try {
    handle = await open(temporary, "wx", 0o644);
    await handle.writeFile(text, { encoding: "utf8" });
    await handle.sync();
    await handle.close();
    handle = null;
    await link(temporary, resolved);
    published = true;
    const directoryHandle = await open(directory, constants.O_RDONLY);
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    if (published) await unlink(resolved).catch(() => {});
    throw error;
  } finally {
    await unlink(temporary).catch(() => {});
  }
  return resolved;
}

async function readBoundedRegularFile(filePath) {
  if (!filePath || filePath.includes("\0")) throw new Error("input path is required");
  const resolved = path.resolve(filePath);
  const resolvedBefore = await realpath(resolved);
  if (resolvedBefore !== resolved) {
    throw new Error("input path must not contain symbolic links");
  }
  const handle = await open(resolved, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw new Error("input must be a regular non-symlink file");
    if (before.size < 1 || before.size > MAX_PACKET_BYTES) {
      throw new Error(`input must be between 1 and ${MAX_PACKET_BYTES} bytes`);
    }
    const text = await handle.readFile("utf8");
    const after = await handle.stat();
    const resolvedAfter = await realpath(resolved);
    if (Buffer.byteLength(text, "utf8") !== before.size
      || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || before.ino !== after.ino
      || resolvedAfter !== resolvedBefore) {
      throw new Error("input changed while being read");
    }
    return { resolved, text };
  } finally {
    await handle.close();
  }
}

function operationErrorDocument(operation, message) {
  return {
    schema: OPERATION_ERROR_SCHEMA,
    status: "operation_failed",
    truthStatus: "no_deployment_or_activation_authority_created",
    operation,
    message: String(message || "operation failed").replace(/[\r\n]+/g, " ").slice(0, 240),
  };
}

function digestDocument(kind, sha256) {
  return `${JSON.stringify({
    schema: DIGEST_DOCUMENT_SCHEMA,
    kind,
    sha256,
  }, null, 2)}\n`;
}

async function publishReceipt(args, receipt, stdout) {
  const text = `${JSON.stringify(receipt, null, 2)}\n`;
  if (args.receiptOutput) await writeNewRegularFile(args.receiptOutput, text);
  stdout(text);
}

function dependencyFlagError(message) {
  return {
    ok: false,
    errors: [{ path: "$flags.review_dependencies", message }],
  };
}

async function readReviewAuthorityDependencies(args, descriptor) {
  const hasDeploymentIntent = Boolean(args.deploymentIntent);
  const hasContractReceipt = Boolean(args.contractReceipt);
  const hasCvmLaunchIntent = Boolean(args.cvmLaunchIntent);
  if (descriptor.subjectKind === "deployment_intent") {
    if (hasDeploymentIntent || hasContractReceipt || hasCvmLaunchIntent) {
      return dependencyFlagError("deployment-intent review must not accept dependency flags");
    }
    return { ok: true, authorityDependencies: undefined };
  }
  if (descriptor.subjectKind === "cvm_launch_intent") {
    if (!hasDeploymentIntent || !hasContractReceipt || hasCvmLaunchIntent) {
      return dependencyFlagError(
        "CVM-launch review requires exactly --deployment-intent and --contract-receipt",
      );
    }
  } else if (descriptor.subjectKind === "final_release_authority") {
    if (!hasDeploymentIntent || hasContractReceipt || !hasCvmLaunchIntent) {
      return dependencyFlagError(
        "final-authority review requires exactly --deployment-intent and --cvm-launch-intent",
      );
    }
  }

  let deploymentIntentText;
  try {
    deploymentIntentText = (await readBoundedRegularFile(args.deploymentIntent)).text;
  } catch (error) {
    return dependencyFlagError(`deployment-intent dependency could not be read: ${error.message}`);
  }
  const deploymentIntent = parseDeploymentIntentCoreText(deploymentIntentText);
  if (!deploymentIntent.ok) return deploymentIntent;

  if (descriptor.subjectKind === "cvm_launch_intent") {
    let receiptText;
    try {
      receiptText = (await readBoundedRegularFile(args.contractReceipt)).text;
    } catch (error) {
      return dependencyFlagError(`fresh-contract receipt dependency could not be read: ${error.message}`);
    }
    const receipt = parseFreshContractDeploymentReceiptText(receiptText, {
      expectedDeploymentIntentSha256:
        deploymentIntent.receipt.deploymentIntentSha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        deploymentIntent.intent.release.reviewerAuthorityGenesisAcceptanceSha256,
    });
    if (!receipt.ok) return receipt;
    return {
      ok: true,
      authorityDependencies: {
        deploymentIntent: deploymentIntent.intent,
        freshContractDeploymentReceipt: receipt.receipt,
      },
    };
  }

  let launchText;
  try {
    launchText = (await readBoundedRegularFile(args.cvmLaunchIntent)).text;
  } catch (error) {
    return dependencyFlagError(`CVM-launch dependency could not be read: ${error.message}`);
  }
  const launch = describeAuthorityReviewSubjectText(launchText);
  if (!launch.ok) return launch;
  if (launch.subjectKind !== "cvm_launch_intent") {
    return dependencyFlagError("--cvm-launch-intent must contain a canonical CVM launch intent");
  }
  return {
    ok: true,
    authorityDependencies: {
      deploymentIntent: deploymentIntent.intent,
      cvmLaunchIntent: launch.subject,
    },
  };
}

export async function runOperatorPolicyPacketCli(argv, io = {}) {
  const stdout = io.stdout || ((value) => process.stdout.write(value));
  const stderr = io.stderr || ((value) => process.stderr.write(value));
  let args;
  try {
    args = parseArgs(argv);
  } catch (error) {
    stderr(`${error.message}\n${USAGE}\n`);
    return 2;
  }
  if (args.command === "help" || !args.command) {
    stdout(`${USAGE}\n`);
    return args.command ? 0 : 2;
  }
  if (args.command === "init-intent") {
    if (!args.output || args.input || args.receiptOutput || args.subject
      || args.deploymentIntent || args.contractReceipt || args.cvmLaunchIntent) {
      stderr(`init-intent requires only --out FILE\n${USAGE}\n`);
      return 2;
    }
    try {
      const resolved = await writeNewRegularFile(
        args.output,
        canonicalArtifactText(createDraftDeploymentIntentCore()),
      );
      stdout(`${JSON.stringify({
        schema: "dnai.deployment-intent-draft-created.v1",
        status: "incomplete_draft_created",
        truthStatus: "no_deployment_authority_created",
        output: resolved,
      }, null, 2)}\n`);
      return 0;
    } catch (error) {
      stderr(`${error.message}\n`);
      return 1;
    }
  }
  if (args.command === "init-review") {
    if (!args.output || !args.subject || args.input || args.receiptOutput) {
      stderr(`init-review requires --subject FILE --out FILE and exact subject-kind dependencies\n${USAGE}\n`);
      return 2;
    }
    try {
      const subjectText = (await readBoundedRegularFile(args.subject)).text;
      const descriptor = describeAuthorityReviewSubjectText(subjectText);
      if (!descriptor.ok) {
        stdout(`${JSON.stringify(validationErrorDocument(descriptor.errors), null, 2)}\n`);
        return 1;
      }
      const dependencies = await readReviewAuthorityDependencies(args, descriptor);
      if (!dependencies.ok) {
        stdout(`${JSON.stringify(validationErrorDocument(dependencies.errors), null, 2)}\n`);
        return 1;
      }
      const draft = createDraftAuthorityReviewEnvelope(
        descriptor.subjectKind,
        descriptor.subjectSha256,
      );
      const resolved = await writeNewRegularFile(args.output, canonicalArtifactText(draft));
      stdout(`${JSON.stringify({
        schema: "dnai.authority-review-envelope-draft-created.v1",
        status: "incomplete_draft_created",
        truthStatus: "no_activation_authority_created",
        subjectKind: descriptor.subjectKind,
        subjectSha256: descriptor.subjectSha256,
        output: resolved,
      }, null, 2)}\n`);
      return 0;
    } catch (error) {
      stdout(`${JSON.stringify(operationErrorDocument("initialize_review", error.message), null, 2)}\n`);
      return 1;
    }
  }
  const intentCommands = new Set(["check-intent", "hash-intent"]);
  const reviewCommands = new Set(["check-review", "hash-review"]);
  if (!intentCommands.has(args.command) && !reviewCommands.has(args.command)) {
    stderr(`unknown or retired command\n${USAGE}\n`);
    return 2;
  }
  const checking = args.command.startsWith("check-");
  if (!args.input || args.output
    || (!checking && args.receiptOutput)
    || (intentCommands.has(args.command) && (
      args.subject || args.deploymentIntent || args.contractReceipt || args.cvmLaunchIntent
    ))
    || (reviewCommands.has(args.command) && !args.subject)) {
    stderr(`${args.command} received the wrong flags; use --help\n${USAGE}\n`);
    return 2;
  }
  let inputText;
  try {
    inputText = (await readBoundedRegularFile(args.input)).text;
  } catch (error) {
    stdout(`${JSON.stringify(operationErrorDocument("read_artifact", error.message), null, 2)}\n`);
    return 1;
  }
  if (intentCommands.has(args.command)) {
    const result = parseDeploymentIntentCoreText(inputText);
    if (!result.ok) {
      stdout(`${JSON.stringify(validationErrorDocument(result.errors), null, 2)}\n`);
      return 1;
    }
    if (args.command === "hash-intent") {
      stdout(digestDocument("deployment_intent", result.receipt.deploymentIntentSha256));
      return 0;
    }
    try {
      await publishReceipt(args, result.receipt, stdout);
      return 0;
    } catch (error) {
      stdout(`${JSON.stringify(operationErrorDocument("publish_receipt", error.message), null, 2)}\n`);
      return 1;
    }
  }
  let descriptor;
  try {
    const subjectText = (await readBoundedRegularFile(args.subject)).text;
    descriptor = describeAuthorityReviewSubjectText(subjectText);
  } catch (error) {
    stdout(`${JSON.stringify(operationErrorDocument("read_review_subject", error.message), null, 2)}\n`);
    return 1;
  }
  if (!descriptor.ok) {
    stdout(`${JSON.stringify(validationErrorDocument(descriptor.errors), null, 2)}\n`);
    return 1;
  }
  const dependencies = await readReviewAuthorityDependencies(args, descriptor);
  if (!dependencies.ok) {
    stdout(`${JSON.stringify(validationErrorDocument(dependencies.errors), null, 2)}\n`);
    return 1;
  }
  const result = parseAuthorityReviewEnvelopeText(inputText, {
    checkedAtMs: Date.now(),
    subjectDescriptor: descriptor,
    authorityDependencies: dependencies.authorityDependencies,
  });
  if (!result.ok) {
    stdout(`${JSON.stringify(validationErrorDocument(result.errors), null, 2)}\n`);
    return 1;
  }
  if (args.command === "hash-review") {
    stdout(digestDocument("authority_review_envelope", result.receipt.reviewEnvelopeSha256));
    return 0;
  }
  try {
    await publishReceipt(args, result.receipt, stdout);
    return 0;
  } catch (error) {
    stdout(`${JSON.stringify(operationErrorDocument("publish_receipt", error.message), null, 2)}\n`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runOperatorPolicyPacketCli(process.argv.slice(2));
}

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const OPENED_FD_DCAP_RUNTIME_AUTHORITY_SCHEMA =
  "dnai.opened-fd-dcap-runtime-authority.v1";
const OPENED_FD_DCAP_RUNTIME_AUTHORITY_DOMAIN =
  "dnai-wikigen/opened-fd-dcap-runtime-authority/v1\0";
const PYTHON_RUNTIME_TREE_DOMAIN = "dnai-wikigen/python-runtime-tree/v1\0";
const ROOT_OWNED_PRODUCTION_MODE = "root_owned_production";
const MAX_DCAP_WIRE_BYTES = 2 * 1024 * 1024;

// This label is part of the already-pinned Python bootstrap bytes. It describes
// fixture ownership only; it is not an authentication claim about node:test.
const OPERATOR_OWNED_FIXTURE_MODE = "operator_owned_node_test";

const OPENED_FD_DCAP_BOOTSTRAP = String.raw`import asyncio
import hashlib
import importlib.machinery
import importlib.util
import os
import stat
import sys
import types

def read_fd(fd, maximum):
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, min(131072, maximum + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise ValueError
        chunks.append(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return b"".join(chunks)

def write_all(fd, value):
    offset = 0
    while offset < len(value):
        written = os.write(fd, value[offset:])
        if written < 1:
            raise ValueError
        offset += written

try:
    if len(sys.argv) != 7:
        raise ValueError
    native_sha256, source_sha256, bootstrap_sha256, runtime_sha256, native_mode, barrier_path = sys.argv[1:]
    if any(len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
           for value in (native_sha256, source_sha256, bootstrap_sha256)):
        raise ValueError
    if (len(runtime_sha256) != 71 or not runtime_sha256.startswith("sha256:")
            or any(c not in "0123456789abcdef" for c in runtime_sha256[7:])):
        raise ValueError
    native_bytes = read_fd(3, 32 * 1024 * 1024)
    source_bytes = read_fd(4, 256 * 1024)
    if (hashlib.sha256(native_bytes).hexdigest() != native_sha256
            or hashlib.sha256(source_bytes).hexdigest() != source_sha256):
        raise ValueError
    native_stat = os.fstat(3)
    source_stat = os.fstat(4)
    if (not stat.S_ISREG(source_stat.st_mode)
            or source_stat.st_uid != os.geteuid()
            or source_stat.st_nlink != 1
            or source_stat.st_mode & 0o7022):
        raise ValueError
    if native_mode == "root_owned_production":
        if (not stat.S_ISREG(native_stat.st_mode)
                or native_stat.st_uid != 0 or native_stat.st_nlink != 1
                or stat.S_IMODE(native_stat.st_mode) != 0o555
                or native_stat.st_mode & 0o7000):
            raise ValueError
    elif native_mode == "operator_owned_node_test":
        if (not stat.S_ISREG(native_stat.st_mode)
                or native_stat.st_uid != os.geteuid() or native_stat.st_nlink != 1
                or native_stat.st_mode & 0o7022):
            raise ValueError
    else:
        raise ValueError

    snapshot_root = "/private/tmp"
    snapshot_root_stat = os.lstat(snapshot_root)
    if (not stat.S_ISDIR(snapshot_root_stat.st_mode)
            or stat.S_ISLNK(snapshot_root_stat.st_mode)
            or snapshot_root_stat.st_uid != 0
            or stat.S_IMODE(snapshot_root_stat.st_mode) != 0o1777):
        raise ValueError
    snapshot_directory = snapshot_root + "/dnai-dcap-" + os.urandom(32).hex()
    os.mkdir(snapshot_directory, 0o700)
    snapshot_name = snapshot_directory + "/native.abi3.so"
    snapshot_writer_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    snapshot_reader_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        snapshot_writer_flags |= os.O_NOFOLLOW
        snapshot_reader_flags |= os.O_NOFOLLOW
    snapshot_writer_fd = None
    snapshot_fd = None
    snapshot_identity = None
    try:
        snapshot_writer_fd = os.open(snapshot_name, snapshot_writer_flags, 0o700)
        write_all(snapshot_writer_fd, native_bytes)
        os.fsync(snapshot_writer_fd)
        os.fchmod(snapshot_writer_fd, 0o500)
        snapshot_writer_stat = os.fstat(snapshot_writer_fd)
        snapshot_fd = os.open(snapshot_name, snapshot_reader_flags)
        if snapshot_fd < 5 or snapshot_fd > 64:
            raise ValueError
        snapshot_stat = os.fstat(snapshot_fd)
        snapshot_identity = (
            snapshot_stat.st_dev,
            snapshot_stat.st_ino,
            snapshot_stat.st_uid,
            snapshot_stat.st_mode,
            snapshot_stat.st_size,
        )
        if (not stat.S_ISREG(snapshot_stat.st_mode)
                or snapshot_stat.st_uid != os.geteuid()
                or snapshot_stat.st_nlink != 1
                or stat.S_IMODE(snapshot_stat.st_mode) != 0o500
                or snapshot_writer_stat.st_dev != snapshot_stat.st_dev
                or snapshot_writer_stat.st_ino != snapshot_stat.st_ino
                or snapshot_writer_stat.st_size != snapshot_stat.st_size
                or hashlib.sha256(read_fd(snapshot_fd, 32 * 1024 * 1024)).hexdigest()
                != native_sha256):
            raise ValueError
        os.close(snapshot_writer_fd)
        snapshot_writer_fd = None
        os.close(3)

        if barrier_path != "-":
            if (not barrier_path.startswith("/") or len(barrier_path.encode("utf-8")) > 1024
                    or "\x00" in barrier_path):
                raise ValueError
            barrier_stat = os.lstat(barrier_path)
            if (not stat.S_ISDIR(barrier_stat.st_mode)
                    or stat.S_ISLNK(barrier_stat.st_mode)
                    or barrier_stat.st_uid != os.geteuid()
                    or stat.S_IMODE(barrier_stat.st_mode) != 0o700):
                raise ValueError
            ready_path = barrier_path + "/snapshot-ready"
            release_path = barrier_path + "/continue"
            loaded_path = barrier_path + "/snapshot-loaded"
            restored_path = barrier_path + "/original-restored"
            for handshake_path in (ready_path, release_path, loaded_path, restored_path):
                handshake_stat = os.lstat(handshake_path)
                if (not stat.S_ISFIFO(handshake_stat.st_mode)
                        or handshake_stat.st_uid != os.geteuid()
                        or handshake_stat.st_nlink != 1
                        or stat.S_IMODE(handshake_stat.st_mode) != 0o600):
                    raise ValueError
            barrier_fd = os.open(ready_path, os.O_WRONLY)
            try:
                write_all(barrier_fd, b"snapshot-ready\n")
            finally:
                os.close(barrier_fd)
            release_fd = os.open(release_path, os.O_RDONLY)
            try:
                release_stat = os.fstat(release_fd)
                if (not stat.S_ISFIFO(release_stat.st_mode)
                        or release_stat.st_uid != os.geteuid()
                        or release_stat.st_nlink != 1
                        or stat.S_IMODE(release_stat.st_mode) != 0o600
                        or os.read(release_fd, 64) != b"continue\n"
                        or os.read(release_fd, 1) != b""):
                    raise ValueError
            finally:
                os.close(release_fd)

        # Darwin's extension loader requires a linked file during exec_module.
        # The private link exists only for that load window and is removed
        # before verifier source executes. This is pathname-race mitigation,
        # not a hostile same-UID kernel boundary.
        native_path = "/dev/fd/" + str(snapshot_fd)
        package = types.ModuleType("dcap_qvl")
        package.__path__ = []
        package.__package__ = "dcap_qvl"
        sys.modules["dcap_qvl"] = package
        loader = importlib.machinery.ExtensionFileLoader(
            "dcap_qvl._dcap_qvl", native_path
        )
        spec = importlib.util.spec_from_file_location(
            "dcap_qvl._dcap_qvl", native_path, loader=loader
        )
        if spec is None or spec.loader is None:
            raise ValueError
        native = importlib.util.module_from_spec(spec)
        sys.modules["dcap_qvl._dcap_qvl"] = native
        loader.exec_module(native)
        os.unlink(snapshot_name)
        snapshot_name = None
        os.rmdir(snapshot_directory)
        snapshot_directory = None
        after_snapshot = os.fstat(snapshot_fd)
        after_identity = (
            after_snapshot.st_dev,
            after_snapshot.st_ino,
            after_snapshot.st_uid,
            after_snapshot.st_mode,
            after_snapshot.st_size,
        )
        if (after_snapshot.st_nlink != 0
                or after_identity != snapshot_identity
                or hashlib.sha256(read_fd(snapshot_fd, 32 * 1024 * 1024)).hexdigest()
                != native_sha256):
            raise ValueError

        if barrier_path != "-":
            loaded_fd = os.open(loaded_path, os.O_WRONLY)
            try:
                write_all(loaded_fd, b"snapshot-loaded\n")
            finally:
                os.close(loaded_fd)
            restored_fd = os.open(restored_path, os.O_RDONLY)
            try:
                restored_stat = os.fstat(restored_fd)
                if (not stat.S_ISFIFO(restored_stat.st_mode)
                        or restored_stat.st_uid != os.geteuid()
                        or restored_stat.st_nlink != 1
                        or stat.S_IMODE(restored_stat.st_mode) != 0o600
                        or os.read(restored_fd, 64) != b"original-restored\n"
                        or os.read(restored_fd, 1) != b""):
                    raise ValueError
            finally:
                os.close(restored_fd)

        package.parse_quote = native.parse_quote
        package.get_collateral = native.get_collateral
        package.collateral_from_json = native.PyQuoteCollateralV3.from_json
        package.verify_with_collateral = native.py_verify
        package.__version__ = "0.5.2"
        package.__native_sha256__ = native_sha256
        package.__native_snapshot_fd__ = snapshot_fd
        package.__native_snapshot_path__ = native_path
        package.__verifier_source_sha256__ = source_sha256
        package.__bootstrap_sha256__ = bootstrap_sha256
        package.__runtime_environment_sha256__ = runtime_sha256
        globals_value = {
            "__builtins__": __builtins__,
            "__file__": "/dev/fd/4",
            "__name__": "__main__",
            "__package__": None,
        }
        exec(compile(source_bytes, "/dev/fd/4", "exec"), globals_value, globals_value)
    except Exception:
        raise
    finally:
        if snapshot_writer_fd is not None:
            os.close(snapshot_writer_fd)
        if snapshot_name is not None:
            try:
                os.unlink(snapshot_name)
            except OSError:
                pass
        if snapshot_directory is not None:
            try:
                os.rmdir(snapshot_directory)
            except OSError:
                pass
except SystemExit:
    raise
except Exception:
    sys.stderr.write("opened-fd DCAP bootstrap failed safely\n")
    raise SystemExit(1)
`;

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, keys, label) {
  if (!isRecord(value)) throw new Error(`${label} must contain exactly the frozen fields`);
  const prototype = Object.getPrototypeOf(value);
  const ownKeys = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if ((prototype !== Object.prototype && prototype !== null)
    || ownKeys.some((key) => typeof key !== "string")
    || JSON.stringify(ownKeys.sort()) !== JSON.stringify([...keys].sort())
    || Object.values(descriptors).some((descriptor) =>
      !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true)) {
    throw new Error(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function compactCanonicalText(value) {
  return JSON.stringify(sorted(value));
}

export function computePythonRuntimeTreeSha256(runtimeRoot, options = {}) {
  const parsedOptions = exactRecord(options, [
    ...Object.keys(options).includes("expectedUid") ? ["expectedUid"] : [],
    ...Object.keys(options).includes("allowHardlinks") ? ["allowHardlinks"] : [],
  ], "Python runtime-tree hash options");
  const root = path.resolve(runtimeRoot);
  if (fs.realpathSync.native(root) !== root) {
    throw new Error("Python runtime root must be canonical and symlink-free");
  }
  const expectedUid = Object.hasOwn(parsedOptions, "expectedUid")
    ? parsedOptions.expectedUid
    : typeof process.geteuid === "function" ? process.geteuid() : null;
  const allowHardlinks = parsedOptions.allowHardlinks === true;
  if ((expectedUid !== null && (!Number.isSafeInteger(expectedUid) || expectedUid < 0))
    || (Object.hasOwn(parsedOptions, "allowHardlinks")
      && typeof parsedOptions.allowHardlinks !== "boolean")) {
    throw new Error("Python runtime-tree hash options are invalid");
  }
  const records = [];
  const visit = (absolute, relative) => {
    const stat = fs.lstatSync(absolute);
    if (expectedUid !== null && stat.uid !== expectedUid) {
      throw new Error("Python runtime tree contains a file owned by another user");
    }
    if ((stat.mode & 0o022) !== 0) {
      throw new Error("Python runtime tree contains group/world-writable authority");
    }
    const mode = stat.mode & 0o777;
    if (stat.isSymbolicLink()) {
      const target = fs.readlinkSync(absolute);
      const resolved = path.resolve(path.dirname(absolute), target);
      if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
        throw new Error("Python runtime symlink escapes the pinned tree");
      }
      records.push({ path: relative, type: "symlink", mode, target });
      return;
    }
    if (stat.isDirectory()) {
      records.push({ path: relative, type: "directory", mode });
      for (const name of fs.readdirSync(absolute).sort()) {
        if (!name || name === "." || name === ".." || name.includes("/")) {
          throw new Error("Python runtime tree contains an invalid entry name");
        }
        visit(path.join(absolute, name), relative === "." ? name : `${relative}/${name}`);
      }
      return;
    }
    if (!stat.isFile() || (!allowHardlinks && stat.nlink !== 1)) {
      throw new Error("Python runtime tree contains a special or multiply linked file");
    }
    const fd = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    try {
      const opened = fs.fstatSync(fd);
      if (opened.dev !== stat.dev || opened.ino !== stat.ino || opened.size !== stat.size) {
        throw new Error("Python runtime file changed while opening");
      }
      const digest = createHash("sha256");
      const buffer = Buffer.alloc(128 * 1024);
      let offset = 0;
      while (offset < opened.size) {
        const count = fs.readSync(
          fd,
          buffer,
          0,
          Math.min(buffer.length, opened.size - offset),
          offset,
        );
        if (count < 1) throw new Error("Python runtime file ended during hashing");
        digest.update(buffer.subarray(0, count));
        offset += count;
      }
      const after = fs.fstatSync(fd);
      if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size
        || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
        throw new Error("Python runtime file changed while hashing");
      }
      records.push({
        path: relative,
        type: "file",
        mode,
        size: opened.size,
        sha256: digest.digest("hex"),
      });
    } finally {
      fs.closeSync(fd);
    }
  };
  visit(root, ".");
  const digest = createHash("sha256").update(PYTHON_RUNTIME_TREE_DOMAIN, "utf8");
  for (const record of records) digest.update(`${compactCanonicalText(record)}\n`, "utf8");
  return `sha256:${digest.digest("hex")}`;
}

function bigintStatSnapshot(stat) {
  return {
    dev: stat.dev,
    ino: stat.ino,
    uid: stat.uid,
    gid: stat.gid,
    mode: stat.mode,
    nlink: stat.nlink,
    size: stat.size,
    mtimeNs: stat.mtimeNs,
    ctimeNs: stat.ctimeNs,
  };
}

function sameBigintStatSnapshot(left, right, { includeTimes = true } = {}) {
  const keys = ["dev", "ino", "uid", "gid", "mode", "nlink", "size"];
  if (includeTimes) keys.push("mtimeNs", "ctimeNs");
  return keys.every((key) => left[key] === right[key]);
}

function boundedOpenedFileSha256(fd, maximumBytes, label) {
  const before = bigintStatSnapshot(fs.fstatSync(fd, { bigint: true }));
  if (before.size < 1n || before.size > BigInt(maximumBytes)) {
    throw new Error(`${label} is outside its frozen byte bound`);
  }
  const size = Number(before.size);
  const hash = createHash("sha256");
  const buffer = Buffer.alloc(Math.min(128 * 1024, size));
  let offset = 0;
  while (offset < size) {
    const count = fs.readSync(fd, buffer, 0, Math.min(buffer.length, size - offset), offset);
    if (count < 1) throw new Error(`${label} ended during its bounded descriptor read`);
    hash.update(buffer.subarray(0, count));
    offset += count;
  }
  const after = bigintStatSnapshot(fs.fstatSync(fd, { bigint: true }));
  if (!sameBigintStatSnapshot(before, after)) {
    throw new Error(`${label} changed during its bounded descriptor read`);
  }
  return { sha256: hash.digest("hex"), snapshot: after };
}

function openAuthenticatedOperatorFile(filePath, expectedSha256, maximumBytes, label) {
  const absolute = path.resolve(filePath);
  if (absolute !== filePath || fs.realpathSync.native(absolute) !== absolute) {
    throw new Error(`${label} path must be absolute, canonical, and symlink-free`);
  }
  const expectedUid = BigInt(process.geteuid());
  const beforeStat = fs.lstatSync(absolute, { bigint: true });
  const before = bigintStatSnapshot(beforeStat);
  if (!beforeStat.isFile() || beforeStat.isSymbolicLink() || before.nlink !== 1n
    || before.uid !== expectedUid || (before.mode & 0o022n) !== 0n
    || (before.mode & 0o7000n) !== 0n) {
    throw new Error(`${label} must be a single-link operator-owned restricted regular file`);
  }
  const fd = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = bigintStatSnapshot(fs.fstatSync(fd, { bigint: true }));
    if (!sameBigintStatSnapshot(before, opened)) {
      throw new Error(`${label} changed while its descriptor was opened`);
    }
    const authenticated = boundedOpenedFileSha256(fd, maximumBytes, label);
    if (authenticated.sha256 !== expectedSha256) {
      throw new Error(`${label} bytes do not match the frozen verifier authority`);
    }
    return {
      fd,
      label,
      maximumBytes,
      sha256: authenticated.sha256,
      snapshot: authenticated.snapshot,
    };
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}

function assertOpenedFileStillAuthenticated(opened) {
  const current = boundedOpenedFileSha256(opened.fd, opened.maximumBytes, opened.label);
  if (current.sha256 !== opened.sha256
    || !sameBigintStatSnapshot(opened.snapshot, current.snapshot, { includeTimes: false })) {
    throw new Error(`${opened.label} changed after descriptor authentication`);
  }
}

function assertRootOwnedRestrictedAncestry(filePath, label) {
  let current = path.dirname(filePath);
  while (true) {
    const stat = fs.lstatSync(current, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0n
      || (stat.mode & 0o022n) !== 0n) {
      throw new Error(`${label} has mutable or non-root path ancestry`);
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

function openAuthenticatedRootOwnedFile(filePath, expectedSha256, label, {
  allowHardlinks = false,
  executable = false,
  expectedMode,
  maximumBytes = 8 * 1024 * 1024,
  missingMessage,
} = {}) {
  const absolute = path.resolve(filePath);
  let canonical;
  try {
    canonical = fs.realpathSync.native(absolute);
  } catch (error) {
    if (error?.code === "ENOENT" && missingMessage !== undefined) {
      throw new Error(missingMessage);
    }
    throw error;
  }
  if (absolute !== filePath || canonical !== absolute) {
    throw new Error(`${label} path must be canonical and symlink-free`);
  }
  if (expectedMode !== undefined
    && (!Number.isInteger(expectedMode) || expectedMode < 0 || expectedMode > 0o7777)) {
    throw new Error(`${label} expected mode is invalid`);
  }
  assertRootOwnedRestrictedAncestry(absolute, label);
  const beforeStat = fs.lstatSync(absolute, { bigint: true });
  const before = bigintStatSnapshot(beforeStat);
  if (!beforeStat.isFile() || beforeStat.isSymbolicLink() || before.uid !== 0n
    || (!allowHardlinks && before.nlink !== 1n) || before.nlink < 1n
    || (before.mode & 0o022n) !== 0n
    || (expectedMode !== undefined && (before.mode & 0o7777n) !== BigInt(expectedMode))
    || (executable && (before.mode & 0o111n) === 0n)) {
    throw new Error(`${label} must be a root-owned restricted regular file`);
  }
  const fd = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = bigintStatSnapshot(fs.fstatSync(fd, { bigint: true }));
    if (!sameBigintStatSnapshot(before, opened)) {
      throw new Error(`${label} changed while opening`);
    }
    const authenticated = boundedOpenedFileSha256(fd, maximumBytes, label);
    if (authenticated.sha256 !== expectedSha256) {
      throw new Error(`${label} bytes do not match the frozen verifier authority`);
    }
    return {
      fd,
      label,
      maximumBytes,
      sha256: authenticated.sha256,
      snapshot: authenticated.snapshot,
    };
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}

function assertPinnedRootOwnedFile(filePath, expectedSha256, label, options = {}) {
  const opened = openAuthenticatedRootOwnedFile(filePath, expectedSha256, label, options);
  fs.closeSync(opened.fd);
}

function assertPinnedDcapNativeCodeSignature(nativePath, authority) {
  assertPinnedRootOwnedFile(
    authority.codesign_executable,
    authority.codesign_executable_sha256,
    "macOS code-signature verifier",
    { allowHardlinks: true, executable: true },
  );
  const spawnOptions = {
    cwd: "/",
    encoding: "utf8",
    env: { HOME: "/var/empty", LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    maxBuffer: 16 * 1024,
    timeout: 10_000,
  };
  const verification = spawnSync(authority.codesign_executable, [
    "--verify", "--strict", "--verbose=4", nativePath,
  ], spawnOptions);
  const expectedVerification = [
    `${nativePath}: valid on disk`,
    `${nativePath}: satisfies its Designated Requirement`,
    "",
  ].join("\n");
  if (verification.error || verification.status !== 0 || verification.stdout !== ""
    || verification.stderr !== expectedVerification) {
    throw new Error("dcap-qvl abi3 extension does not pass the pinned strict code-signature check");
  }
  const description = spawnSync(authority.codesign_executable, [
    "-d", "--verbose=4", nativePath,
  ], spawnOptions);
  if (description.error || description.status !== 0 || description.stdout !== ""
    || typeof description.stderr !== "string" || description.stderr.length > 16 * 1024) {
    throw new Error("dcap-qvl abi3 extension code-signature metadata is unavailable");
  }
  const lines = description.stderr.trimEnd().split("\n");
  const required = [
    `Executable=${nativePath}`,
    "Identifier=libdcap_qvl.dylib",
    "Format=Mach-O thin (arm64)",
    "Hash type=sha256 size=32",
    `CandidateCDHashFull sha256=${authority.dcap_qvl_abi3_cdhash_full_sha256}`,
    "Hash choices=sha256",
    "Signature=adhoc",
    "TeamIdentifier=not set",
  ];
  if (required.some((line) => !lines.includes(line))
    || lines.filter((line) => line.startsWith("CodeDirectory ")).length !== 1
    || !lines.find((line) => line.startsWith("CodeDirectory "))
      .includes("flags=0x20002(adhoc,linker-signed)")) {
    throw new Error("dcap-qvl abi3 extension code-signature metadata differs from the frozen authority");
  }
}

function assertPinnedRootOwnedSymlink(filePath, target, resolvedTarget, label) {
  const absolute = path.resolve(filePath);
  if (absolute !== filePath) throw new Error(`${label} path must be absolute`);
  assertRootOwnedRestrictedAncestry(absolute, label);
  const stat = fs.lstatSync(absolute, { bigint: true });
  if (!stat.isSymbolicLink() || stat.uid !== 0n || (stat.mode & 0o022n) !== 0n
    || stat.nlink !== 1n || fs.readlinkSync(absolute) !== target
    || fs.realpathSync.native(absolute) !== resolvedTarget) {
    throw new Error(`${label} does not match the root-owned interpreter link authority`);
  }
}

function openedFdDcapRuntimeAuthorityManifest(authority) {
  return {
    schema: OPENED_FD_DCAP_RUNTIME_AUTHORITY_SCHEMA,
    verifier: authority.verifier,
    verifier_version: authority.verifier_version,
    invocation: authority.invocation,
    platform: authority.platform,
    architecture: authority.architecture,
    darwin_release: authority.darwin_release,
    macos_version: authority.macos_version,
    macos_build: authority.macos_build,
    system_version_plist: authority.system_version_plist,
    system_version_plist_sha256: authority.system_version_plist_sha256,
    system_python_launcher: authority.system_python_launcher,
    system_python_launcher_sha256: authority.system_python_launcher_sha256,
    system_python_reported_executable: authority.system_python_reported_executable,
    system_python_reported_executable_link: authority.system_python_reported_executable_link,
    system_python_resolved_executable: authority.system_python_resolved_executable,
    system_python_resolved_executable_sha256:
      authority.system_python_resolved_executable_sha256,
    system_python_version: authority.system_python_version,
    system_python_runtime_root: authority.system_python_runtime_root,
    system_python_runtime_tree_sha256: authority.system_python_runtime_tree_sha256,
    python_flags: authority.python_flags,
    user_writable_import_path: authority.user_writable_import_path,
    codesign_executable: authority.codesign_executable,
    codesign_executable_sha256: authority.codesign_executable_sha256,
    dcap_qvl_abi3_path: authority.dcap_qvl_abi3_path,
    dcap_qvl_abi3_owner_uid: authority.dcap_qvl_abi3_owner_uid,
    dcap_qvl_abi3_mode: authority.dcap_qvl_abi3_mode,
    dcap_qvl_abi3_signature: authority.dcap_qvl_abi3_signature,
    dcap_qvl_abi3_cdhash_full_sha256: authority.dcap_qvl_abi3_cdhash_full_sha256,
    native_descriptor_authority:
      "root_owned_fixed_path_sha256_and_code_signature_authenticated_before_inherited_fd3_load",
    native_snapshot:
      "darwin_private_link_retained_only_through_exec_module_then_unlinked_read_only_0500_snapshot_rehashed_nlink0_path_race_mitigation_not_hostile_same_uid_kernel_boundary",
    bootstrap_sha256: authority.bootstrap_sha256,
    verifier_script_sha256: authority.verifier_script_sha256,
    dcap_qvl_abi3_sha256: authority.dcap_qvl_abi3_sha256,
  };
}

function openedFdDcapRuntimeAuthoritySha256(authority) {
  return `sha256:${createHash("sha256")
    .update(OPENED_FD_DCAP_RUNTIME_AUTHORITY_DOMAIN, "utf8")
    .update(compactCanonicalText(openedFdDcapRuntimeAuthorityManifest(authority)), "utf8")
    .digest("hex")}`;
}

function normalizeRuntimeConfiguration(value) {
  const optional = ["beforeSpawn", "extraEnvironment", "nativeSnapshotBarrier"]
    .filter((key) => Object.hasOwn(value || {}, key));
  const parsed = exactRecord(value, [
    "authority", "host", "nativeAuthorityMode", "nativePath", "sourcePath", ...optional,
  ], "opened-FD runtime configuration");
  const host = exactRecord(parsed.host, ["architecture", "platform"], "opened-FD runtime host");
  if (typeof parsed.sourcePath !== "string" || !path.isAbsolute(parsed.sourcePath)
    || typeof parsed.nativePath !== "string" || !path.isAbsolute(parsed.nativePath)
    || typeof host.platform !== "string" || typeof host.architecture !== "string"
    || ![ROOT_OWNED_PRODUCTION_MODE, OPERATOR_OWNED_FIXTURE_MODE]
      .includes(parsed.nativeAuthorityMode)
    || (parsed.beforeSpawn !== undefined && typeof parsed.beforeSpawn !== "function")
    || (parsed.nativeSnapshotBarrier !== undefined
      && (typeof parsed.nativeSnapshotBarrier !== "string"
        || !path.isAbsolute(parsed.nativeSnapshotBarrier)
        || path.resolve(parsed.nativeSnapshotBarrier) !== parsed.nativeSnapshotBarrier
        || Buffer.byteLength(parsed.nativeSnapshotBarrier, "utf8") > 1_024))) {
    throw new Error("opened-FD runtime configuration is invalid");
  }
  const extraEnvironment = parsed.extraEnvironment === undefined
    ? {}
    : exactRecord(
      parsed.extraEnvironment,
      Object.keys(parsed.extraEnvironment),
      "opened-FD runtime fixture environment",
    );
  if (Object.entries(extraEnvironment).some(([key, entry]) =>
    !/^[A-Z_][A-Z0-9_]{0,63}$/.test(key) || typeof entry !== "string"
    || ["HOME", "LANG", "LC_ALL", "PATH"].includes(key)
    || Buffer.byteLength(entry, "utf8") > 4_096)) {
    throw new Error("opened-FD runtime fixture environment is invalid");
  }
  if (parsed.nativeAuthorityMode === ROOT_OWNED_PRODUCTION_MODE
    && (parsed.nativePath !== parsed.authority?.dcap_qvl_abi3_path
      || parsed.beforeSpawn !== undefined || parsed.nativeSnapshotBarrier !== undefined
      || Object.keys(extraEnvironment).length !== 0)) {
    throw new Error("root-owned production runtime configuration cannot contain overrides");
  }
  return Object.freeze({
    authority: parsed.authority,
    host: Object.freeze({ platform: host.platform, architecture: host.architecture }),
    sourcePath: parsed.sourcePath,
    nativePath: parsed.nativePath,
    nativeAuthorityMode: parsed.nativeAuthorityMode,
    beforeSpawn: parsed.beforeSpawn,
    nativeSnapshotBarrier: parsed.nativeSnapshotBarrier,
    extraEnvironment: Object.freeze({ ...extraEnvironment }),
  });
}

export function createPinnedSevenCvmOpenedFdRuntime(configuration) {
  const config = normalizeRuntimeConfiguration(configuration);
  const { authority } = config;

  function openPinnedDcapNative() {
    if (config.nativeAuthorityMode === OPERATOR_OWNED_FIXTURE_MODE) {
      return openAuthenticatedOperatorFile(
        path.resolve(config.nativePath),
        authority.dcap_qvl_abi3_sha256,
        32 * 1024 * 1024,
        "dcap-qvl abi3 extension",
      );
    }
    return openAuthenticatedRootOwnedFile(
      authority.dcap_qvl_abi3_path,
      authority.dcap_qvl_abi3_sha256,
      "root-owned dcap-qvl abi3 extension",
      {
        expectedMode: Number.parseInt(authority.dcap_qvl_abi3_mode, 8),
        maximumBytes: 32 * 1024 * 1024,
        missingMessage:
          `root-owned DCAP native extension is not provisioned at ${authority.dcap_qvl_abi3_path}`,
      },
    );
  }

  function assertRuntime() {
    if (config.host.platform !== authority.platform
      || config.host.architecture !== authority.architecture) {
      throw new Error("opened-FD DCAP verifier host is outside the frozen Darwin arm64 authority");
    }
    if (typeof process.geteuid !== "function" || process.geteuid() === 0) {
      throw new Error("opened-FD DCAP verifier must run as a non-root operator");
    }
    const bootstrapSha256 = createHash("sha256")
      .update(OPENED_FD_DCAP_BOOTSTRAP, "utf8")
      .digest("hex");
    if (bootstrapSha256 !== authority.bootstrap_sha256
      || openedFdDcapRuntimeAuthoritySha256(authority)
        !== authority.isolated_runtime_environment_sha256) {
      throw new Error("opened-FD runtime manifest differs from the frozen authority");
    }
    assertPinnedRootOwnedFile(
      authority.system_python_launcher,
      authority.system_python_launcher_sha256,
      "system Python launcher",
      { allowHardlinks: true, executable: true },
    );
    assertPinnedRootOwnedSymlink(
      authority.system_python_reported_executable,
      authority.system_python_reported_executable_link,
      authority.system_python_resolved_executable,
      "reported system Python executable",
    );
    assertPinnedRootOwnedFile(
      authority.system_python_resolved_executable,
      authority.system_python_resolved_executable_sha256,
      "resolved system Python executable",
      { executable: true },
    );
    assertPinnedRootOwnedFile(
      authority.system_version_plist,
      authority.system_version_plist_sha256,
      "macOS system version authority",
      { maximumBytes: 64 * 1024 },
    );
    if (os.release() !== authority.darwin_release) {
      throw new Error("Darwin release differs from the frozen native dependency authority");
    }
    const treeOptions = { expectedUid: 0, allowHardlinks: true };
    const treeBefore = computePythonRuntimeTreeSha256(
      authority.system_python_runtime_root,
      treeOptions,
    );
    const treeAfter = computePythonRuntimeTreeSha256(
      authority.system_python_runtime_root,
      treeOptions,
    );
    if (treeBefore !== authority.system_python_runtime_tree_sha256 || treeAfter !== treeBefore) {
      throw new Error("root-owned Python runtime tree differs from the frozen authority");
    }
    const source = openAuthenticatedOperatorFile(
      path.resolve(config.sourcePath),
      authority.verifier_script_sha256,
      256 * 1024,
      "seven-CVM DCAP verifier source",
    );
    try {
      const native = openPinnedDcapNative();
      try {
        assertPinnedDcapNativeCodeSignature(config.nativePath, authority);
      } finally {
        fs.closeSync(native.fd);
      }
    } finally {
      fs.closeSync(source.fd);
    }
    return structuredClone(authority);
  }

  function run(input) {
    assertRuntime();
    const inputText = JSON.stringify(input);
    if (typeof inputText !== "string" || Buffer.byteLength(inputText, "utf8") < 2
      || Buffer.byteLength(inputText, "utf8") > MAX_DCAP_WIRE_BYTES) {
      throw new Error("opened-FD DCAP verifier input is outside its frozen wire bound");
    }
    const native = openPinnedDcapNative();
    let source;
    try {
      source = openAuthenticatedOperatorFile(
        path.resolve(config.sourcePath),
        authority.verifier_script_sha256,
        256 * 1024,
        "seven-CVM DCAP verifier source",
      );
      config.beforeSpawn?.();
      const result = spawnSync(authority.system_python_launcher, [
        "-I", "-S", "-B", "-c", OPENED_FD_DCAP_BOOTSTRAP,
        authority.dcap_qvl_abi3_sha256,
        authority.verifier_script_sha256,
        authority.bootstrap_sha256,
        authority.isolated_runtime_environment_sha256,
        config.nativeAuthorityMode,
        config.nativeSnapshotBarrier ?? "-",
      ], {
        cwd: "/",
        encoding: "utf8",
        input: inputText,
        stdio: ["pipe", "pipe", "pipe", native.fd, source.fd],
        timeout: 60_000,
        maxBuffer: MAX_DCAP_WIRE_BYTES,
        env: {
          HOME: "/var/empty",
          LANG: "C",
          LC_ALL: "C",
          PATH: "/usr/bin:/bin",
          ...config.extraEnvironment,
        },
      });
      assertOpenedFileStillAuthenticated(native);
      assertOpenedFileStillAuthenticated(source);
      const output = String(result.stdout || "");
      if (result.error || result.status !== 0 || String(result.stderr || "") !== ""
        || Buffer.byteLength(output, "utf8") > MAX_DCAP_WIRE_BYTES) {
        throw new Error("pinned opened-FD Intel TDX verifier failed");
      }
      let parsed;
      try {
        parsed = JSON.parse(output);
      } catch {
        throw new Error("pinned opened-FD DCAP verifier output is not JSON");
      }
      if (`${JSON.stringify(parsed)}\n` !== output) {
        throw new Error("pinned opened-FD DCAP verifier output is not canonical JSON");
      }
      return parsed;
    } finally {
      if (source) fs.closeSync(source.fd);
      fs.closeSync(native.fd);
    }
  }

  return Object.freeze({
    assertRuntime,
    probe: () => run({ runtime_probe: true }),
    run,
  });
}

export const OPENED_FD_RUNTIME_AUTHORITY_MODES = Object.freeze({
  operatorOwnedFixture: OPERATOR_OWNED_FIXTURE_MODE,
  rootOwnedProduction: ROOT_OWNED_PRODUCTION_MODE,
});

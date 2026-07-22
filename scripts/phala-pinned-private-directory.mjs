import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export const PHALA_PINNED_PRIVATE_DIRECTORY_SCHEMA =
  "dnai.phala-pinned-private-directory.v1";
export const PHALA_PINNED_PRIVATE_DIRECTORY_IDENTITY_SCHEMA =
  "dnai.phala-pinned-private-directory-identity.v1";
export const PHALA_PINNED_PRIVATE_FILE_IDENTITY_SCHEMA =
  "dnai.phala-pinned-private-file-identity.v1";

const PYTHON = "/usr/bin/python3";
const DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const MAX_OPERATION_BYTES = 4 * 1024 * 1024;
const HANDLES = new WeakMap();
const SESSION_IDENTITY_ANCHORS = new Map();

// Node does not expose openat(2). This root-owned, isolated system-Python
// bootstrap is deliberately literal and receives the already authenticated
// directory descriptor as fd 3. Every child path is a single basename; no
// operation resolves the mutable directory pathname after it has been pinned.
const OPENAT_HELPER = String.raw`
import hashlib, json, os, re, secrets, stat, sys

def die(message, code=1):
    sys.stderr.write(str(message) + "\n")
    raise SystemExit(code)

def name(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9._-]{1,255}", value) is None or value in (".", ".."):
        die("invalid fd-relative basename")
    return value

def directory():
    value = os.fstat(3)
    if not stat.S_ISDIR(value.st_mode):
        die("fd-relative authority is not a directory")
    if stat.S_IMODE(value.st_mode) != 0o700:
        die("fd-relative authority directory mode is not exactly 0700")
    if value.st_uid != os.geteuid():
        die("fd-relative authority directory is not owned by the current operator")
    expected = (int(sys.argv[5]), int(sys.argv[6]), int(sys.argv[7]), int(sys.argv[8], 8))
    observed = (value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode))
    if observed != expected:
        die("fd-relative authority directory identity changed")
    return value

def identity(value, data):
    return {
        "device": str(value.st_dev),
        "inode": str(value.st_ino),
        "uid": str(value.st_uid),
        "mode": format(stat.S_IMODE(value.st_mode), "04o"),
        "link_count": value.st_nlink,
        "size": value.st_size,
        "mtime_ns": str(value.st_mtime_ns),
        "ctime_ns": str(value.st_ctime_ns),
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
    }

def emit_identity(value, data):
    sys.stdout.write(json.dumps(identity(value, data), sort_keys=True, separators=(",", ":")) + "\n")

def regular(fd, expected_mode, maximum, minimum=0):
    value = os.fstat(fd)
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        die("fd-relative file is not a single-link regular file")
    if stat.S_IMODE(value.st_mode) != expected_mode:
        die("fd-relative file mode differs from exact private mode-%04o" % expected_mode)
    if value.st_uid != os.geteuid():
        die("fd-relative file is not owned by the current operator")
    if value.st_dev != os.fstat(3).st_dev:
        die("fd-relative file is not on the pinned directory device")
    if value.st_size < minimum or value.st_size > maximum:
        die("fd-relative file is outside the bounded size")
    return value

def read_open_fd(fd, expected_mode, maximum, minimum=0):
    before = regular(fd, expected_mode, maximum, minimum)
    chunks = []
    remaining = before.st_size
    while remaining:
        chunk = os.read(fd, min(remaining, 65536))
        if not chunk:
            die("fd-relative file ended during its bounded read")
        chunks.append(chunk)
        remaining -= len(chunk)
    after = regular(fd, expected_mode, maximum, minimum)
    data = b"".join(chunks)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(data) != before.st_size:
        die("fd-relative file changed during its bounded read")
    return data, after

def read_exact(file_name, expected_mode, maximum, minimum=0):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(file_name, flags, dir_fd=3)
    try:
        data, after = read_open_fd(fd, expected_mode, maximum, minimum)
        current = os.stat(file_name, dir_fd=3, follow_symlinks=False)
        if (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino):
            die("fd-relative file directory entry changed during its bounded read")
        return data, after
    finally:
        os.close(fd)

def write_all(fd, data, fault):
    offset = 0
    while offset < len(data):
        length = len(data) - offset
        if fault == "partial-write":
            length = max(1, length // 2)
        count = os.write(fd, data[offset:offset + length])
        if count < 1:
            die("fd-relative write made no forward progress")
        offset += count
        if fault == "partial-write":
            die("injected durable-write failure at partial-write")

operation = sys.argv[1]
target = name(sys.argv[2])
mode = int(sys.argv[3], 8)
maximum = int(sys.argv[4])
directory()

if operation == "exists":
    try:
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=3)
    except FileNotFoundError:
        raise SystemExit(44)
    else:
        os.close(fd)
        raise SystemExit(0)

if operation == "list":
    entries = sorted(os.listdir(3))
    for entry in entries:
        name(entry)
    sys.stdout.write(json.dumps(entries, separators=(",", ":")) + "\n")
    raise SystemExit(0)

if operation == "read":
    minimum = int(sys.argv[9])
    expected_dev = sys.argv[10]
    expected_ino = sys.argv[11]
    expected_sha = sys.argv[12]
    expected_mtime_ns = sys.argv[13]
    expected_ctime_ns = sys.argv[14]
    try:
        data, observed = read_exact(target, mode, maximum, minimum)
    except FileNotFoundError:
        raise SystemExit(44)
    expected_identity = (expected_dev, expected_ino, expected_mtime_ns, expected_ctime_ns)
    if any(expected_identity) and (not all(expected_identity) or (str(observed.st_dev), str(observed.st_ino), str(observed.st_mtime_ns), str(observed.st_ctime_ns)) != expected_identity):
        die("fd-relative file identity differs from the authenticated identity")
    if expected_sha and hashlib.sha256(data).hexdigest() != expected_sha:
        die("fd-relative file digest differs from the authenticated identity")
    sys.stdout.buffer.write(data)
    raise SystemExit(0)

if operation == "create":
    data = sys.stdin.buffer.read(maximum + 1)
    if len(data) > maximum:
        die("fd-relative create input exceeds its bound")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, mode, dir_fd=3)
    try:
        write_all(fd, data, "")
        os.fchmod(fd, mode)
        created = regular(fd, mode, maximum, 0)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(3)
    data, observed = read_exact(target, mode, maximum, 0)
    if (observed.st_dev, observed.st_ino) != (created.st_dev, created.st_ino):
        die("fd-relative created file changed before identity return")
    emit_identity(observed, data)
    raise SystemExit(0)

if operation == "publish":
    publish_mode = sys.argv[9]
    temporary = name(sys.argv[10])
    fault = sys.argv[11]
    if publish_mode not in ("create", "replace"):
        die("fd-relative publish mode is invalid")
    if fault not in ("", "partial-write", "complete-write", "file-fsync", "publish", "directory-fsync"):
        die("unknown fd-relative durable-write fault stage")
    data = sys.stdin.buffer.read(maximum + 1)
    if len(data) > maximum:
        die("fd-relative publish input exceeds its bound")
    target_before = None
    try:
        existing, target_before = read_exact(target, mode, maximum, 0)
        if publish_mode == "create":
            die("fd-relative create target already exists")
    except FileNotFoundError:
        if publish_mode == "replace":
            die("fd-relative replacement target does not exist")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    temporary_created = False
    published = False
    fd = None
    try:
        fd = os.open(temporary, flags, mode, dir_fd=3)
        temporary_created = True
        write_all(fd, data, fault)
        if fault == "complete-write":
            die("injected durable-write failure at complete-write")
        os.fchmod(fd, mode)
        written = regular(fd, mode, maximum, 0)
        if written.st_size != len(data):
            die("fd-relative temporary file length is incomplete")
        if fault == "file-fsync":
            die("injected durable-write failure at file-fsync")
        os.fsync(fd)
        os.close(fd)
        fd = None
        reread, temporary_stat = read_exact(temporary, mode, maximum, 0)
        if reread != data:
            die("fd-relative temporary bytes differ from source")
        if fault == "publish":
            die("injected durable-write failure at publish")
        if publish_mode == "create":
            os.link(temporary, target, src_dir_fd=3, dst_dir_fd=3, follow_symlinks=False)
            os.unlink(temporary, dir_fd=3)
        else:
            current_data, current = read_exact(target, mode, maximum, 0)
            if target_before is None or current_data != existing or (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (target_before.st_dev, target_before.st_ino, target_before.st_size, target_before.st_mtime_ns, target_before.st_ctime_ns):
                die("fd-relative replacement target changed before publication")
            os.rename(temporary, target, src_dir_fd=3, dst_dir_fd=3)
        published = True
        observed, observed_stat = read_exact(target, mode, maximum, 0)
        if observed != data or (observed_stat.st_dev, observed_stat.st_ino) != (temporary_stat.st_dev, temporary_stat.st_ino):
            die("fd-relative published bytes or inode differ from source")
        if fault == "directory-fsync":
            die("injected durable-write failure at directory-fsync")
        os.fsync(3)
        emit_identity(observed_stat, observed)
    finally:
        if fd is not None:
            try: os.close(fd)
            except OSError: pass
        if temporary_created and not published:
            try: os.unlink(temporary, dir_fd=3)
            except OSError: pass
    raise SystemExit(0)

if operation == "unlink":
    expected_sha = sys.argv[9]
    expected_dev = sys.argv[10]
    expected_ino = sys.argv[11]
    expected_mtime_ns = sys.argv[12]
    expected_ctime_ns = sys.argv[13]
    if not all((expected_dev, expected_ino, expected_mtime_ns, expected_ctime_ns)):
        die("fd-relative unlink requires one complete acquired lock identity")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    held_fd = os.open(target, flags, dir_fd=3)
    quarantine = None
    try:
        data, before = read_open_fd(held_fd, mode, maximum, 0)
        expected_identity = (
            expected_dev,
            expected_ino,
            expected_mtime_ns,
            expected_ctime_ns,
        )
        observed_identity = (
            str(before.st_dev),
            str(before.st_ino),
            str(before.st_mtime_ns),
            str(before.st_ctime_ns),
        )
        if observed_identity != expected_identity:
            die("fd-relative unlink target identity differs from the acquired lock")
        if expected_sha and hashlib.sha256(data).hexdigest() != expected_sha:
            die("fd-relative unlink target digest differs from reviewed bytes")
        current = os.stat(target, dir_fd=3, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            die("fd-relative unlink target changed before quarantine")
        # POSIX has no unlink-if-inode primitive. Keep the authenticated inode
        # open while moving the directory entry to a high-entropy quarantine,
        # then compare the moved entry with the still-live descriptor. Holding
        # the descriptor prevents inode-number reuse from impersonating it.
        quarantine = name("." + target + ".release-" + secrets.token_hex(32))
        os.rename(target, quarantine, src_dir_fd=3, dst_dir_fd=3)
        os.fsync(3)
        moved_data, moved = read_exact(quarantine, mode, maximum, 0)
        held_after = regular(held_fd, mode, maximum, 0)
        if moved_data != data or (moved.st_dev, moved.st_ino) != (held_after.st_dev, held_after.st_ino):
            try:
                os.link(quarantine, target, src_dir_fd=3, dst_dir_fd=3, follow_symlinks=False)
                os.unlink(quarantine, dir_fd=3)
                os.fsync(3)
            except OSError:
                pass
            die("fd-relative unlink quarantined a replacement target; automatic removal is forbidden")
        os.unlink(quarantine, dir_fd=3)
        os.fsync(3)
    except BaseException:
        # If the expected entry was moved but a later validation failed, put
        # it back without replacing any newly-created lock.
        if quarantine is not None:
            try:
                os.link(quarantine, target, src_dir_fd=3, dst_dir_fd=3, follow_symlinks=False)
                os.unlink(quarantine, dir_fd=3)
                os.fsync(3)
            except OSError:
                pass
        raise
    finally:
        os.close(held_fd)
    raise SystemExit(0)

die("unknown fd-relative operation")
`;

export const PHALA_OPENAT_HELPER_SHA256 = `sha256:${createHash("sha256")
  .update(OPENAT_HELPER, "utf8")
  .digest("hex")}`;

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function canonicalText(value) {
  const sorted = Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]]));
  return `${JSON.stringify(sorted, null, 2)}\n`;
}

function validateSystemPython() {
  const stat = fs.lstatSync(PYTHON);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0
    || (stat.mode & 0o022) !== 0 || (stat.mode & 0o111) === 0) {
    throw new Error("root-owned isolated system Python is unavailable for openat persistence");
  }
}

function validateDirectoryPath(directory) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)
    || path.resolve(directory) !== directory || path.normalize(directory) !== directory) {
    throw new Error("pinned private directory path must be canonical and absolute");
  }
  const stat = fs.lstatSync(directory, { bigint: true });
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error("pinned private directory must be a non-symlink directory");
  }
  if ((stat.mode & 0o777n) !== 0o700n) {
    throw new Error("pinned private directory must have exact mode 0700");
  }
  if (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())) {
    throw new Error("pinned private directory must be owned by the current operator");
  }
  const real = fs.realpathSync.native(directory);
  if (real !== directory) {
    throw new Error("pinned private directory path must not traverse a symlink or alias");
  }
  return stat;
}

function identityAnchorPath(directory) {
  const key = createHash("sha256").update(directory, "utf8").digest("hex");
  return path.join(path.dirname(directory), `.dnai-phala-directory-${key}.identity.json`);
}

function openValidatedIdentityAnchorParent(directory) {
  const parent = path.dirname(directory);
  if (fs.realpathSync.native(parent) !== parent) {
    throw new Error("pinned directory identity-anchor parent must be canonical");
  }
  const before = fs.lstatSync(parent, { bigint: true });
  if (before.isSymbolicLink() || !before.isDirectory()
    || (before.mode & 0o777n) !== 0o700n
    || (typeof process.getuid === "function" && before.uid !== BigInt(process.getuid()))) {
    throw new Error(
      "pinned directory identity-anchor parent must be owned, non-symlink, and exact mode 0700",
    );
  }
  const fd = fs.openSync(parent, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    const after = fs.lstatSync(parent, { bigint: true });
    if (!opened.isDirectory() || !sameInode(before, opened) || !sameInode(opened, after)) {
      throw new Error("pinned directory identity-anchor parent changed while opened");
    }
    return { parent, fd, stat: opened };
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}

function validateIdentityAnchorParent(directory) {
  const opened = openValidatedIdentityAnchorParent(directory);
  fs.closeSync(opened.fd);
  return opened.parent;
}

export function phalaPinnedPrivateDirectoryIdentityAnchorPath(directory) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)) {
    throw new Error("pinned private directory identity path requires an absolute directory");
  }
  return identityAnchorPath(directory);
}

function stableReadIdentity(filePath) {
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink?.() || before.nlink !== 1n
      || (before.mode & 0o777n) !== 0o600n || before.size < 2n || before.size > 4096n
      || (typeof process.getuid === "function" && before.uid !== BigInt(process.getuid()))) {
      throw new Error("pinned directory identity anchor posture is invalid");
    }
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd, { bigint: true });
    const current = fs.lstatSync(filePath, { bigint: true });
    if (!sameInode(before, after) || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs
      || !sameInode(after, current) || current.isSymbolicLink()
      || BigInt(bytes.length) !== before.size) {
      throw new Error("pinned directory identity anchor changed during read");
    }
    return bytes;
  } finally {
    fs.closeSync(fd);
  }
}

function installOrVerifyIdentityAnchor(
  directory,
  stat,
  expectedIdentityAnchorSha256,
) {
  const anchorPath = identityAnchorPath(directory);
  if (expectedIdentityAnchorSha256 !== null
    && (typeof expectedIdentityAnchorSha256 !== "string"
      || !/^sha256:[0-9a-f]{64}$/.test(expectedIdentityAnchorSha256))) {
    throw new Error("expected pinned-directory identity anchor must be a canonical SHA-256 digest");
  }
  const document = {
    schema: PHALA_PINNED_PRIVATE_DIRECTORY_IDENTITY_SCHEMA,
    canonical_path_sha256: `sha256:${createHash("sha256")
      .update(directory, "utf8").digest("hex")}`,
    directory_device: String(stat.dev),
    directory_inode: String(stat.ino),
    directory_uid: String(stat.uid),
    directory_mode: (stat.mode & 0o777n).toString(8).padStart(4, "0"),
    automatic_rebind_authorized: false,
  };
  const bytes = Buffer.from(canonicalText(document), "utf8");
  const cachedAnchorSha256 = SESSION_IDENTITY_ANCHORS.get(directory) ?? null;
  const anchorExisted = fs.existsSync(anchorPath);
  if (!anchorExisted) {
    if (expectedIdentityAnchorSha256 !== null) {
      throw new Error("externally authenticated pinned-directory identity anchor is missing");
    }
    if (cachedAnchorSha256 !== null) {
      throw new Error("pinned directory identity anchor disappeared; automatic replacement is forbidden");
    }
    if (fs.readdirSync(directory).length !== 0) {
      throw new Error(
        "existing Phala persistence contents lack an authenticated directory identity anchor",
      );
    }
  }
  let createdAnchor = false;
  if (!anchorExisted) {
    let fd;
    try {
      fd = fs.openSync(
        anchorPath,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW,
        0o600,
      );
      fs.writeFileSync(fd, bytes);
      fs.fchmodSync(fd, 0o600);
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      createdAnchor = true;
      const parentFd = fs.openSync(
        path.dirname(directory),
        fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW,
      );
      try { fs.fsyncSync(parentFd); } finally { fs.closeSync(parentFd); }
    } catch (error) {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch { /* Preserve the first error. */ }
      }
      if (error?.code === "EEXIST") {
        throw new Error(
          "pinned directory identity anchor appeared during initialization; explicit review is required",
        );
      }
      throw error;
    }
  }
  const observedBytes = stableReadIdentity(anchorPath);
  let observed;
  try { observed = JSON.parse(observedBytes.toString("utf8")); } catch {
    throw new Error("pinned directory identity anchor is corrupt");
  }
  if (canonicalText(observed) !== observedBytes.toString("utf8")
    || JSON.stringify(Object.keys(observed).sort())
      !== JSON.stringify(Object.keys(document).sort())
    || observed.schema !== document.schema
    || observed.canonical_path_sha256 !== document.canonical_path_sha256
    || observed.directory_device !== document.directory_device
    || observed.directory_inode !== document.directory_inode
    || observed.directory_uid !== document.directory_uid
    || observed.directory_mode !== document.directory_mode
    || observed.automatic_rebind_authorized !== false) {
    throw new Error("pinned private directory identity changed; automatic rebind is forbidden");
  }
  const anchorSha256 = `sha256:${createHash("sha256").update(observedBytes).digest("hex")}`;
  if (expectedIdentityAnchorSha256 !== null
    && expectedIdentityAnchorSha256 !== anchorSha256) {
    throw new Error("pinned directory identity anchor differs from external authenticated authority");
  }
  if (cachedAnchorSha256 !== null && cachedAnchorSha256 !== anchorSha256) {
    throw new Error("pinned directory identity anchor changed within this process");
  }
  if (!createdAnchor && cachedAnchorSha256 === null
    && expectedIdentityAnchorSha256 === null) {
    throw new Error(
      "cross-process Phala persistence requires an externally authenticated directory identity anchor digest",
    );
  }
  SESSION_IDENTITY_ANCHORS.set(directory, anchorSha256);
  return { anchorPath, anchorSha256 };
}

export function ensurePhalaPinnedPrivateDirectory(directory) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)) {
    throw new Error("pinned private directory must be absolute");
  }
  if (!fs.existsSync(directory)) {
    const parent = validateIdentityAnchorParent(directory);
    fs.mkdirSync(directory, { mode: 0o700 });
    const parentFd = fs.openSync(parent, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW);
    try { fs.fsyncSync(parentFd); } finally { fs.closeSync(parentFd); }
  }
  validateDirectoryPath(directory);
  validateIdentityAnchorParent(directory);
  return directory;
}

function pinValidatedPhalaPrivateDirectory(directory, {
  expectedIdentityAnchorSha256 = null,
  requiredCreatedIdentity = null,
  openExistingOnly = false,
} = {}) {
  validateSystemPython();
  if (openExistingOnly) {
    if (!fs.existsSync(directory)) {
      throw new Error(
        "externally authenticated pinned private directory must already exist",
      );
    }
    validateDirectoryPath(directory);
    validateIdentityAnchorParent(directory);
  } else {
    ensurePhalaPinnedPrivateDirectory(directory);
  }
  const before = validateDirectoryPath(directory);
  if (requiredCreatedIdentity !== null
    && !sameInode(before, requiredCreatedIdentity)) {
    throw new Error(
      "new pinned private directory was substituted before authority pinning",
    );
  }
  const identity = installOrVerifyIdentityAnchor(
    directory,
    before,
    expectedIdentityAnchorSha256,
  );
  const fd = fs.openSync(directory, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    const after = validateDirectoryPath(directory);
    if (!opened.isDirectory() || !sameInode(before, opened)
      || !sameInode(opened, after)
      || (requiredCreatedIdentity !== null
        && !sameInode(opened, requiredCreatedIdentity))) {
      throw new Error("private directory changed while its authority fd was opened");
    }
    const handle = Object.freeze({
      schema: PHALA_PINNED_PRIVATE_DIRECTORY_SCHEMA,
      path: directory,
      device: String(opened.dev),
      inode: String(opened.ino),
      uid: String(opened.uid),
      mode: (opened.mode & 0o777n).toString(8).padStart(4, "0"),
      identity_anchor_sha256: identity.anchorSha256,
      openat_helper_sha256: PHALA_OPENAT_HELPER_SHA256,
    });
    HANDLES.set(handle, { fd, closed: false });
    return handle;
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}

export function pinPhalaPrivateDirectory(directory, {
  expectedIdentityAnchorSha256 = null,
} = {}) {
  return pinValidatedPhalaPrivateDirectory(directory, {
    expectedIdentityAnchorSha256,
    // Supplying an externally authenticated anchor is a strict read/attach
    // operation. It must never create or initialize an absent leaf.
    openExistingOnly: expectedIdentityAnchorSha256 !== null,
  });
}

export function assertPinnedPhalaPrivateDirectory(handle, expectedPath) {
  const state = handle && HANDLES.get(handle);
  if (!state || state.closed || (expectedPath !== undefined && handle.path !== expectedPath)) {
    throw new Error("an exact live pinned private-directory authority is required");
  }
  const stat = fs.fstatSync(state.fd, { bigint: true });
  if (!stat.isDirectory() || String(stat.dev) !== handle.device
    || String(stat.ino) !== handle.inode || (stat.mode & 0o777n) !== 0o700n
    || (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid()))) {
    throw new Error(
      `pinned private-directory fd posture changed (${JSON.stringify({
        observed_device: String(stat.dev),
        observed_inode: String(stat.ino),
        observed_uid: String(stat.uid),
        observed_mode: (stat.mode & 0o777n).toString(8).padStart(4, "0"),
        observed_link_count: String(stat.nlink),
      })})`,
    );
  }
  return handle;
}

export function assertPinnedPhalaPrivateDirectoryPathIdentity(handle) {
  assertPinnedPhalaPrivateDirectory(handle);
  let current;
  let anchorBytes;
  try {
    validateIdentityAnchorParent(handle.path);
    current = validateDirectoryPath(handle.path);
    anchorBytes = stableReadIdentity(identityAnchorPath(handle.path));
  } catch {
    throw new Error(
      "pinned private-directory pathname or identity anchor no longer names its authenticated directory",
    );
  }
  const anchorSha256 = `sha256:${createHash("sha256")
    .update(anchorBytes)
    .digest("hex")}`;
  if (String(current.dev) !== handle.device
    || String(current.ino) !== handle.inode
    || anchorSha256 !== handle.identity_anchor_sha256) {
    throw new Error(
      "pinned private-directory pathname or identity anchor no longer names its authenticated directory",
    );
  }
  return handle;
}

export function phalaPinnedPrivateDirectoryIdentityAnchorSha256(handle) {
  assertPinnedPhalaPrivateDirectory(handle);
  return handle.identity_anchor_sha256;
}

export function closePhalaPinnedPrivateDirectory(handle) {
  const state = handle && HANDLES.get(handle);
  if (!state || state.closed) return;
  fs.closeSync(state.fd);
  state.closed = true;
}

function invoke(handle, operation, fileName, {
  mode = 0o600,
  maximum = MAX_OPERATION_BYTES,
  extra = [],
  input,
  allowMissing = false,
} = {}) {
  assertPinnedPhalaPrivateDirectory(handle);
  if (typeof fileName !== "string" || path.basename(fileName) !== fileName
    || !/^[A-Za-z0-9._-]{1,255}$/.test(fileName)
    || fileName === "." || fileName === "..") {
    throw new Error("fd-relative persistence requires one exact basename");
  }
  if (!Number.isInteger(mode) || mode < 0o400 || mode > 0o700
    || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > MAX_OPERATION_BYTES) {
    throw new Error("fd-relative persistence bounds are invalid");
  }
  const state = HANDLES.get(handle);
  const result = spawnSync(PYTHON, [
    "-I", "-S", "-B", "-c", OPENAT_HELPER,
    operation,
    fileName,
    mode.toString(8),
    String(maximum),
    handle.device,
    handle.inode,
    handle.uid,
    handle.mode,
    ...extra.map(String),
  ], {
    input,
    maxBuffer: maximum + 64 * 1024,
    stdio: ["pipe", "pipe", "pipe", state.fd],
    env: {},
    cwd: "/",
    windowsHide: true,
  });
  if (allowMissing && result.status === 44) return null;
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const detail = result.stderr?.toString("utf8").trim();
    const error = new Error(detail || `fd-relative ${operation} failed closed`);
    error.code = result.status === 44 || /No such file|does not exist/i.test(detail)
      ? "ENOENT"
      : /File exists|already exists/i.test(detail)
        ? "EEXIST"
        : "EPHALAPINNEDIO";
    throw error;
  }
  assertPinnedPhalaPrivateDirectory(handle);
  return result.stdout;
}

export function phalaPinnedPrivateFileExists(handle, fileName) {
  return invoke(handle, "exists", fileName, { allowMissing: true }) !== null;
}

export function listPhalaPinnedPrivateEntries(handle) {
  const output = invoke(handle, "list", "_", { maximum: 256 * 1024 });
  let parsed;
  try { parsed = JSON.parse(output.toString("utf8")); } catch {
    throw new Error("fd-relative directory listing is not canonical JSON");
  }
  if (!Array.isArray(parsed)
    || parsed.some((entry) => typeof entry !== "string"
      || !/^[A-Za-z0-9._-]{1,255}$/.test(entry)
      || entry === "." || entry === "..")
    || JSON.stringify([...parsed].sort()) !== JSON.stringify(parsed)) {
    throw new Error("fd-relative directory listing is invalid");
  }
  return Object.freeze(parsed);
}

export function readPhalaPinnedPrivateFile(handle, fileName, {
  mode = 0o600,
  maximum = MAX_OPERATION_BYTES,
  minimum = 2,
  allowMissing = false,
  expectedIdentity = null,
} = {}) {
  const identity = expectedIdentity === null
    ? null
    : normalizeExpectedPrivateFileIdentity(expectedIdentity);
  if (identity !== null
    && (identity.mode !== mode.toString(8).padStart(4, "0")
      || identity.size < minimum || identity.size > maximum)) {
    throw new Error("fd-relative read bounds differ from the authenticated file identity");
  }
  try {
    return invoke(handle, "read", fileName, {
      mode,
      maximum,
      extra: [
        minimum,
        identity?.device ?? "",
        identity?.inode ?? "",
        identity?.sha256?.slice("sha256:".length) ?? "",
        identity?.mtime_ns ?? "",
        identity?.ctime_ns ?? "",
      ],
      allowMissing,
    });
  } catch (error) {
    if (allowMissing && error?.code === "ENOENT") return null;
    throw error;
  }
}

function normalizeExpectedPrivateFileIdentity(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([
      "ctime_ns",
      "device",
      "inode",
      "link_count",
      "mode",
      "mtime_ns",
      "schema",
      "sha256",
      "size",
      "uid",
    ].sort())
    || value.schema !== PHALA_PINNED_PRIVATE_FILE_IDENTITY_SCHEMA
    || typeof value.device !== "string" || !/^[0-9]+$/.test(value.device)
    || typeof value.inode !== "string" || !/^[0-9]+$/.test(value.inode)
    || typeof value.uid !== "string" || !/^[0-9]+$/.test(value.uid)
    || typeof value.mode !== "string" || !/^0[4-7][0-7]{2}$/.test(value.mode)
    || typeof value.mtime_ns !== "string" || !/^[0-9]+$/.test(value.mtime_ns)
    || typeof value.ctime_ns !== "string" || !/^[0-9]+$/.test(value.ctime_ns)
    || value.link_count !== 1
    || !Number.isSafeInteger(value.size) || value.size < 0
    || typeof value.sha256 !== "string"
    || !/^sha256:[0-9a-f]{64}$/.test(value.sha256)) {
    throw new Error("an exact authenticated fd-relative file identity is required");
  }
  return value;
}

function parsePrivateFileIdentity(output, label) {
  let parsed;
  try {
    parsed = JSON.parse(output.toString("utf8"));
  } catch {
    throw new Error(`${label} did not return its authenticated identity`);
  }
  return Object.freeze(normalizeExpectedPrivateFileIdentity({
    schema: PHALA_PINNED_PRIVATE_FILE_IDENTITY_SCHEMA,
    ...parsed,
  }));
}

export function createExclusivePhalaPinnedPrivateFile(handle, fileName, bytes, {
  mode = 0o600,
  maximum = MAX_OPERATION_BYTES,
} = {}) {
  const input = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const output = invoke(handle, "create", fileName, { mode, maximum, input });
  return parsePrivateFileIdentity(output, "created fd-relative file");
}

export function publishPhalaPinnedPrivateFile(handle, fileName, bytes, {
  publishMode,
  mode = 0o600,
  maximum = MAX_OPERATION_BYTES,
  faultStage = null,
} = {}) {
  const input = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const temporary = `.${fileName}.${process.pid}.${randomBytes(24).toString("hex")}.tmp`;
  const output = invoke(handle, "publish", fileName, {
    mode,
    maximum,
    extra: [publishMode, temporary, faultStage ?? ""],
    input,
  });
  return parsePrivateFileIdentity(output, "published fd-relative file");
}

export function unlinkPhalaPinnedPrivateFile(handle, fileName, {
  expectedSha256 = null,
  expectedIdentity,
  mode = 0o600,
  maximum = MAX_OPERATION_BYTES,
} = {}) {
  const identity = normalizeExpectedPrivateFileIdentity(expectedIdentity);
  const effectiveSha256 = expectedSha256 ?? identity.sha256;
  const bare = String(effectiveSha256).replace(/^sha256:/, "");
  if (bare && !/^[0-9a-f]{64}$/.test(bare)) {
    throw new Error("fd-relative unlink requires a canonical expected SHA-256");
  }
  if (identity.mode !== mode.toString(8).padStart(4, "0")
    || identity.size > maximum) {
    throw new Error("fd-relative unlink bounds differ from the authenticated file identity");
  }
  if (identity.sha256 !== `sha256:${bare}`) {
    throw new Error("fd-relative unlink digest and acquired identity disagree");
  }
  invoke(handle, "unlink", fileName, {
    mode,
    maximum,
    extra: [
      bare,
      identity.device,
      identity.inode,
      identity.mtime_ns,
      identity.ctime_ns,
    ],
  });
}

export function phalaPinnedPrivatePathForDisplay(handle, fileName) {
  assertPinnedPhalaPrivateDirectory(handle);
  if (path.basename(fileName) !== fileName) {
    throw new Error("display path requires one basename");
  }
  return path.join(handle.path, fileName);
}

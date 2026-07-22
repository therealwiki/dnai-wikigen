import { lstat, mkdir, mkdtemp, realpath, rm, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

export async function createPrivateReleaseBuildHome() {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const home = await mkdtemp(
    path.join(canonicalTemporaryRoot, "dnai-cloudflare-build-home-"),
  );
  await chmod(home, 0o700);
  for (const relative of [
    "tmp",
    ".cache",
    ".config",
    path.join(".local", "share"),
    ".npm-cache",
  ]) {
    await mkdir(path.join(home, relative), {
      recursive: true,
      mode: 0o700,
    });
  }
  const canonical = await realpath(home);
  const metadata = await lstat(home);
  const expectedUid = typeof process.geteuid === "function"
    ? process.geteuid()
    : metadata.uid;
  if (
    canonical !== home
    || !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || metadata.uid !== expectedUid
    || (metadata.mode & 0o077) !== 0
  ) {
    await rm(home, { recursive: true, force: true });
    throw new Error("release build HOME is not a private operator-owned directory");
  }
  return home;
}

export async function removePrivateReleaseBuildHome(home) {
  await rm(home, { recursive: true, force: true });
}

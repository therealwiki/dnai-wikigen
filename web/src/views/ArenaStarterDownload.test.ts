import { createComponent, createRoot } from "solid-js";
import { renderToString } from "solid-js/web";
import { sha256 } from "viem";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ARENA_SAFE_IR_STARTER_FILENAME, arenaSafeIrStarterCandidateBytes } from "../lib/arena";
import { ArenaSafeIrStarterLink, createArenaSafeIrStarterDownload } from "./Arena";
import arenaSource from "./Arena.tsx?raw";

const lifecycle = vi.hoisted(() => ({ mounts: [] as Array<() => void> }));

// Node/SSR does not run onMount. Keep Solid's real owner/cleanup implementation
// and explicitly drive only this public-download resource's browser mount.
vi.mock("solid-js", async (importOriginal) => ({
  ...await importOriginal<typeof import("solid-js")>(),
  onMount: (callback: () => void) => lifecycle.mounts.push(callback),
}));

function createStarterOwner() {
  let dispose = () => {};
  const download = createRoot((stop) => {
    dispose = stop;
    return createArenaSafeIrStarterDownload();
  });
  const mount = lifecycle.mounts.at(-1)!;
  return { download, mount, dispose };
}

function renderStarter(download: Parameters<typeof ArenaSafeIrStarterLink>[0]["download"]) {
  return renderToString(() => createComponent(ArenaSafeIrStarterLink, { download }));
}

beforeEach(() => {
  lifecycle.mounts.length = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("Arena Safe-IR starter download", () => {
  it("waits for browser mount and does not allocate a Blob URL during SSR", () => {
    const createUrl = vi.spyOn(URL, "createObjectURL");
    const revokeUrl = vi.spyOn(URL, "revokeObjectURL");
    const starter = createStarterOwner();
    expect(starter.download()).toEqual({ status: "preparing" });
    expect(renderStarter(starter.download())).toContain("Preparing Safe-IR starter");
    expect(renderStarter(starter.download())).not.toContain("<a ");
    expect(createUrl).not.toHaveBeenCalled();
    starter.dispose();
    expect(revokeUrl).not.toHaveBeenCalled();
  });

  it("creates the exact 209-byte canonical JSON Blob without newline or text conversion", async () => {
    const createUrl = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:starter");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const starter = createStarterOwner();
    starter.mount();
    expect(createUrl).toHaveBeenCalledTimes(1);
    const blob = createUrl.mock.calls[0][0] as Blob;
    const bytes = new Uint8Array(await blob.arrayBuffer());
    expect(blob.type).toBe("application/json");
    expect(blob.size).toBe(209);
    expect(bytes).toEqual(arenaSafeIrStarterCandidateBytes());
    expect(sha256(bytes)).toBe("0x57338c5996cb2e545d75cb2ddbefb6f7bad00884bdbe80caa4d0e4b92b1bc8ef");
    expect(new TextDecoder().decode(bytes).endsWith("\n")).toBe(false);
    starter.dispose();
  });

  it("renders a native download link with the exact filename and existing visual class", () => {
    const html = renderStarter({ status: "ready", href: "blob:starter" });
    expect(html).toMatch(/<a\s/);
    expect(html).toContain('class="starter-kit-button"');
    expect(html).toContain('href="blob:starter"');
    expect(html).toContain(`download="${ARENA_SAFE_IR_STARTER_FILENAME}"`);
    expect(html).toContain('type="application/json"');
    expect(html).toContain("Download byte-exact Safe-IR starter");
    expect(html).not.toContain("<button");
    expect(html).not.toContain("unavailable");
  });

  it("keeps the same URL through microtasks and repeated link renders until owner cleanup", async () => {
    const createUrl = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:starter");
    const revokeUrl = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const starter = createStarterOwner();
    starter.mount();
    const first = renderStarter(starter.download());
    await Promise.resolve();
    expect(renderStarter(starter.download())).toBe(first);
    expect(createUrl).toHaveBeenCalledTimes(1);
    expect(revokeUrl).not.toHaveBeenCalled();
    starter.dispose();
    expect(revokeUrl).toHaveBeenCalledExactlyOnceWith("blob:starter");
  });

  it("releases only its own URL when one of two Arena owners is disposed", () => {
    vi.spyOn(URL, "createObjectURL")
      .mockReturnValueOnce("blob:first")
      .mockReturnValueOnce("blob:second");
    const revokeUrl = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const first = createStarterOwner();
    const second = createStarterOwner();
    first.mount();
    second.mount();
    first.dispose();
    expect(revokeUrl).toHaveBeenCalledExactlyOnceWith("blob:first");
    expect(second.download()).toEqual({ status: "ready", href: "blob:second" });
    second.dispose();
    expect(revokeUrl.mock.calls).toEqual([["blob:first"], ["blob:second"]]);
  });

  it.each(["throws", "unsupported"])("shows a non-action unavailable state when URL creation %s", (failure) => {
    const revokeUrl = vi.fn();
    vi.stubGlobal("URL", {
      createObjectURL: failure === "unsupported" ? undefined : () => { throw new Error("unavailable"); },
      revokeObjectURL: revokeUrl,
    });
    const starter = createStarterOwner();
    expect(() => starter.mount()).not.toThrow();
    expect(starter.download()).toEqual({ status: "unavailable" });
    const html = renderStarter(starter.download());
    expect(html).toContain('role="status"');
    expect(html).toContain("Starter download unavailable. This browser could not prepare the file.");
    expect(html).not.toContain("<a ");
    expect(html).not.toContain("<button");
    starter.dispose();
    expect(revokeUrl).not.toHaveBeenCalled();
  });

  it("owns the resource in Arena rather than the conditionally rendered spec panel", () => {
    expect(arenaSource).toContain("const starterDownload = createArenaSafeIrStarterDownload();");
    expect(arenaSource).toContain("<ArenaSafeIrStarterLink download={starterDownload()} />");
    expect(arenaSource).not.toContain("downloadSafeIrStarter");
    expect(arenaSource).not.toContain("queueMicrotask(() => URL.revokeObjectURL");
    expect(arenaSource).not.toContain('document.createElement("a")');
  });
});

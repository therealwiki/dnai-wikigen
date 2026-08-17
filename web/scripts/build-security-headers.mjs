#!/usr/bin/env node

import { chmod, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadEnv } from "vite";
import { renderProductionHeadersForEnv } from "./security-headers-core.mjs";

const modulePath = fileURLToPath(new URL(
  "./build-security-headers.mjs",
  import.meta.url,
));
const webDir = path.resolve(path.dirname(modulePath), "..");
const output = path.join(webDir, "dist", "_headers");
const env = { ...loadEnv("production", webDir, ""), ...process.env };
const headers = renderProductionHeadersForEnv(env);
await writeFile(output, headers, { encoding: "utf8", mode: 0o644 });
await chmod(output, 0o644);
console.log(`security_headers=${output}`);

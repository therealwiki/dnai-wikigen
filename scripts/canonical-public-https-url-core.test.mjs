import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalPublicHttpsOrigin,
  parseCanonicalPublicHttpsUrl,
} from "./canonical-public-https-url-core.mjs";

test("canonical public HTTPS parser accepts only the signed-release subset", () => {
  assert.deepEqual(
    parseCanonicalPublicHttpsUrl("https://api.wikigen.me/compute/workload-encryption-contract"),
    {
      href: "https://api.wikigen.me/compute/workload-encryption-contract",
      hostname: "api.wikigen.me",
      origin: "https://api.wikigen.me",
      pathname: "/compute/workload-encryption-contract",
      port: "",
    },
  );
  assert.equal(
    canonicalPublicHttpsOrigin("https://www.wikigen.me"),
    "https://www.wikigen.me",
  );
  assert.equal(
    parseCanonicalPublicHttpsUrl("https://rpc.wikigen.me:8443/base", {
      allowPort: true,
    }).port,
    "8443",
  );
  for (const value of [
    "http://api.wikigen.me/path",
    "https://user@api.wikigen.me/path",
    "https://api.wikigen.me:443/path",
    "https://api.wikigen.me//path",
    "https://api.wikigen.me/../path",
    "https://api.wikigen.me/path?query=1",
    "https://api.wikigen.me/path#fragment",
    "https://127.0.0.1/path",
    "https://localhost/path",
    "https://API.wikigen.me/path",
    "https://api.wikigen.me/%2f",
    "https://api.wikigen.me/%2E%2E/path",
    "https://api.wikigen.me/%2Fpath",
  ]) {
    assert.throws(() => parseCanonicalPublicHttpsUrl(value), /canonical public HTTPS/);
  }
});

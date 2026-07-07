import type { SubstrateClaim, VerificationBundle } from "../lib/dstackVerifier";

/**
 * A REAL attestation bundle captured live on 2026-07-07 from amiller's
 * dstack-webhost tee-daemon (project "timelock"), running in a Phala Intel TDX
 * CVM. The giant TDX quote / event-log hex is truncated here for size — the
 * "verify live" button fetches the full, current bundle. This fixture is the
 * offline fallback and is genuine evidence, not a mock.
 *
 * Source of truth: GET {DAEMON_BASE}/_api/verification/timelock
 */
export const CAPTURED_AT = "2026-07-07";

export const CAPTURED_VERIFICATION: VerificationBundle = {
  "schema_version": "1.0.0",
  "platform_quote": {
    "quote": "040002008100000000000000939a7233f79c4ca9940a0db3957f06074d79685452a1c5725d6ff7f9d09c91b4000000000b0105000000000000000000000000007bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\u2026[+9692 hex chars \u2014 fetch live for the full quote]",
    "event_log": "[{\"imr\":0,\"event_type\":2147483659,\"digest\":\"5b684faf8d02a733945f821d9cdd170802e72103977acf66949c9382500283adc90cbec57f8e7653f8bee1cab83689de\",\"event\":\"\",\"event_\u2026[+4767 hex chars \u2014 fetch live for the full quote]",
    "report_data": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "vm_config": "{\"os_image_hash\":\"9b6a523983685016c0bf4a8a4ad930f86d283e5308c30e10fc0136db7c85f1fe\",\"cpu_count\":2,\"memory_size\":4294967296,\"qemu_version\":\"8.2.2\",\"pci_hole64_size\":0,\"hugepages\":false,\"num_gpus\":0,\"num_nvswitches\":0,\"hotplug_off\":false,\"image\":\"dstack-dev-0.5.7-9b6a5239\",\"host_share_mode\":\"9p\",\"spec_version\":1}"
  },
  "webhost_app_id": "",
  "onchain": {
    "chain_id": 0,
    "kms_contract": "",
    "dstackapp": "",
    "allowed_compose_hash": "",
    "allowed_os_image": ""
  },
  "gateway": {
    "domain": "",
    "app_id": "",
    "zt_cert_ref": ""
  },
  "app": {
    "project": "timelock",
    "source": {
      "repo": "https://github.com/amiller/timelock",
      "ref": "main",
      "commit_sha": "510b4e2645dce51eef6a44f2688924f3892ce884",
      "tree_hash": "573fb4642ba9798b36b80c544803ec8165c1d0e8",
      "tree_hash_kind": "git"
    },
    "image_digest": "sha256:9bd6fcaf0bebf504f5972c856be09f327a35e6af975db65b64549ef970535d8e",
    "binding_quote": {
      "signature_chain": [
        "d2fe5fd665afcf9fed0d5678074e70f2ef29cdc8b539ba15f87b6b9517e95ca12610c7b1c879a873f365b77a64891978419c3e65ab1a0ccd052e67e71e2e2b7c00",
        "70ed08509eeec505dbaf95ac919cd375835f9997e55e200eb4f17860d7fab20021211d33cd011f1d36cf11df93dec7b30ad66bc02d7bb92055f0eb18051faa3901"
      ],
      "pubkey": "039e9a4f47315f11d10dee3140f69d4db0c5eab12bea7bfbfd715324899c3e3e87"
    }
  }
} as VerificationBundle;

export const CAPTURED_SUBSTRATE: SubstrateClaim = {
  "container_runtime": "runsc",
  "effective_runtime": "runsc",
  "isolation_modes": [
    "shared",
    "container"
  ],
  "deno_entry_shim_sha256": "76f995f51b2b90adb60efaf12b7a97776513fc341493d75849671bc03cdc54a3",
  "networks": [
    "tee-apps-dev",
    "tee-apps-attested"
  ]
} as SubstrateClaim;

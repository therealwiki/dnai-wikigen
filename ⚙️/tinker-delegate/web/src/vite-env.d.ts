/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Absolute URL of a tee-daemon that hosts THIS app (set by deploy-gate.sh). */
  readonly VITE_TEE_DAEMON_URL?: string;
  /** Project name this app is hosted under on that daemon. */
  readonly VITE_TEE_PROJECT?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

import type { Locality, LocalityMeta } from "../types";

/**
 * The deployment spine. Locality is the primary axis of the whole publication:
 * "does the owner's data have to leave for this to work?" Color is information,
 * not decoration — and is always paired with the text label below.
 */
export const LOCALITIES: Record<Locality, LocalityMeta> = {
  "on-device": {
    id: "on-device",
    label: "On-device",
    klass: "stays-local",
    colorVar: "--local-teal",
    blurb: "Runs on the owner's phone, wearable, or laptop. Nothing leaves.",
  },
  enclave: {
    id: "enclave",
    label: "Enclave / on-prem",
    klass: "stays-local",
    colorVar: "--enclave-cyan",
    blurb:
      "Runs beside the data inside a confidential-compute enclave. Operators cannot read raw values.",
  },
  hybrid: {
    id: "hybrid",
    label: "Hybrid",
    klass: "caution",
    colorVar: "--caution-olive",
    blurb: "Self-hostable, but calls out to a general model. Egress must be gated.",
  },
  "api-only": {
    id: "api-only",
    label: "API-only",
    klass: "data-leaves",
    colorVar: "--leave-amber",
    blurb: "Capability lives behind a third party; data transits, so it needs the strictest gating.",
  },
};

export const LOCALITY_ORDER: Locality[] = ["on-device", "enclave", "hybrid", "api-only"];

export const LOCALITY_CLASS_LABEL: Record<string, string> = {
  "stays-local": "Stays local",
  caution: "Caution",
  "data-leaves": "Data leaves",
};

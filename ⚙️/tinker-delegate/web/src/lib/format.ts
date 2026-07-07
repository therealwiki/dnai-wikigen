import type { AttestationOutcome, Decision, Locality, SensitivityTier } from "../types";
import { LOCALITIES } from "../data/localities";

export const DECISION_LABEL: Record<Decision, string> = {
  pass: "Pass",
  hold: "Hold · human review",
  deny: "Deny",
};

/** CSS custom-property name for a decision's color. */
export const DECISION_COLOR: Record<Decision, string> = {
  pass: "--pass",
  hold: "--hold",
  deny: "--deny",
};

export const OUTCOME_LABEL: Record<AttestationOutcome, string> = {
  cleared: "CLEARED",
  stopped: "STOPPED",
};

export const SENSITIVITY_LABEL: Record<SensitivityTier, string> = {
  low: "Low sensitivity",
  med: "Medium sensitivity",
  high: "High sensitivity",
  restricted: "Restricted",
};

export const SENSITIVITY_RANK: Record<SensitivityTier, number> = {
  low: 0,
  med: 1,
  high: 2,
  restricted: 3,
};

export function localityLabel(locality: Locality): string {
  return LOCALITIES[locality].label;
}

export function localityColorVar(locality: Locality): string {
  return LOCALITIES[locality].colorVar;
}

/** e.g. 0.02 -> "$0.02 / query"; 0 -> "no royalty". */
export function formatRoyalty(v: number): string {
  if (!v) return "no royalty";
  return `$${v.toFixed(v < 0.01 ? 4 : 3).replace(/0+$/, "").replace(/\.$/, ".0")} / query`;
}

export function titleCase(slug: string): string {
  return slug
    .split(/[-_\s]+/)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/** Short relative-ish label for an iso timestamp (stable, no locale surprises). */
export function isoTime(iso: string): string {
  return iso.replace("T", " ").replace("Z", " UTC").replace(/\.\d+/, "");
}

import type { EnclaveRef, IdentityRef } from "../types";

/** Synthetic principals. No real people. `verified: false` => stage 1 denies. */
export const IDENTITIES: Record<string, IdentityRef> = {
  patientOwner: {
    ref: "did:key:z6Mk-owner-4a1c",
    displayName: "Data owner (self)",
    role: "patient",
    verified: true,
  },
  clinicianCardio: {
    ref: "org:meridian-cardio/clinician-114",
    displayName: "Dr. A. Okafor (attending, cardiology)",
    role: "clinician",
    verified: true,
    org: "Meridian Cardiology",
  },
  clinicianGenomics: {
    ref: "org:helix-clinic/clinician-233",
    displayName: "Dr. R. Vasquez (clinical geneticist)",
    role: "clinician",
    verified: true,
    org: "Helix Clinical Genetics",
  },
  researcherLongevity: {
    ref: "org:northwind-longevity/researcher-51",
    displayName: "Dr. M. Chen (longevity researcher)",
    role: "researcher",
    verified: true,
    org: "Northwind Longevity Lab",
  },
  biopharmaScientist: {
    ref: "org:atlas-bio/scientist-907",
    displayName: "Atlas Bio — assay team",
    role: "biopharma",
    verified: true,
    org: "Atlas Bio",
  },
  unverifiedRequester: {
    ref: "anon:unattested-req",
    displayName: "Unverified requester",
    role: "researcher",
    verified: false,
  },
  ethicsReviewer: {
    ref: "org:wikigen/ethics-board",
    displayName: "wikigen Ethics & Legal Review Board",
    role: "auditor",
    verified: true,
    org: "wikigen.me",
  },
  humanReviewer: {
    ref: "org:wikigen/access-review",
    displayName: "Access Review Officer",
    role: "operator",
    verified: true,
    org: "wikigen.me",
  },
};

/** Synthetic confidential-compute enclaves. */
export const ENCLAVES: Record<string, EnclaveRef> = {
  phalaCvm: {
    ref: "enclave://phala/cvm-8f21a4",
    platform: "intel-tdx",
    region: "us-west",
  },
  onPremSev: {
    ref: "enclave://meridian/onprem-sev-02",
    platform: "amd-sev-snp",
    region: "on-prem",
  },
  deviceSecure: {
    ref: "enclave://device/secure-enclave",
    platform: "on-device-secure-enclave",
    region: "device-local",
  },
};

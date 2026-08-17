/**
 * Immutable protocol identifier shared by pure authority validation and the
 * effectful filesystem lock implementation.
 *
 * Keeping this leaf capability-free prevents a receipt parser from acquiring
 * filesystem, process, or randomness authority merely to compare a string.
 */
export const RELEASE_CEREMONY_LOCK_PROTOCOL = "dnai.release-ceremony-lock.v1";

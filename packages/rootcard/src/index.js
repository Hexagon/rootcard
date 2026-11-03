// rootcard: a portable, self-certifying identity for online logins.
//
// This package mirrors the `rootcard` Rust crate byte for byte. The normative format is spec/SPEC.md in the repository,
// and spec/vectors/ holds the shared test vectors both implementations must reproduce.
//
// Status: skeleton (phase 0). Nothing here is stable.

/** Version of the wire and storage format described by the specification. */
export const FORMAT_VERSION = 1;

/** Prefix of every domain-separation label (`rootcard/<purpose>/v<n>`). */
export const LABEL_PREFIX = "rootcard/";

/**
 * Build a domain-separation label, e.g. `label("id", 1) === "rootcard/id/v1"`.
 * @param {string} purpose
 * @param {number} version
 * @returns {string}
 */
export function label(purpose, version) {
  return `${LABEL_PREFIX}${purpose}/v${version}`;
}

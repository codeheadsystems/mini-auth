package com.codeheadsystems.minitoken.auth;

/**
 * The data-plane operations a client may be granted against a key group.
 *
 * <p>This is a deliberate mirror of mini-kms's {@code KeyOperation} enum. mini-idp does not
 * <em>perform</em> any of these operations; it only names them so that an issued token can
 * carry a set of granted operations per key group. When the future mini-kms verifies one of
 * our tokens it can map this set straight onto its own {@code KeyOperation} and a per-key-group
 * {@code PolicyEngine} decision (mini-policy) without a translation table.
 *
 * <p>Keep these names byte-for-byte identical to mini-kms's enum constants — the contract is
 * the string value that travels in the JWT claim, so a rename here silently breaks the KMS's
 * ability to parse a grant.
 */
public enum KeyOperation {
  /** GenerateDataKey against a group. */
  GENERATE_DATA_KEY,
  /** Encrypt under a group. */
  ENCRYPT,
  /** Decrypt a blob (group taken from the blob). */
  DECRYPT,
  /** Re-encrypt to a destination group. */
  RE_ENCRYPT
}

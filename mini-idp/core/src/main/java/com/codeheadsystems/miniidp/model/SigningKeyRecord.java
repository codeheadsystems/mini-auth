package com.codeheadsystems.miniidp.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A signing key in the signing-key set, including its private key material.
 *
 * <p>The private key is stored as base64 PKCS#8. The file backing the signing-key set is written
 * 0600 by {@link com.codeheadsystems.miniidp.store.JsonStore}. <b>A real deployment would wrap
 * the private key under a KMS</b> (the eventual recursive integration with mini-kms) rather than
 * holding it as a local base64 blob; that is intentionally out of scope here, and the field is
 * named to make the at-rest material obvious.
 *
 * @param kid                key identifier (echoed in each token's JWS {@code kid} header and JWK).
 * @param privatePkcs8Base64 the Ed25519 private key, PKCS#8 DER, base64. Secret at rest.
 * @param publicSpkiBase64   the Ed25519 public key, X.509 SPKI DER, base64. Public.
 * @param active             whether this is the current signing key (exactly one key is active).
 * @param createdAt          creation time (epoch seconds).
 * @param retiredAt          retirement time (epoch seconds), or null while active. A retired key
 *                           stays published in JWKS until every token it could have signed expires.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SigningKeyRecord(
    String kid,
    String privatePkcs8Base64,
    String publicSpkiBase64,
    boolean active,
    long createdAt,
    Long retiredAt) {

  /** @return a copy marked retired at the given time (no longer the active signer). */
  public SigningKeyRecord retiredAt(final long when) {
    return new SigningKeyRecord(kid, privatePkcs8Base64, publicSpkiBase64, false, createdAt, when);
  }
}

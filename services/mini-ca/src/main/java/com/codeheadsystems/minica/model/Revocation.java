package com.codeheadsystems.minica.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A revoked certificate on the CA's revocation list, keyed by serial.
 *
 * <p>Short leaf TTLs are the primary control — most certs simply expire — but a revocation lets an
 * operator kill a specific outstanding leaf before its {@code notAfter}. The list is meant to be
 * polled by a verifier; an entry may be pruned once the cert's own validity has passed.
 *
 * @param serial    the revoked certificate's serial (lowercase hex).
 * @param revokedAt when the revocation was recorded (epoch seconds).
 * @param reason    an optional operator-supplied reason (may be null).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Revocation(String serial, long revokedAt, String reason) {
}

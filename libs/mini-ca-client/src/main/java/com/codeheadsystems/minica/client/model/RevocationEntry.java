package com.codeheadsystems.minica.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * One entry on the CA's revocation list — the client-side copy of mini-ca's {@code Revocation}.
 *
 * @param serial    the revoked certificate's serial (lowercase hex).
 * @param revokedAt when the revocation was recorded (epoch seconds).
 * @param reason    an optional operator-supplied reason (may be null).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RevocationEntry(String serial, long revokedAt, String reason) {
}

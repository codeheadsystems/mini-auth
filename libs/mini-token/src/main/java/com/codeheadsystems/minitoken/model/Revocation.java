package com.codeheadsystems.minitoken.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A revoked token id ({@code jti}) on the denylist.
 *
 * <p>Short token TTLs are the primary defence — most tokens simply expire — but a revocation lets
 * an operator kill a specific outstanding token before its {@code exp}. The denylist is meant to
 * be polled by a verifier (mini-kms); an entry can be dropped once {@code expiresAt} has passed,
 * because by then the token is invalid on expiry grounds anyway.
 *
 * @param jti       the revoked token id.
 * @param revokedAt when the revocation was recorded (epoch seconds).
 * @param expiresAt the revoked token's own expiry (epoch seconds); the entry may be pruned after this.
 * @param reason    optional operator-supplied reason (may be null).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Revocation(String jti, long revokedAt, long expiresAt, String reason) {
}

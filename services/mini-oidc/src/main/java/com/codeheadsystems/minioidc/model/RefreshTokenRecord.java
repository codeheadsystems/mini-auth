package com.codeheadsystems.minioidc.model;

import java.util.List;

/**
 * A rotating refresh token (for humans), letting a session outlive the short access-token TTL
 * without re-running the passkey ceremony.
 *
 * <p>Refresh tokens rotate on every use: redeeming one marks it {@code used} and issues a successor
 * in the same {@code familyId}. Presenting an already-used token is a replay — the whole family is
 * revoked (a stolen token can't outlive one use). Only the SHA-256 {@code secretHash} is stored, so
 * the at-rest store holds no usable bearer value. (This is mini-oidc's own opaque-token primitive,
 * modeled on pk-auth-refresh-tokens' family-rotation design; it is NOT a JWS, so it does not touch
 * the token plane.)
 *
 * @param id         the token id (the clear half of the wire value {@code id.secret}; the family handle).
 * @param secretHash SHA-256 of the secret half (the lookup/verification value).
 * @param familyId   the rotation family this token belongs to (the root id).
 * @param clientId   the client the token was issued to.
 * @param subject    the authenticated principal id.
 * @param scopes     the scopes carried forward to refreshed tokens.
 * @param used       whether this token has already been rotated (a second use is a replay).
 * @param revoked    whether this token (or its family) has been revoked.
 * @param expiresAt  expiry (epoch seconds).
 * @param authTime   when the human originally authenticated (epoch seconds), carried unchanged
 *                   across rotations so a refreshed ID token's {@code auth_time} reflects the real
 *                   login — not the refresh — keeping client max-age / re-auth checks honest.
 */
public record RefreshTokenRecord(
    String id,
    String secretHash,
    String familyId,
    String clientId,
    String subject,
    List<String> scopes,
    boolean used,
    boolean revoked,
    long expiresAt,
    long authTime) {

  public RefreshTokenRecord {
    scopes = scopes == null ? List.of() : List.copyOf(scopes);
  }

  /** @return a copy marked used (rotated). */
  public RefreshTokenRecord markUsed() {
    return new RefreshTokenRecord(id, secretHash, familyId, clientId, subject, scopes, true, revoked, expiresAt, authTime);
  }

  /** @return a copy marked revoked. */
  public RefreshTokenRecord revoke() {
    return new RefreshTokenRecord(id, secretHash, familyId, clientId, subject, scopes, used, true, expiresAt, authTime);
  }
}

package com.codeheadsystems.minioidc.service;

import com.codeheadsystems.minioidc.model.RefreshTokenRecord;
import com.codeheadsystems.minioidc.util.Tokens;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rotating refresh tokens for humans, with family-based replay defense.
 *
 * <p>Each refresh token is a {@code id.secret} wire value; only the secret's SHA-256 is stored.
 * Redeeming a token ({@link #rotate}) marks it used and issues a successor in the same family. A
 * second use of an already-used token is a replay — the whole family is revoked, so a stolen token
 * cannot outlive one use. Every failure (unknown, expired, revoked, wrong client, replayed) returns
 * the same empty result: the token endpoint surfaces one generic {@code invalid_grant}, never an
 * oracle. In-memory, modeled on pk-auth-refresh-tokens' design; this is an opaque token, not a JWS,
 * so it does not touch the token plane.
 */
public final class RefreshTokenService {

  private final Clock clock;
  private final Tokens tokens;
  private final Duration ttl;
  private final Map<String, RefreshTokenRecord> byId = new ConcurrentHashMap<>();

  public RefreshTokenService(final Clock clock, final Tokens tokens, final Duration ttl) {
    this.clock = clock;
    this.tokens = tokens;
    this.ttl = ttl;
  }

  /**
   * Issue a fresh refresh token (the root of a new rotation family).
   *
   * @return the {@code id.secret} wire value to hand the client (only its hash is stored).
   */
  public synchronized String issue(final String clientId, final String subject, final List<String> scopes) {
    final String id = tokens.newRefreshId();
    return mint(id, id, clientId, subject, scopes);
  }

  /**
   * Rotate a presented refresh token: verify it, mark it used, and issue its successor.
   *
   * @param wireToken the presented {@code id.secret}.
   * @param clientId  the client presenting it (must match the token's client).
   * @return the rotated grant (new wire token + carried-forward subject/scopes), or empty on ANY
   *     failure (a replay additionally scorches the whole family).
   */
  public synchronized Optional<Rotated> rotate(final String wireToken, final String clientId) {
    final int dot = wireToken == null ? -1 : wireToken.indexOf('.');
    if (dot <= 0) {
      return Optional.empty();
    }
    final String id = wireToken.substring(0, dot);
    final String secret = wireToken.substring(dot + 1);
    final RefreshTokenRecord record = byId.get(id);
    if (record == null
        || !Tokens.constantTimeEquals(record.secretHash(), Tokens.sha256(secret))
        || !record.clientId().equals(clientId)) {
      return Optional.empty();
    }
    if (record.revoked() || clock.instant().getEpochSecond() >= record.expiresAt()) {
      return Optional.empty();
    }
    if (record.used()) {
      // Replay of an already-rotated token: revoke the entire family.
      revokeFamily(record.familyId());
      return Optional.empty();
    }
    byId.put(id, record.markUsed());
    final String successor = tokens.newRefreshId();
    final String wire = mint(successor, record.familyId(), record.clientId(), record.subject(), record.scopes());
    return Optional.of(new Rotated(wire, record.subject(), record.scopes()));
  }

  /** Revoke every token in a family (replay response). */
  public synchronized void revokeFamily(final String familyId) {
    byId.replaceAll((id, record) -> record.familyId().equals(familyId) ? record.revoke() : record);
  }

  /** Revoke every token for a subject (logout-everywhere). */
  public synchronized void revokeForSubject(final String subject) {
    byId.replaceAll((id, record) -> record.subject().equals(subject) ? record.revoke() : record);
  }

  private String mint(final String id, final String familyId, final String clientId,
                      final String subject, final List<String> scopes) {
    final String secret = tokens.newRefreshSecret();
    byId.put(id, new RefreshTokenRecord(id, Tokens.sha256(secret), familyId, clientId, subject,
        scopes, false, false, clock.instant().getEpochSecond() + ttl.toSeconds()));
    return id + "." + secret;
  }

  /**
   * A successful rotation.
   *
   * @param wireToken the new refresh token to return to the client.
   * @param subject   the principal the token is for.
   * @param scopes    the scopes carried forward.
   */
  public record Rotated(String wireToken, String subject, List<String> scopes) {
  }
}

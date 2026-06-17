package com.codeheadsystems.minioidc.service;

import com.codeheadsystems.minioidc.model.AuthorizationCode;
import java.time.Clock;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Issues and redeems one-time authorization codes, with replay detection.
 *
 * <p>A code is single-use: {@link #consume} removes it and remembers that it was used. If the same
 * code is presented again ({@link #wasUsed}), it is a replay — the token endpoint then revokes the
 * refresh-token family that the first redemption produced ({@link #familyFor}), per OIDC's guidance
 * that a replayed code SHOULD revoke the tokens previously issued from it. Codes are short-lived and
 * in-memory.
 */
public final class AuthorizationCodeStore {

  private final Clock clock;
  private final Map<String, AuthorizationCode> active = new ConcurrentHashMap<>();
  // code -> the refresh-token family issued at first redemption (empty string until bound).
  private final Map<String, String> used = new ConcurrentHashMap<>();

  public AuthorizationCodeStore(final Clock clock) {
    this.clock = clock;
  }

  /** Store a freshly issued code. */
  public void put(final AuthorizationCode code) {
    active.put(code.code(), code);
  }

  /**
   * Redeem a code exactly once.
   *
   * @return the code record if it was active and unexpired; empty if unknown, expired, or already
   *     used (a used code is recorded so {@link #wasUsed} can flag the replay).
   */
  public synchronized Optional<AuthorizationCode> consume(final String code) {
    final AuthorizationCode record = code == null ? null : active.remove(code);
    if (record == null) {
      return Optional.empty();
    }
    if (clock.instant().getEpochSecond() >= record.expiresAt()) {
      return Optional.empty();
    }
    used.put(code, "");
    return Optional.of(record);
  }

  /** @return whether this code was already redeemed (so a re-presentation is a replay). */
  public boolean wasUsed(final String code) {
    return code != null && used.containsKey(code);
  }

  /** Record the refresh-token family produced when a code was redeemed (for replay revocation). */
  public void bindFamily(final String code, final String familyId) {
    if (used.containsKey(code)) {
      used.put(code, familyId);
    }
  }

  /** @return the refresh-token family bound to a used code, if any. */
  public Optional<String> familyFor(final String code) {
    final String family = used.get(code);
    return family == null || family.isEmpty() ? Optional.empty() : Optional.of(family);
  }
}

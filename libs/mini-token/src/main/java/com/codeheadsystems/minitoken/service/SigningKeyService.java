package com.codeheadsystems.minitoken.service;

import com.codeheadsystems.minitoken.crypto.Ed25519Keys;
import com.codeheadsystems.minitoken.jwks.Jwk;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.model.SigningKeyRecord;
import com.codeheadsystems.minitoken.store.DocumentStore;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import com.codeheadsystems.minitoken.util.RandomIds;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages the Ed25519 signing keys: exactly one <b>active</b> key signs new tokens, while recently
 * <b>retired</b> keys stay published in the JWKS so tokens they already signed keep verifying
 * until they expire.
 *
 * <p>Rotation ({@link #rotate}) generates a fresh key, marks it active, and demotes the previous
 * active key to retired (timestamped). A retired key is dropped from the published set only once
 * it has been retired longer than {@code retiredKeyRetention} — which must exceed the maximum
 * token TTL, so no live token is ever left with an unpublished {@code kid}.
 *
 * <p>State is persisted via the {@link DocumentStore} SPI; the document holds private keys, so a
 * file-backed implementation should restrict it to owner-only ({@code 0600}). All methods are
 * {@code synchronized}; rotation is rare and signing is cheap, so a single lock is adequate.
 */
public final class SigningKeyService {

  private final DocumentStore<SigningKeys> store;
  private final RandomIds ids;
  private final Clock clock;
  private final Duration retiredKeyRetention;
  private final List<SigningKeyRecord> keys = new ArrayList<>();
  private String activeKid;

  /**
   * @param store               the backing JSON store (created/initialized on first use).
   * @param ids                 the random kid generator.
   * @param clock               the clock for created/retired timestamps and pruning.
   * @param retiredKeyRetention how long a retired key stays published; must exceed the token TTL.
   */
  public SigningKeyService(final DocumentStore<SigningKeys> store, final RandomIds ids,
                           final Clock clock, final Duration retiredKeyRetention) {
    this.store = store;
    this.ids = ids;
    this.clock = clock;
    this.retiredKeyRetention = retiredKeyRetention;
    if (store.exists()) {
      final SigningKeys loaded = store.load();
      keys.addAll(loaded.keys());
      activeKid = loaded.activeKid();
    }
    if (activeKid == null || findActive() == null) {
      // First run (or an empty/garbled set): mint the initial signing key.
      generateActive();
      persist();
    }
  }

  /** @return the current active signer (kid + private key) for issuing new tokens. */
  public synchronized Signer currentSigner() {
    final SigningKeyRecord active = findActive();
    if (active == null) {
      throw new IllegalStateException("no active signing key");
    }
    return new Signer(active.kid(), Ed25519Keys.decodePrivate(active.privatePkcs8Base64()));
  }

  /**
   * The published JWK Set: every key still retained (active + not-yet-expired retired keys).
   *
   * <p>Pruning of long-retired keys happens here lazily, so the served set never advertises a key
   * that can no longer be backing any live token.
   */
  public synchronized JwkSet jwkSet() {
    pruneExpiredRetired();
    final List<Jwk> jwks = new ArrayList<>();
    for (final SigningKeyRecord key : keys) {
      jwks.add(Jwk.forEd25519(key.kid(), Ed25519Keys.decodePublic(key.publicSpkiBase64())));
    }
    return new JwkSet(jwks);
  }

  /**
   * Rotate the signing key: retire the current active key and activate a fresh one.
   *
   * @return the new active kid.
   */
  public synchronized String rotate() {
    final long now = clock.instant().getEpochSecond();
    final List<SigningKeyRecord> updated = new ArrayList<>();
    for (final SigningKeyRecord key : keys) {
      updated.add(key.active() ? key.retiredAt(now) : key);
    }
    keys.clear();
    keys.addAll(updated);
    generateActive();
    pruneExpiredRetired();
    persist();
    return activeKid;
  }

  /** @return the active kid (for diagnostics/tests). */
  public synchronized String activeKid() {
    return activeKid;
  }

  private void generateActive() {
    final KeyPair pair = Ed25519Keys.generate();
    final String kid = ids.newKid();
    keys.add(new SigningKeyRecord(
        kid,
        Ed25519Keys.encodePrivate(pair.getPrivate()),
        Ed25519Keys.encodePublic(pair.getPublic()),
        true,
        clock.instant().getEpochSecond(),
        null));
    activeKid = kid;
  }

  private void pruneExpiredRetired() {
    final long cutoff = clock.instant().getEpochSecond() - retiredKeyRetention.toSeconds();
    keys.removeIf(key -> !key.active() && key.retiredAt() != null && key.retiredAt() < cutoff);
  }

  private SigningKeyRecord findActive() {
    for (final SigningKeyRecord key : keys) {
      if (key.active() && key.kid().equals(activeKid)) {
        return key;
      }
    }
    return null;
  }

  private void persist() {
    store.save(new SigningKeys(activeKid, new ArrayList<>(keys)));
  }

  /**
   * The material needed to sign a token: the key id (for the JWS {@code kid} header) and the
   * Ed25519 private key.
   *
   * @param kid        the active key id.
   * @param privateKey the active private key.
   */
  public record Signer(String kid, PrivateKey privateKey) {
  }
}

package com.codeheadsystems.minitoken.service;

import com.codeheadsystems.minitoken.crypto.SigningAlgorithm;
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
import java.util.Base64;
import java.util.List;

/**
 * Manages one algorithm's signing keys (Ed25519 by default, or ES256): exactly one <b>active</b> key signs new tokens, while recently
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
 *
 * <p><b>Pre-published next key (opt-in).</b> With {@code prePublishNextKey}, the set also holds a
 * <b>next</b> key: generated ahead of time and published in the JWKS, but not yet signing. Rotation
 * promotes it to active and generates a fresh next key. So the kid a token is signed with after a
 * rotation has been in the JWKS since the <em>previous</em> rotation (or startup), and a verifier
 * holding a cached JWKS already has it: it never meets an unknown kid right after a rotation, which
 * matters when its JWKS refetch is rate-limited (Nimbus, as config-server uses it, refetches at most
 * twice per 30 seconds). Only two rotations within one verifier cache period still force a refetch.
 * A next key is persisted like the others, with {@code active=false} and {@code retiredAt=null}, so
 * the document shape is unchanged; it is never pruned (pruning only drops retired keys).
 *
 * <p><b>One service per algorithm.</b> An issuer that signs with both Ed25519 and ES256 (mini-idp,
 * when an audience is mapped to ES256) runs two of these over two stores, so each algorithm has its
 * own active key, kid, rotation and retention, and the existing Ed25519 file is untouched. The
 * persisted record shape is the same for both (PKCS#8 + SPKI, base64); the service's algorithm says
 * how to read it.
 */
public final class SigningKeyService {

  private final DocumentStore<SigningKeys> store;
  private final SigningAlgorithm algorithm;
  private final RandomIds ids;
  private final Clock clock;
  private final Duration retiredKeyRetention;
  private final boolean prePublishNextKey;
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
    this(store, SigningAlgorithm.EDDSA, ids, clock, retiredKeyRetention);
  }

  /**
   * @param store               the backing JSON store, holding only keys of {@code algorithm}.
   * @param algorithm           the algorithm every key in this set signs with.
   * @param ids                 the random kid generator.
   * @param clock               the clock for created/retired timestamps and pruning.
   * @param retiredKeyRetention how long a retired key stays published; must exceed the token TTL.
   */
  public SigningKeyService(final DocumentStore<SigningKeys> store, final SigningAlgorithm algorithm,
                           final RandomIds ids, final Clock clock, final Duration retiredKeyRetention) {
    this(store, algorithm, ids, clock, retiredKeyRetention, false);
  }

  /**
   * @param store               the backing JSON store, holding only keys of {@code algorithm}.
   * @param algorithm           the algorithm every key in this set signs with.
   * @param ids                 the random kid generator.
   * @param clock               the clock for created/retired timestamps and pruning.
   * @param retiredKeyRetention how long a retired key stays published; must exceed the token TTL.
   * @param prePublishNextKey   keep a published-but-not-yet-signing next key, so the kid that signs
   *                            after a rotation was already in the JWKS before it (see class doc).
   */
  public SigningKeyService(final DocumentStore<SigningKeys> store, final SigningAlgorithm algorithm,
                           final RandomIds ids, final Clock clock, final Duration retiredKeyRetention,
                           final boolean prePublishNextKey) {
    if (algorithm == null) {
      throw new IllegalArgumentException("algorithm must not be null");
    }
    if (retiredKeyRetention == null || retiredKeyRetention.isNegative() || retiredKeyRetention.isZero()) {
      // The full invariant — retention MUST exceed the max token TTL, or a token signed just before
      // a rotation can outlive its kid in the JWKS and fail verification — is a numeric relationship
      // the caller must uphold (this service does not know the issuer's TTL). We at least refuse a
      // non-positive retention, which would drop a freshly retired key immediately.
      throw new IllegalArgumentException("retiredKeyRetention must be positive and exceed the max token TTL");
    }
    this.store = store;
    this.algorithm = algorithm;
    this.ids = ids;
    this.clock = clock;
    this.retiredKeyRetention = retiredKeyRetention;
    this.prePublishNextKey = prePublishNextKey;
    boolean changed = false;
    if (store.exists()) {
      final SigningKeys loaded = store.load();
      keys.addAll(loaded.keys());
      activeKid = loaded.activeKid();
    }
    if (activeKid == null || findActive() == null) {
      // First run (or an empty/garbled set): mint the initial signing key.
      generateActive();
      changed = true;
    }
    if (prePublishNextKey && findNext() == null) {
      // First run, or a set written before pre-publication was turned on: publish a next key now.
      keys.add(newKey(false));
      changed = true;
    }
    if (changed) {
      persist();
    }
  }

  /** @return the current active signer (kid + private key) for issuing new tokens. */
  public synchronized Signer currentSigner() {
    final SigningKeyRecord active = findActive();
    if (active == null) {
      throw new IllegalStateException("no active signing key");
    }
    return new Signer(active.kid(), algorithm.decodePrivate(active.privatePkcs8Base64()), algorithm);
  }

  /**
   * The published JWK Set: every key still retained (active, the next key if pre-published, and
   * not-yet-expired retired keys).
   *
   * <p>Pruning of long-retired keys happens here lazily, so the served set never advertises a key
   * that can no longer be backing any live token.
   */
  public synchronized JwkSet jwkSet() {
    pruneExpiredRetired();
    final List<Jwk> jwks = new ArrayList<>();
    for (final SigningKeyRecord key : keys) {
      jwks.add(algorithm.jwk(key.kid(), algorithm.decodePublic(key.publicSpkiBase64())));
    }
    return new JwkSet(jwks);
  }

  /**
   * Rotate the signing key: retire the current active key and activate the next one. The next key
   * is the pre-published one if there is one (it is already in the JWKS), else a fresh key. With
   * {@code prePublishNextKey}, a new next key is then generated and published.
   *
   * @return the new active kid.
   */
  public synchronized String rotate() {
    final long now = clock.instant().getEpochSecond();
    final SigningKeyRecord next = findNext();
    final List<SigningKeyRecord> updated = new ArrayList<>();
    for (final SigningKeyRecord key : keys) {
      if (key.active()) {
        updated.add(key.retiredAt(now));
      } else if (key == next) {
        updated.add(key.activated());
      } else {
        updated.add(key);
      }
    }
    keys.clear();
    keys.addAll(updated);
    if (next != null) {
      // Promote even when pre-publication is off: the key is already published, so use it.
      activeKid = next.kid();
    } else {
      generateActive();
    }
    if (prePublishNextKey) {
      keys.add(newKey(false));
    }
    pruneExpiredRetired();
    persist();
    return activeKid;
  }

  /** @return the pre-published next kid, or null when there is none. */
  public synchronized String nextKid() {
    final SigningKeyRecord next = findNext();
    return next == null ? null : next.kid();
  }

  /** @return the algorithm every key in this set signs with. */
  public SigningAlgorithm algorithm() {
    return algorithm;
  }

  /** @return the active kid (for diagnostics/tests). */
  public synchronized String activeKid() {
    return activeKid;
  }

  private void generateActive() {
    final SigningKeyRecord key = newKey(true);
    keys.add(key);
    activeKid = key.kid();
  }

  private SigningKeyRecord newKey(final boolean active) {
    final KeyPair pair = algorithm.generate();
    // PKCS#8 / SPKI DER, base64 — the same at-rest encoding for every algorithm.
    return new SigningKeyRecord(
        ids.newKid(),
        Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
        Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
        active,
        clock.instant().getEpochSecond(),
        null);
  }

  /** The next key: not active and never retired. At most one exists. */
  private SigningKeyRecord findNext() {
    for (final SigningKeyRecord key : keys) {
      if (!key.active() && key.retiredAt() == null) {
        return key;
      }
    }
    return null;
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
   * The material needed to sign a token: the key id (for the JWS {@code kid} header), the private
   * key, and the algorithm it signs with (for the JWS {@code alg} header).
   *
   * @param kid        the active key id.
   * @param privateKey the active private key.
   * @param algorithm  the key's signature algorithm.
   */
  public record Signer(String kid, PrivateKey privateKey, SigningAlgorithm algorithm) {

    /** An Ed25519 signer (the historical two-field form). */
    public Signer(final String kid, final PrivateKey privateKey) {
      this(kid, privateKey, SigningAlgorithm.EDDSA);
    }
  }
}

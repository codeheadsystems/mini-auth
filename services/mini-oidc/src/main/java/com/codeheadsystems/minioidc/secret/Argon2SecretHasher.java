package com.codeheadsystems.minioidc.secret;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Hashes and verifies service-account secrets with Argon2id (Bouncy Castle).
 *
 * <p>This mirrors mini-kms's {@code Argon2KeyDeriver}: Argon2id is a memory-hard password hash,
 * so even if the directory file leaks, recovering a service-account secret from its stored
 * {@link SecretHash} is deliberately expensive. Each secret gets a fresh random salt, which
 * defeats precomputation and ensures two clients with the same secret hash differently.
 *
 * <p>The presented/stored secrets are handled as {@code char[]}/{@code byte[]} and the transient
 * UTF-8 byte buffers are zeroed before returning. {@link #verify} compares the recomputed hash to
 * the stored one with {@link MessageDigest#isEqual}, which runs in time independent of how many
 * leading bytes match — no byte-by-byte timing oracle.
 */
public final class Argon2SecretHasher {

  /** Length of the derived hash in bytes. */
  public static final int HASH_LENGTH_BYTES = 32;

  /** Length of the per-secret salt in bytes. */
  public static final int SALT_LENGTH_BYTES = 16;

  private final SecureRandom secureRandom;
  private final Argon2Settings settings;

  /**
   * @param settings the Argon2 cost parameters new hashes are produced with (verification of an
   *                 existing hash always uses the parameters stored in that hash).
   */
  public Argon2SecretHasher(final Argon2Settings settings) {
    this.secureRandom = new SecureRandom();
    this.settings = settings;
  }

  /**
   * Hash a freshly generated service-account secret with a new random salt.
   *
   * @param secret the secret to hash (not mutated; the caller still owns and should zero it).
   * @return the stored hash record (salt + params + hash), safe to persist.
   */
  public SecretHash hash(final char[] secret) {
    if (secret == null || secret.length == 0) {
      throw new IllegalArgumentException("secret must not be empty");
    }
    final byte[] salt = new byte[SALT_LENGTH_BYTES];
    secureRandom.nextBytes(salt);
    final byte[] hash = derive(secret, salt, settings);
    try {
      final Base64.Encoder b64 = Base64.getEncoder();
      return new SecretHash(
          SecretHash.ALGORITHM_ARGON2ID,
          b64.encodeToString(salt),
          b64.encodeToString(hash),
          settings.memoryKiB(),
          settings.iterations(),
          settings.parallelism());
    } finally {
      Arrays.fill(hash, (byte) 0);
    }
  }

  /**
   * Verify a presented secret against a stored hash in constant time.
   *
   * @param presented the secret presented by the client (not mutated; caller should zero it).
   * @param stored    the stored hash to verify against.
   * @return whether the presented secret matches.
   */
  public boolean verify(final char[] presented, final SecretHash stored) {
    if (presented == null || presented.length == 0 || stored == null) {
      return false;
    }
    final byte[] salt = Base64.getDecoder().decode(stored.saltBase64());
    final byte[] expected = Base64.getDecoder().decode(stored.hashBase64());
    // Re-derive using the SAME parameters the stored hash was produced with, not our current
    // defaults, so a later cost bump does not lock existing clients out.
    final byte[] candidate = derive(presented, salt, stored.settings());
    try {
      return MessageDigest.isEqual(expected, candidate);
    } finally {
      Arrays.fill(candidate, (byte) 0);
      Arrays.fill(expected, (byte) 0);
    }
  }

  private static byte[] derive(final char[] secret, final byte[] salt, final Argon2Settings settings) {
    final byte[] secretBytes = toUtf8(secret);
    try {
      final Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
          .withVersion(Argon2Parameters.ARGON2_VERSION_13)
          .withIterations(settings.iterations())
          .withMemoryAsKB(settings.memoryKiB())
          .withParallelism(settings.parallelism())
          .withSalt(salt)
          .build();
      final Argon2BytesGenerator generator = new Argon2BytesGenerator();
      generator.init(params);
      final byte[] hash = new byte[HASH_LENGTH_BYTES];
      generator.generateBytes(secretBytes, hash);
      return hash;
    } finally {
      Arrays.fill(secretBytes, (byte) 0);
    }
  }

  private static byte[] toUtf8(final char[] chars) {
    final java.nio.CharBuffer charBuffer = java.nio.CharBuffer.wrap(chars);
    final java.nio.ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
    final byte[] bytes = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
    Arrays.fill(byteBuffer.array(), (byte) 0);
    return bytes;
  }
}

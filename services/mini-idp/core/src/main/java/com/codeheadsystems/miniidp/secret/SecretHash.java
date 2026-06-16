package com.codeheadsystems.miniidp.secret;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A stored Argon2id hash of a client secret, together with the salt and cost parameters needed
 * to recompute it.
 *
 * <p>This is what the client registry persists in place of the raw secret. It contains no
 * recoverable secret material: the hash is one-way, and the salt/params are not sensitive.
 * Verification re-derives a hash from a presented secret using these exact parameters and
 * compares in constant time (see {@link Argon2SecretHasher#verify}).
 *
 * @param algorithm   the KDF name, always {@code "argon2id"} (recorded for forward compatibility).
 * @param saltBase64  the per-secret random salt (base64).
 * @param hashBase64  the derived hash (base64).
 * @param memoryKiB   Argon2 memory cost used to produce {@code hashBase64}.
 * @param iterations  Argon2 time cost used to produce {@code hashBase64}.
 * @param parallelism Argon2 parallelism used to produce {@code hashBase64}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SecretHash(
    String algorithm,
    String saltBase64,
    String hashBase64,
    int memoryKiB,
    int iterations,
    int parallelism) {

  /** The only KDF currently supported. */
  public static final String ALGORITHM_ARGON2ID = "argon2id";

  /** @return the Argon2 cost parameters this hash was produced with. */
  public Argon2Settings settings() {
    return new Argon2Settings(memoryKiB, iterations, parallelism);
  }
}

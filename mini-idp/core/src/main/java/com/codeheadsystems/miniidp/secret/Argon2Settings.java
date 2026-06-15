package com.codeheadsystems.miniidp.secret;

/**
 * Tunable Argon2id cost parameters used when hashing client secrets.
 *
 * <p>Mirrors mini-kms's {@code Argon2Settings}. The defaults sit comfortably above OWASP's
 * Argon2id floor (19 MiB, t=2, p=1) while hashing in well under a second on commodity hardware.
 * Each stored hash records the parameters it was produced with, so the cost can be raised later
 * without invalidating existing client secrets (verification reads back the stored values).
 *
 * @param memoryKiB   memory cost in kibibytes (the dominant cost).
 * @param iterations  number of passes (time cost).
 * @param parallelism number of parallel lanes.
 */
public record Argon2Settings(int memoryKiB, int iterations, int parallelism) {

  /** Default memory cost: 64 MiB. */
  public static final int DEFAULT_MEMORY_KIB = 64 * 1024;

  /** Default time cost: 3 passes. */
  public static final int DEFAULT_ITERATIONS = 3;

  /** Default parallelism: 1 lane. */
  public static final int DEFAULT_PARALLELISM = 1;

  /** Validate ranges. */
  public Argon2Settings {
    if (memoryKiB < 8) {
      throw new IllegalArgumentException("Argon2 memory must be at least 8 KiB");
    }
    if (iterations < 1) {
      throw new IllegalArgumentException("Argon2 iterations must be at least 1");
    }
    if (parallelism < 1) {
      throw new IllegalArgumentException("Argon2 parallelism must be at least 1");
    }
  }

  /** @return the documented default parameters. */
  public static Argon2Settings defaults() {
    return new Argon2Settings(DEFAULT_MEMORY_KIB, DEFAULT_ITERATIONS, DEFAULT_PARALLELISM);
  }
}

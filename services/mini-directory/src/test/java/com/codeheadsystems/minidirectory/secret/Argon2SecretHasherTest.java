package com.codeheadsystems.minidirectory.secret;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** The replicated Argon2id hasher behaves as the family's pattern requires. */
class Argon2SecretHasherTest {

  // Small parameters keep the test fast; production uses Argon2Settings.defaults().
  private final Argon2SecretHasher hasher = new Argon2SecretHasher(new Argon2Settings(1024, 1, 1));

  @Test
  void correctSecretVerifies() {
    final SecretHash hash = hasher.hash("correct horse battery staple".toCharArray());
    assertTrue(hasher.verify("correct horse battery staple".toCharArray(), hash));
  }

  @Test
  void wrongSecretIsRejected() {
    final SecretHash hash = hasher.hash("correct horse".toCharArray());
    assertFalse(hasher.verify("wrong horse".toCharArray(), hash));
  }

  @Test
  void sameSecretHashesDifferentlyEachTime() {
    final SecretHash a = hasher.hash("same".toCharArray());
    final SecretHash b = hasher.hash("same".toCharArray());
    assertNotEquals(a.saltBase64(), b.saltBase64());
    assertNotEquals(a.hashBase64(), b.hashBase64());
    assertTrue(hasher.verify("same".toCharArray(), a));
    assertTrue(hasher.verify("same".toCharArray(), b));
  }
}

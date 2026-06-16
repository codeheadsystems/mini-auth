package com.codeheadsystems.miniidp.secret;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

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
  void emptyOrNullPresentedSecretIsRejected() {
    final SecretHash hash = hasher.hash("secret".toCharArray());
    assertFalse(hasher.verify(new char[0], hash));
    assertFalse(hasher.verify(null, hash));
  }

  @Test
  void sameSecretHashesDifferentlyEachTime() {
    // A fresh random salt per hash means two hashes of the same secret are not byte-identical.
    final SecretHash a = hasher.hash("same".toCharArray());
    final SecretHash b = hasher.hash("same".toCharArray());
    assertNotEquals(a.saltBase64(), b.saltBase64());
    assertNotEquals(a.hashBase64(), b.hashBase64());
    // ...yet both still verify.
    assertTrue(hasher.verify("same".toCharArray(), a));
    assertTrue(hasher.verify("same".toCharArray(), b));
  }

  @Test
  void verificationUsesParametersStoredInTheHash() {
    // A hash made with different cost params must still verify under a hasher configured with
    // other defaults, because verify() reads the params from the stored hash.
    final Argon2SecretHasher producer = new Argon2SecretHasher(new Argon2Settings(2048, 2, 1));
    final SecretHash hash = producer.hash("portable".toCharArray());
    final Argon2SecretHasher verifier = new Argon2SecretHasher(new Argon2Settings(1024, 1, 1));
    assertTrue(verifier.verify("portable".toCharArray(), hash));
  }
}

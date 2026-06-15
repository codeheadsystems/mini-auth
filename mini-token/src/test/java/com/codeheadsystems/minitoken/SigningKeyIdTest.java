package com.codeheadsystems.minitoken;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class SigningKeyIdTest {

  @Test
  void ofEdDsaUsesTheFamilyDefaultAlgorithm() {
    final SigningKeyId id = SigningKeyId.ofEdDsa("key-2026-06");
    assertEquals("key-2026-06", id.kid());
    assertEquals("EdDSA", id.algorithm());
  }

  @Test
  void blankKidIsRejected() {
    assertThrows(IllegalArgumentException.class, () -> new SigningKeyId(" ", "EdDSA"));
  }

  @Test
  void blankAlgorithmIsRejected() {
    assertThrows(IllegalArgumentException.class, () -> new SigningKeyId("kid", ""));
  }
}

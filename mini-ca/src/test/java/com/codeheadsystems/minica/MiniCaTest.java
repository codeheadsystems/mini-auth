package com.codeheadsystems.minica;

import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class MiniCaTest {

  @Test
  void isStillARoadmapPlaceholder() {
    // This guard flips to a real assertion when mini-ca starts being implemented.
    assertFalse(MiniCa.IMPLEMENTED);
  }
}

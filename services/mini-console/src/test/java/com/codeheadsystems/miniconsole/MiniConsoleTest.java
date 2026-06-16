package com.codeheadsystems.miniconsole;

import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class MiniConsoleTest {

  @Test
  void isStillARoadmapPlaceholder() {
    // This guard flips to a real assertion when mini-console starts being implemented.
    assertFalse(MiniConsole.IMPLEMENTED);
  }
}

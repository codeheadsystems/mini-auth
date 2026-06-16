package com.codeheadsystems.minioidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class HealthTest {

  @Test
  void scaffoldReportsItselfUp() {
    final Health health = Health.up(ServerMain.SERVICE);
    assertEquals("mini-oidc", health.service());
    assertTrue(health.isUp());
  }
}

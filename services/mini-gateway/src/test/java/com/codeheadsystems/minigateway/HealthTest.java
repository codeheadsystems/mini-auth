package com.codeheadsystems.minigateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class HealthTest {

  @Test
  void scaffoldReportsItselfUp() {
    final Health health = Health.up(ServerMain.SERVICE);
    assertEquals("mini-gateway", health.service());
    assertTrue(health.isUp());
  }
}

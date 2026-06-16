package com.codeheadsystems.minipolicy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class DenyAllPolicyEngineTest {

  private final PolicyEngine engine = new DenyAllPolicyEngine();

  @Test
  void deniesByDefault() {
    final Decision decision = engine.evaluate(
        new PolicyRequest("shared-data-client", "billing", "DECRYPT"));
    assertSame(Decision.DENY, decision);
    assertFalse(decision.isAllowed());
  }

  @Test
  void blankRequestCoordinatesAreRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> new PolicyRequest("", "billing", "DECRYPT"));
    assertThrows(IllegalArgumentException.class,
        () -> new PolicyRequest("svc", " ", "DECRYPT"));
    assertThrows(IllegalArgumentException.class,
        () -> new PolicyRequest("svc", "billing", null));
  }

  @Test
  void nullRequestIsAProgrammingError() {
    assertThrows(IllegalArgumentException.class, () -> engine.evaluate(null));
  }
}

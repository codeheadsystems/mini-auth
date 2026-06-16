package com.codeheadsystems.minipolicy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;

class DenyAllPolicyEngineTest {

  private final PolicyEngine engine = new DenyAllPolicyEngine();

  @Test
  void deniesEveryone() {
    final Decision decision = engine.decide(
        Principal.of("shared-data-client"), Action.of("DECRYPT"), Resource.of("billing"));
    assertSame(Decision.DENY, decision);
    assertFalse(decision.isAllowed());
  }

  @Test
  void deniesEvenAnAdmin() {
    assertSame(Decision.DENY,
        engine.decide(Principal.admin("root"), Action.ANY, Resource.ANY));
  }
}

package com.codeheadsystems.minipolicy;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class AllowAllPolicyEngineTest {

  private final PolicyEngine engine = new AllowAllPolicyEngine();

  @Test
  void allowsAnyPrincipalActionResource() {
    final Decision decision = engine.decide(
        Principal.of("shared-data-client"), Action.of("ENCRYPT"), Resource.of("any-group"));
    assertSame(Decision.ALLOW, decision);
    assertTrue(decision.isAllowed());
  }

  @Test
  void allowsADifferentGroupToo() {
    // The behavior mini-kms relies on: every authenticated caller may use every key group.
    assertSame(Decision.ALLOW,
        engine.decide(Principal.of("svc"), Action.of("DECRYPT"), Resource.of("billing")));
  }
}

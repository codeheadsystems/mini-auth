package com.codeheadsystems.minipolicy;

import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;

class GrantBasedPolicyEngineTest {

  // "billing" client may DECRYPT and ENCRYPT under group "billing" only; "ops" may do anything
  // under any group; an admin bypasses grants entirely.
  private final PolicyEngine engine = GrantBasedPolicyEngine.builder()
      .grant("billing", Action.of("DECRYPT"), Resource.of("billing"))
      .grant("billing", Action.of("ENCRYPT"), Resource.of("billing"))
      .grant("ops", Action.ANY, Resource.ANY)
      .build();

  @Test
  void allowsAGrantedActionOnAGrantedResource() {
    assertSame(Decision.ALLOW,
        engine.decide(Principal.of("billing"), Action.of("DECRYPT"), Resource.of("billing")));
  }

  @Test
  void deniesAnUngrantedAction() {
    // billing has no RE_ENCRYPT grant.
    assertSame(Decision.DENY,
        engine.decide(Principal.of("billing"), Action.of("RE_ENCRYPT"), Resource.of("billing")));
  }

  @Test
  void deniesAGrantedActionOnTheWrongResource() {
    assertSame(Decision.DENY,
        engine.decide(Principal.of("billing"), Action.of("DECRYPT"), Resource.of("payroll")));
  }

  @Test
  void deniesAPrincipalWithNoGrants() {
    assertSame(Decision.DENY,
        engine.decide(Principal.of("stranger"), Action.of("DECRYPT"), Resource.of("billing")));
  }

  @Test
  void wildcardGrantCoversEveryActionAndResource() {
    assertSame(Decision.ALLOW,
        engine.decide(Principal.of("ops"), Action.of("anything"), Resource.of("any-group")));
  }

  @Test
  void resourceWildcardCoversAnyGroupForThatAction() {
    final PolicyEngine decryptAnywhere = GrantBasedPolicyEngine.builder()
        .grant("auditor", Action.of("DECRYPT"), Resource.ANY)
        .build();
    assertSame(Decision.ALLOW,
        decryptAnywhere.decide(Principal.of("auditor"), Action.of("DECRYPT"), Resource.of("g1")));
    assertSame(Decision.DENY,
        decryptAnywhere.decide(Principal.of("auditor"), Action.of("ENCRYPT"), Resource.of("g1")));
  }

  @Test
  void adminPrincipalBypassesGrants() {
    // Mirrors a mini-idp token's grants.control implying full authority.
    assertSame(Decision.ALLOW,
        engine.decide(Principal.admin("root"), Action.of("RE_ENCRYPT"), Resource.of("anything")));
  }
}

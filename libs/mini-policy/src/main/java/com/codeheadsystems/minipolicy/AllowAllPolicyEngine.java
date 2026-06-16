package com.codeheadsystems.minipolicy;

/**
 * Permits everything. This is mini-kms's current default ({@code auth/AllowAllPolicy}, lifted here
 * verbatim in behavior): with a single shared data-plane token there is only one principal, so any
 * authenticated caller may use any key group — groups still provide isolation and independent
 * rotation. Swap in {@link GrantBasedPolicyEngine} once per-client identities exist.
 *
 * <p>Contrast {@link DenyAllPolicyEngine}, the safe default for a generic service that has not yet
 * configured its rules; allow-all is appropriate only where another layer already gates the door.
 */
public final class AllowAllPolicyEngine implements PolicyEngine {

  @Override
  public Decision decide(final Principal principal, final Action action, final Resource resource) {
    return Decision.ALLOW;
  }
}

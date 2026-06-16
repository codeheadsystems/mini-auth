package com.codeheadsystems.minipolicy;

/**
 * Refuses everything — the deliberately SAFE default for an unconfigured generic service.
 *
 * <p>It is the opposite choice from {@link AllowAllPolicyEngine} on purpose: mini-kms can ship
 * allow-all because a single shared token already gates the door, whereas mini-policy is the
 * generic engine real services wire in, so an unconfigured engine must never silently permit
 * access. A service that wants to grant anything supplies its own engine (e.g.
 * {@link GrantBasedPolicyEngine}).
 */
public final class DenyAllPolicyEngine implements PolicyEngine {

  @Override
  public Decision decide(final Principal principal, final Action action, final Resource resource) {
    return Decision.DENY;
  }
}

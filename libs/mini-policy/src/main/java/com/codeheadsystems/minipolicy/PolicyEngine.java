package com.codeheadsystems.minipolicy;

/**
 * The authorization decision function shared across the family:
 * {@code decide(principal, action, resource) -> ALLOW | DENY}.
 *
 * <p>This is the generalization of mini-kms's {@code KeyAuthorizationPolicy}, whose single-purpose
 * {@code isAllowed(Principal, keyGroupId, KeyOperation)} is exactly this question with the
 * key-group as the {@link Resource} and the operation name as the {@link Action}. One engine now
 * answers it for every service: mini-kms gating a key group, mini-gateway gating a route,
 * mini-idp/mini-oidc checking a scope.
 *
 * <p>Shipped implementations: {@link AllowAllPolicyEngine} (mini-kms's current default — any
 * authenticated caller may use any group), {@link DenyAllPolicyEngine} (the safe default for an
 * unconfigured generic service), and {@link GrantBasedPolicyEngine} (per-principal grants, the
 * shape real per-key-group / per-scope rules take). Functional, so a custom rule is a lambda.
 */
@FunctionalInterface
public interface PolicyEngine {

  /**
   * @param principal the authenticated caller; must not be {@code null}.
   * @param action    the verb being attempted; must not be {@code null}.
   * @param resource  the thing being accessed; must not be {@code null}.
   * @return {@link Decision#ALLOW} if permitted, otherwise {@link Decision#DENY}.
   */
  Decision decide(Principal principal, Action action, Resource resource);
}

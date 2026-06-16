package com.codeheadsystems.minipolicy;

/**
 * The authorization decision function shared across the family: {@code (principal, resource,
 * action) -> ALLOW | DENY}.
 *
 * <p>This is the generalization of mini-kms's {@code KeyAuthorizationPolicy}. Where mini-kms has
 * a single-purpose {@code isAllowed(Principal, keyGroupId, KeyOperation)}, mini-policy exposes
 * one engine every service can evaluate through: mini-gateway gating a route, mini-kms gating a
 * key group, mini-oidc/mini-idp checking a scope — all become a {@link PolicyRequest} against an
 * implementation of this interface.
 *
 * <p>The shipped implementation is {@link DenyAllPolicyEngine} (secure default). Real engines —
 * role/grant evaluation sourced from mini-directory, mini-idp/mini-oidc token scopes — implement
 * this same method with no change to callers.
 */
@FunctionalInterface
public interface PolicyEngine {

  /**
   * @param request the authorization question.
   * @return {@link Decision#ALLOW} if permitted, otherwise {@link Decision#DENY}.
   */
  Decision evaluate(PolicyRequest request);
}

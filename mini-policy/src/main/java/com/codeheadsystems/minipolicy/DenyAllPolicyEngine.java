package com.codeheadsystems.minipolicy;

/**
 * The default {@link PolicyEngine}: it refuses everything.
 *
 * <p>Deny-by-default is the deliberately SAFE placeholder for a scaffold. It is the mirror image
 * of mini-kms's {@code AllowAllPolicy}, and the opposite choice on purpose: mini-kms can ship
 * allow-all because a single shared token already gates the door, whereas mini-policy is the
 * generic engine that real services will wire in, so an unconfigured engine must never silently
 * permit access.
 *
 * <p>TODO(mini-policy): replace with a real engine that evaluates roles and per-resource grants
 * (sourced from mini-directory) and token scopes (from mini-idp / mini-oidc). Until then, any
 * service wiring this in must supply its own engine to grant anything.
 */
public final class DenyAllPolicyEngine implements PolicyEngine {

  @Override
  public Decision evaluate(final PolicyRequest request) {
    // A null request is a programming error, not an authorization question.
    if (request == null) {
      throw new IllegalArgumentException("request must not be null");
    }
    return Decision.DENY;
  }
}

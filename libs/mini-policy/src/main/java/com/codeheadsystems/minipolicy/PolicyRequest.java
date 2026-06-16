package com.codeheadsystems.minipolicy;

/**
 * One authorization question: may {@code principalId} perform {@code action} on {@code resource}?
 *
 * <p>This is the generalized shape of the question mini-kms asks today through
 * {@code KeyAuthorizationPolicy.isAllowed(principal, keyGroupId, operation)}: the principal is
 * the authenticated caller, the resource is what is being touched (a key group, a route, a
 * directory record…), and the action is the verb (a {@code KeyOperation} name, an HTTP method,
 * a directory operation…). Keeping it as opaque strings is deliberate — mini-policy is the
 * common decision function and must not depend on any one service's enums.
 *
 * @param principalId the authenticated caller (maps to a mini-kms {@code Principal.id} /
 *     a token {@code sub}). Must be present.
 * @param resource the thing being accessed (opaque to mini-policy). Must be present.
 * @param action the operation being attempted (opaque to mini-policy). Must be present.
 */
public record PolicyRequest(String principalId, String resource, String action) {

  /** Validate: all three coordinates of a decision must be present. */
  public PolicyRequest {
    if (principalId == null || principalId.isBlank()) {
      throw new IllegalArgumentException("principalId must not be blank");
    }
    if (resource == null || resource.isBlank()) {
      throw new IllegalArgumentException("resource must not be blank");
    }
    if (action == null || action.isBlank()) {
      throw new IllegalArgumentException("action must not be blank");
    }
  }
}

package com.codeheadsystems.minipolicy;

import java.util.Objects;

/**
 * A single permission: "this (action, resource) pair is allowed." Grants are the rules a
 * {@link GrantBasedPolicyEngine} evaluates, attached to a principal.
 *
 * <p>Either coordinate may be a wildcard ({@link Action#ANY} / {@link Resource#ANY}) so a grant
 * can express the per-key-group rules mini-kms reasons about today — for example "any operation
 * on key group {@code billing}" ({@code new Grant(Action.ANY, Resource.of("billing"))}) or
 * "{@code DECRYPT} on any group" ({@code new Grant(Action.of("DECRYPT"), Resource.ANY)}) — and,
 * unchanged, an OIDC scope or a forward-auth route later.
 *
 * @param action   the permitted action, or {@link Action#ANY}.
 * @param resource the permitted resource, or {@link Resource#ANY}.
 */
public record Grant(Action action, Resource resource) {

  /** Validate: both coordinates of a grant must be present. */
  public Grant {
    Objects.requireNonNull(action, "grant action must not be null");
    Objects.requireNonNull(resource, "grant resource must not be null");
  }

  /**
   * @param requestedAction   the action being attempted.
   * @param requestedResource the resource being accessed.
   * @return whether this grant permits that action on that resource (honoring wildcards).
   */
  public boolean permits(final Action requestedAction, final Resource requestedResource) {
    final boolean actionMatches = action.equals(Action.ANY) || action.equals(requestedAction);
    final boolean resourceMatches = resource.equals(Resource.ANY) || resource.equals(requestedResource);
    return actionMatches && resourceMatches;
  }
}

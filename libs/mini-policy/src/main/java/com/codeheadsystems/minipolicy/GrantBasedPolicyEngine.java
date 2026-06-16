package com.codeheadsystems.minipolicy;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Decides from a set of per-principal {@link Grant}s — the generalized shape of the per-key-group
 * rules mini-kms describes for "KEK groups dependent on the client".
 *
 * <p>The rule is: an {@code admin} {@link Principal} is permitted everything (mirroring a mini-idp
 * token's {@code grants.control} ⇒ full authority); otherwise the principal is permitted iff one
 * of its grants {@link Grant#permits permits} the requested action on the requested resource.
 * Anything not granted is denied. The same engine expresses key-group rules today and OIDC
 * scope / forward-auth route rules later — only the {@link Action}/{@link Resource} strings differ.
 *
 * <p>Immutable once built; grants are copied defensively. Use {@link #builder()} for readable
 * wiring.
 */
public final class GrantBasedPolicyEngine implements PolicyEngine {

  private final Map<String, List<Grant>> grantsByPrincipalId;

  /**
   * @param grantsByPrincipalId principal id → the grants held by that principal. Copied
   *                            defensively; null/empty means "no grants" (deny-by-default).
   */
  public GrantBasedPolicyEngine(final Map<String, ? extends Collection<Grant>> grantsByPrincipalId) {
    final Map<String, List<Grant>> copy = new HashMap<>();
    if (grantsByPrincipalId != null) {
      grantsByPrincipalId.forEach((id, grants) -> copy.put(id, List.copyOf(grants)));
    }
    this.grantsByPrincipalId = Map.copyOf(copy);
  }

  @Override
  public Decision decide(final Principal principal, final Action action, final Resource resource) {
    Objects.requireNonNull(principal, "principal must not be null");
    Objects.requireNonNull(action, "action must not be null");
    Objects.requireNonNull(resource, "resource must not be null");
    // The control/admin capability bypasses per-resource grants (mini-idp grants.control).
    if (principal.admin()) {
      return Decision.ALLOW;
    }
    for (final Grant grant : grantsByPrincipalId.getOrDefault(principal.id(), List.of())) {
      if (grant.permits(action, resource)) {
        return Decision.ALLOW;
      }
    }
    return Decision.DENY;
  }

  /** @return a builder for accumulating grants per principal. */
  public static Builder builder() {
    return new Builder();
  }

  /** Accumulates per-principal {@link Grant}s into an immutable {@link GrantBasedPolicyEngine}. */
  public static final class Builder {

    private final Map<String, List<Grant>> grants = new HashMap<>();

    /**
     * Grant a principal an action on a resource (either may be {@link Action#ANY} /
     * {@link Resource#ANY}).
     *
     * @param principalId the principal that holds the grant.
     * @param action      the permitted action.
     * @param resource    the permitted resource.
     * @return this builder.
     */
    public Builder grant(final String principalId, final Action action, final Resource resource) {
      grants.computeIfAbsent(principalId, key -> new ArrayList<>()).add(new Grant(action, resource));
      return this;
    }

    /** @return the immutable engine. */
    public GrantBasedPolicyEngine build() {
      return new GrantBasedPolicyEngine(grants);
    }
  }
}

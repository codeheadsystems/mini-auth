package com.codeheadsystems.minidirectory.model;

import com.codeheadsystems.minipolicy.GrantBasedPolicyEngine;
import com.codeheadsystems.minipolicy.Grant;
import com.codeheadsystems.minipolicy.Principal;
import java.util.List;

/**
 * The outcome of resolving a directory {@link Account}: a mini-policy {@link Principal} plus the
 * fully-expanded set of mini-policy {@link Grant}s it holds. This is the directory's whole reason
 * to exist — turning stored identities, roles, and group memberships into exactly the inputs a
 * {@link com.codeheadsystems.minipolicy.PolicyEngine} decides over.
 *
 * <p>The {@code grants} list is already flattened and de-duplicated: directly-assigned grants, the
 * grants of directly-assigned roles, and everything inherited via group membership, all merged. An
 * {@code admin} principal will be permitted everything by {@link GrantBasedPolicyEngine} regardless
 * of the grant list (mirroring a mini-idp token's {@code grants.control}).
 *
 * @param principal the mini-policy principal (id + admin capability).
 * @param grants    the effective, flattened, de-duplicated grants this principal holds.
 */
public record ResolvedPrincipal(Principal principal, List<Grant> grants) {

  /** Defensively copy the grant list. */
  public ResolvedPrincipal {
    grants = grants == null ? List.of() : List.copyOf(grants);
  }

  /**
   * Build a single-principal {@link GrantBasedPolicyEngine} from this resolution, so a caller can
   * immediately make decisions about it. This is the seam a verifier/gateway uses: resolve once,
   * then {@code engine.decide(principal, action, resource)}.
   *
   * @return an engine that knows this principal's grants (and nothing else).
   */
  public GrantBasedPolicyEngine toPolicyEngine() {
    return new GrantBasedPolicyEngine(java.util.Map.of(principal.id(), grants));
  }
}

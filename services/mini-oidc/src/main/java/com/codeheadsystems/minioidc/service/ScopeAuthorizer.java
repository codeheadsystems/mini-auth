package com.codeheadsystems.minioidc.service;

import com.codeheadsystems.minioidc.directory.DirectoryUser;
import com.codeheadsystems.minipolicy.Action;
import com.codeheadsystems.minipolicy.Decision;
import com.codeheadsystems.minipolicy.GrantBasedPolicyEngine;
import com.codeheadsystems.minipolicy.Resource;
import java.util.ArrayList;
import java.util.List;

/**
 * Decides which of a client's requested OIDC scopes a given user may actually be granted, by
 * asking <b>mini-policy</b>.
 *
 * <p>Each non-base scope {@code X} is authorized iff the user's grants permit the action {@code X}
 * on the resource {@link #SCOPE_RESOURCE} — i.e. {@code decide(principal, Action.of(X),
 * Resource.of("oidc:scope")) == ALLOW}. An {@code admin} principal is permitted every scope (the
 * engine's admin bypass, mirroring a control-plane token). The base {@code openid} scope is always
 * granted to an authenticated user — it carries no profile data, only the request to do OIDC.
 *
 * <p>This is the consent backstop: even if a user approves a scope on the consent screen, it is only
 * issued if mini-policy allows it. The granted set (requested ∩ allowed) is what ends up in the
 * access token and gates {@code /userinfo}.
 */
public final class ScopeAuthorizer {

  /** The OIDC base scope: requesting to do OpenID Connect at all. Always granted once authenticated. */
  public static final String OPENID = "openid";

  /** The mini-policy resource that OIDC scope grants are expressed against. */
  public static final Resource SCOPE_RESOURCE = Resource.of("oidc:scope");

  /**
   * @param user      the resolved user (its grants drive the decision).
   * @param requested the scopes the client asked for.
   * @return the subset the user is authorized to receive, order-preserving and de-duplicated;
   *     {@code openid} is included whenever it was requested.
   */
  public List<String> authorize(final DirectoryUser user, final List<String> requested) {
    final GrantBasedPolicyEngine engine = new GrantBasedPolicyEngine(
        java.util.Map.of(user.subject(), user.grants()));
    final List<String> granted = new ArrayList<>();
    for (final String scope : requested) {
      if (granted.contains(scope)) {
        continue;
      }
      if (OPENID.equals(scope)
          || engine.decide(user.principal(), Action.of(scope), SCOPE_RESOURCE) == Decision.ALLOW) {
        granted.add(scope);
      }
    }
    return granted;
  }
}

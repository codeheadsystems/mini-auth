package com.codeheadsystems.minigateway.service;

import com.codeheadsystems.minigateway.auth.AuthenticatedUser;
import com.codeheadsystems.minigateway.model.GatewayRoutes;
import com.codeheadsystems.minigateway.model.RouteAccess;
import com.codeheadsystems.minigateway.model.RouteRule;
import com.codeheadsystems.minipolicy.Action;
import com.codeheadsystems.minipolicy.Decision;
import com.codeheadsystems.minipolicy.GrantBasedPolicyEngine;
import com.codeheadsystems.minipolicy.Grant;
import com.codeheadsystems.minipolicy.Resource;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * The config-driven, per-route authorization decision. It matches a proxied request to the first
 * {@link RouteRule} that covers it, then decides through <b>mini-policy</b>: public routes pass,
 * authenticated routes need any valid caller, and scope-gated routes are evaluated by a
 * {@link GrantBasedPolicyEngine} built from the caller's scopes — so the allow/deny call is the same
 * decision function the rest of the family uses, never an ad-hoc check here.
 *
 * <p>Unmatched requests are denied (deny-by-default): a request must be explicitly allowed by a rule.
 */
public final class RoutePolicy {

  /** OIDC scopes are expressed as mini-policy grants on this resource (matching mini-oidc). */
  private static final Resource SCOPE_RESOURCE = Resource.of("oidc:scope");

  /** The outcome of evaluating a request: allow it, send it to login, or forbid it. */
  public enum Outcome {
    /** The request is permitted. */
    ALLOW,
    /** No valid caller and the route needs one — send a browser to login, or 401 an API client. */
    UNAUTHENTICATED,
    /** A valid caller, but the route's policy denies it — 403. */
    FORBIDDEN
  }

  private final List<RouteRule> rules;

  public RoutePolicy(final GatewayRoutes routes) {
    this.rules = routes.routes();
  }

  /** @return the first rule covering this request, if any. */
  public Optional<RouteRule> match(final String method, final String path) {
    for (final RouteRule rule : rules) {
      if (rule.matches(method, path)) {
        return Optional.of(rule);
      }
    }
    return Optional.empty();
  }

  /**
   * Decide whether to allow a request.
   *
   * @param method the proxied request's method.
   * @param path   the proxied request's path.
   * @param user   the validated caller, if any.
   * @return the outcome.
   */
  public Outcome evaluate(final String method, final String path, final Optional<AuthenticatedUser> user) {
    final Optional<RouteRule> matched = match(method, path);
    if (matched.isEmpty()) {
      return Outcome.FORBIDDEN; // deny by default
    }
    final RouteRule rule = matched.get();
    if (rule.access() == RouteAccess.PUBLIC) {
      return Outcome.ALLOW;
    }
    if (user.isEmpty()) {
      return Outcome.UNAUTHENTICATED;
    }
    if (rule.access() == RouteAccess.AUTHENTICATED) {
      return Outcome.ALLOW;
    }
    // SCOPE: defer to mini-policy over the caller's scopes (admin is permitted everything).
    final AuthenticatedUser caller = user.get();
    final List<Grant> grants = new ArrayList<>();
    for (final String scope : caller.scopes()) {
      grants.add(new Grant(Action.of(scope), SCOPE_RESOURCE));
    }
    final GrantBasedPolicyEngine engine = new GrantBasedPolicyEngine(
        java.util.Map.of(caller.subject(), grants));
    return engine.decide(caller.principal(), Action.of(rule.scope()), SCOPE_RESOURCE) == Decision.ALLOW
        ? Outcome.ALLOW : Outcome.FORBIDDEN;
  }
}

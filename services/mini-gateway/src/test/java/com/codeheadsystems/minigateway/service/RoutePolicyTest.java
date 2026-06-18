package com.codeheadsystems.minigateway.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.codeheadsystems.minigateway.auth.AuthenticatedUser;
import com.codeheadsystems.minigateway.model.GatewayRoutes;
import com.codeheadsystems.minigateway.model.RouteAccess;
import com.codeheadsystems.minigateway.model.RouteRule;
import com.codeheadsystems.minigateway.service.RoutePolicy.Outcome;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class RoutePolicyTest {

  private final RoutePolicy policy = new RoutePolicy(new GatewayRoutes(List.of(
      new RouteRule("/public", null, RouteAccess.PUBLIC, null),
      new RouteRule("/admin", null, RouteAccess.SCOPE, "admin"),
      new RouteRule("/", null, RouteAccess.AUTHENTICATED, null))));

  private static AuthenticatedUser user(final String... scopes) {
    return new AuthenticatedUser("alice", false, List.of(scopes), "token");
  }

  @Test
  void publicRouteAllowsAnyone() {
    assertEquals(Outcome.ALLOW, policy.evaluate("GET", "/public/x", Optional.empty()));
  }

  @Test
  void authenticatedRouteNeedsACaller() {
    assertEquals(Outcome.UNAUTHENTICATED, policy.evaluate("GET", "/app", Optional.empty()));
    assertEquals(Outcome.ALLOW, policy.evaluate("GET", "/app", Optional.of(user())));
  }

  @Test
  void scopeRouteDefersToMiniPolicy() {
    assertEquals(Outcome.UNAUTHENTICATED, policy.evaluate("GET", "/admin/x", Optional.empty()));
    assertEquals(Outcome.FORBIDDEN, policy.evaluate("GET", "/admin/x", Optional.of(user("openid"))));
    assertEquals(Outcome.ALLOW, policy.evaluate("GET", "/admin/x", Optional.of(user("openid", "admin"))));
  }

  @Test
  void adminPrincipalIsAllowedEverywhere() {
    final AuthenticatedUser admin = new AuthenticatedUser("root", true, List.of(), "token");
    assertEquals(Outcome.ALLOW, policy.evaluate("GET", "/admin/x", Optional.of(admin)));
  }

  @Test
  void prefixMatchIsSegmentAwareNotSubstring() {
    // "/admin-public" must NOT be covered by the "/admin" SCOPE rule (a raw startsWith would have
    // over-matched it); it falls through to the catch-all AUTHENTICATED rule instead.
    assertEquals(Outcome.ALLOW, policy.evaluate("GET", "/admin-public", Optional.of(user("openid"))));
    // The real /admin subtree still defers to the scope rule.
    assertEquals(Outcome.FORBIDDEN, policy.evaluate("GET", "/admin", Optional.of(user("openid"))));
    assertEquals(Outcome.FORBIDDEN, policy.evaluate("GET", "/admin/x", Optional.of(user("openid"))));
  }

  @Test
  void unmatchedRequestIsDeniedByDefault() {
    final RoutePolicy empty = new RoutePolicy(new GatewayRoutes(List.of(
        new RouteRule("/known", null, RouteAccess.PUBLIC, null))));
    assertEquals(Outcome.FORBIDDEN, empty.evaluate("GET", "/unknown", Optional.of(user())));
  }
}

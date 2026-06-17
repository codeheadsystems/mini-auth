package com.codeheadsystems.minigateway.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * The config-driven route table ({@code routes.json}): the ordered list of {@link RouteRule}s the
 * gateway matches each proxied request against. First match wins; if nothing matches, the gateway
 * denies by default (a request must be explicitly allowed by a rule).
 *
 * @param routes the rules, in match order; never null.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GatewayRoutes(List<RouteRule> routes) {

  public GatewayRoutes {
    routes = routes == null ? List.of() : List.copyOf(routes);
  }

  /** The default table when no routes file is configured: gate everything behind login. */
  public static GatewayRoutes defaults() {
    return new GatewayRoutes(List.of(RouteRule.defaultAuthenticated()));
  }
}

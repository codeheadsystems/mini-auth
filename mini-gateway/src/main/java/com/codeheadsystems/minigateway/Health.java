package com.codeheadsystems.minigateway;

/**
 * The liveness summary a service reports about itself (see mini-oidc's equivalent — each service
 * keeps its own copy until a shared serving layer exists).
 *
 * @param service the service name (e.g. {@code "mini-gateway"}).
 * @param status the liveness status; {@code "ok"} when the process is up.
 */
public record Health(String service, String status) {

  /** @return a healthy status for {@code service}. */
  public static Health up(final String service) {
    return new Health(service, "ok");
  }

  /** @return whether the service reports itself live. */
  public boolean isUp() {
    return "ok".equals(status);
  }
}

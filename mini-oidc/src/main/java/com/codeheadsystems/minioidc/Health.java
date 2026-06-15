package com.codeheadsystems.minioidc;

/**
 * The liveness summary a service reports about itself.
 *
 * <p>A scaffold stand-in for a real {@code GET /health} response. Every service in the family
 * exposes the same minimal shape so the eventual mini-gateway / mini-console can probe them
 * uniformly.
 *
 * @param service the service name (e.g. {@code "mini-oidc"}).
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

package com.codeheadsystems.minigateway;

/**
 * mini-gateway entry point (SCAFFOLD).
 *
 * <p>Today this only proves the module is wired and reports {@link Health}. It does NOT yet bind
 * the forward-auth HTTP endpoint.
 *
 * <p>TODO(mini-gateway): the real service must add, behind a loopback HTTP server:
 * <ul>
 *   <li>A single forward-auth endpoint (e.g. {@code GET /auth}) shaped for Traefik ForwardAuth /
 *       Caddy {@code forward_auth} / nginx {@code auth_request}: read the proxied request's
 *       headers, return 2xx to allow or 401/403 to deny, optionally injecting identity headers
 *       (e.g. {@code X-Auth-Subject}) on allow.</li>
 *   <li>Token verification via <b>mini-token</b> (validate the session/access token offline
 *       against the published JWKS).</li>
 *   <li>The allow/deny decision via <b>mini-policy</b> ({@code (subject, requested-host+path,
 *       method) -> ALLOW | DENY}).</li>
 *   <li>A redirect-to-login handshake with <b>mini-oidc</b> for unauthenticated browsers.</li>
 * </ul>
 */
public final class ServerMain {

  /** The service name reported in health and logs. */
  public static final String SERVICE = "mini-gateway";

  private ServerMain() {
  }

  /** @param args CLI arguments (none parsed yet; see the TODOs above). */
  public static void main(final String[] args) {
    final Health health = Health.up(SERVICE);
    System.out.println(SERVICE + " scaffold — status=" + health.status());
    System.out.println("Not yet serving: the forward-auth endpoint is not implemented. "
        + "See the TODOs in ServerMain and docs/DIRECTION.md.");
  }
}

package com.codeheadsystems.minioidc;

/**
 * mini-oidc entry point (SCAFFOLD).
 *
 * <p>Today this only proves the module is wired and reports {@link Health}. It does NOT yet bind
 * an HTTP server or implement any OpenID Connect flow. The startup shape intentionally mirrors
 * the siblings' {@code ServerMain} (resolve config, build a server, serve until interrupted) so
 * filling it in is a matter of replacing the TODOs, not restructuring.
 *
 * <p>TODO(mini-oidc): the real service must add, behind a loopback HTTP server:
 * <ul>
 *   <li>OpenID Provider discovery ({@code /.well-known/openid-configuration}) + JWKS (via
 *       mini-token).</li>
 *   <li>Authorization Code flow with <b>PKCE</b> ({@code /authorize}, {@code /token}),
 *       issuing ID + access tokens through mini-token.</li>
 *   <li>Browser SSO session management and a login/consent UI.</li>
 *   <li>The passkey login/registration ceremonies, delegated to <b>pk-auth</b>.</li>
 *   <li>Consent/scope authorization decisions evaluated through <b>mini-policy</b>.</li>
 *   <li>Reading users/clients from <b>mini-directory</b> rather than a local store.</li>
 * </ul>
 */
public final class ServerMain {

  /** The service name reported in health and logs. */
  public static final String SERVICE = "mini-oidc";

  private ServerMain() {
  }

  /** @param args CLI arguments (none parsed yet; see the TODOs above). */
  public static void main(final String[] args) {
    final Health health = Health.up(SERVICE);
    System.out.println(SERVICE + " scaffold — status=" + health.status());
    System.out.println("Not yet serving: OpenID Provider flows are not implemented. "
        + "See the TODOs in ServerMain and docs/DIRECTION.md.");
  }
}

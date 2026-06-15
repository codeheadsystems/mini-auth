package com.codeheadsystems.minidirectory;

/**
 * mini-directory entry point (SCAFFOLD).
 *
 * <p>Today this only proves the module is wired and reports {@link Health}. It does NOT yet bind
 * an HTTP server or model any identities.
 *
 * <p>TODO(mini-directory): the real service must add, behind a loopback HTTP server:
 * <ul>
 *   <li>The core identity model: <b>users</b>, <b>groups</b>, <b>roles</b>, and
 *       <b>service accounts</b>, with stable ids that become token subjects.</li>
 *   <li><b>Grant mappings</b> — which principals hold which roles / per-resource grants — in the
 *       shape mini-policy evaluates over.</li>
 *   <li>A read API for the issuers: mini-oidc resolves human users, mini-idp resolves service
 *       accounts (see the open question in docs/DIRECTION.md about folding mini-idp's client
 *       registry in here).</li>
 *   <li>JSON stores following the siblings' atomic-write + {@code 0600} pattern.</li>
 * </ul>
 */
public final class ServerMain {

  /** The service name reported in health and logs. */
  public static final String SERVICE = "mini-directory";

  private ServerMain() {
  }

  /** @param args CLI arguments (none parsed yet; see the TODOs above). */
  public static void main(final String[] args) {
    final Health health = Health.up(SERVICE);
    System.out.println(SERVICE + " scaffold — status=" + health.status());
    System.out.println("Not yet serving: the identity model and read API are not implemented. "
        + "See the TODOs in ServerMain and docs/DIRECTION.md.");
  }
}

package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniconsole.harness.ExerciseRegistry;
import com.codeheadsystems.miniconsole.harness.flows.CertLifecycleFlow;
import com.codeheadsystems.miniconsole.harness.flows.KeyRotationFlow;
import com.codeheadsystems.miniconsole.harness.flows.M2mTokenFlow;
import com.codeheadsystems.miniconsole.harness.flows.OidcCodePkceFlow;
import com.codeheadsystems.miniconsole.kms.KeyGroupAdmin;
import com.codeheadsystems.miniconsole.server.http.Router;
import com.codeheadsystems.minica.client.MiniCaClient;
import com.codeheadsystems.minidirectory.client.MiniDirectoryClient;
import com.codeheadsystems.miniidp.client.MiniIdpClient;
import com.codeheadsystems.minioidc.client.MiniOidcClient;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.Executors;

/**
 * Assembles the admin console and exposes it through a loopback {@link HttpServer}.
 *
 * <p>This is the composition root. It wires the console-login session ({@link ConsoleSession} over an
 * atomic-{@code 0600} JSON store), the constant-time token comparator ({@link AdminAuthenticator}),
 * the cookie/CSRF helpers, and the route table ({@link ConsoleHandlers}), then binds loopback and
 * serves each request on a virtual thread — exactly as the family's other servers do.
 *
 * <p>The console adds no new authority: it holds its own bootstrap console token, a session store,
 * and (from Slice 1) a copy of each wired downstream service's admin token, used only to read
 * surfaces that already exist.
 */
public final class ConsoleServer {

  private final HttpServer httpServer;
  private final ConsoleConfig config;

  private ConsoleServer(final HttpServer httpServer, final ConsoleConfig config) {
    this.httpServer = httpServer;
    this.config = config;
  }

  /**
   * Build a server with no downstream clients wired (the Dashboard reports every service as not
   * configured). Retained for tests and the bare quickstart.
   *
   * @param config       the resolved configuration.
   * @param consoleToken the bootstrap console token guarding login (resolved from env/file).
   * @param clock        the clock shared by the session store.
   * @return a built, not-yet-started server.
   * @throws IOException if the listening socket cannot be opened.
   */
  public static ConsoleServer create(final ConsoleConfig config, final String consoleToken,
                                     final Clock clock) throws IOException {
    return create(config, consoleToken, null, null, clock);
  }

  /**
   * Build a server wiring the mini-directory client (no mini-idp). Retained for the Slice 1 tests.
   *
   * @param config       the resolved configuration.
   * @param consoleToken the bootstrap console token guarding login (resolved from env/file).
   * @param directory    the wired directory client, or null when the directory is not configured.
   * @param clock        the clock shared by the session store.
   * @return a built, not-yet-started server.
   * @throws IOException if the listening socket cannot be opened.
   */
  public static ConsoleServer create(final ConsoleConfig config, final String consoleToken,
                                     final MiniDirectoryClient directory, final Clock clock)
      throws IOException {
    return create(config, consoleToken, directory, null, clock);
  }

  /**
   * Build a server wiring the mini-directory and mini-idp clients but no KMS (the Keys page's KMS
   * section reports "not configured"). Retained for the Slice 1–3 tests.
   *
   * @param config       the resolved configuration.
   * @param consoleToken the bootstrap console token guarding login (resolved from env/file).
   * @param directory    the wired directory client, or null when the directory is not configured.
   * @param idp          the wired idp client, or null when mini-idp is not configured.
   * @param clock        the clock shared by the session store and the exercise harness.
   * @return a built, not-yet-started server.
   * @throws IOException if the listening socket cannot be opened.
   */
  public static ConsoleServer create(final ConsoleConfig config, final String consoleToken,
                                     final MiniDirectoryClient directory, final MiniIdpClient idp,
                                     final Clock clock) throws IOException {
    return create(config, consoleToken, directory, idp, null, clock);
  }

  /**
   * Build a server, optionally wiring the mini-directory, mini-idp, and mini-kms clients.
   *
   * @param config       the resolved configuration.
   * @param consoleToken the bootstrap console token guarding login (resolved from env/file).
   * @param directory    the wired directory client, or null when the directory is not configured.
   *                     (Tests inject a fake here to exercise the Identities pages without a real
   *                     directory.)
   * @param idp          the wired idp client, or null when mini-idp is not configured. (Tests inject
   *                     a fake here to exercise the Audit/Harness/Keys pages without a real IDP.)
   * @param keys         the wired KMS key-group admin, or null when mini-kms is not configured.
   *                     (Tests inject a fake here to exercise the Keys page without a real KMS.)
   * @param clock        the clock shared by the session store and the exercise harness.
   * @return a built, not-yet-started server.
   * @throws IOException if the listening socket cannot be opened.
   */
  public static ConsoleServer create(final ConsoleConfig config, final String consoleToken,
                                     final MiniDirectoryClient directory, final MiniIdpClient idp,
                                     final KeyGroupAdmin keys, final Clock clock) throws IOException {
    return create(config, consoleToken, directory, idp, keys, null, clock);
  }

  /**
   * Build a server, optionally wiring the mini-directory, mini-idp, mini-kms, and mini-ca clients (no
   * mini-oidc). Delegates to the full overload with a null oidc client.
   */
  public static ConsoleServer create(final ConsoleConfig config, final String consoleToken,
                                     final MiniDirectoryClient directory, final MiniIdpClient idp,
                                     final KeyGroupAdmin keys, final MiniCaClient ca, final Clock clock)
      throws IOException {
    return create(config, consoleToken, directory, idp, keys, ca, null, clock);
  }

  /**
   * Build a server, optionally wiring the mini-directory, mini-idp, mini-kms, mini-ca, and mini-oidc
   * clients.
   *
   * @param config       the resolved configuration.
   * @param consoleToken the bootstrap console token guarding login (resolved from env/file).
   * @param directory    the wired directory client, or null when the directory is not configured.
   * @param idp          the wired idp client, or null when mini-idp is not configured.
   * @param keys         the wired KMS key-group admin, or null when mini-kms is not configured.
   * @param ca           the wired mini-ca client, or null when mini-ca is not configured.
   * @param oidc         the wired mini-oidc client, or null when mini-oidc is not configured. (Tests
   *                     inject a fake here to exercise the Clients/Harness pages without a real OP.)
   * @param clock        the clock shared by the session store and the exercise harness.
   * @return a built, not-yet-started server.
   * @throws IOException if the listening socket cannot be opened.
   */
  public static ConsoleServer create(final ConsoleConfig config, final String consoleToken,
                                     final MiniDirectoryClient directory, final MiniIdpClient idp,
                                     final KeyGroupAdmin keys, final MiniCaClient ca,
                                     final MiniOidcClient oidc, final Clock clock)
      throws IOException {
    final ConsoleSession session = new ConsoleSession(config.dataDir(), clock, config.sessionTtl());
    // The exercise harness: the m2m token flow (Slice 3), the signing-key rotation flow (Slice 4),
    // the certificate-lifecycle flow (Slice 5), and the OIDC code+PKCE flow (Slice 6). The idp flows
    // use the wired idp client, the cert flow the ca client, and the OIDC flow the oidc client.
    final M2mTokenFlow m2mFlow = new M2mTokenFlow(clock);
    final KeyRotationFlow keyRotationFlow = new KeyRotationFlow(clock);
    final CertLifecycleFlow certLifecycleFlow = new CertLifecycleFlow();
    final OidcCodePkceFlow oidcFlow = new OidcCodePkceFlow(clock);
    final ExerciseRegistry exercises =
        new ExerciseRegistry(List.of(m2mFlow, keyRotationFlow, certLifecycleFlow, oidcFlow));
    final ConsoleHandlers handlers = new ConsoleHandlers(
        session, new AdminAuthenticator(consoleToken), new Cookies(config.secureCookies()),
        new Csrf(), config.sessionTtl().toSeconds(), directory, idp, keys, ca, oidc, exercises,
        m2mFlow, keyRotationFlow, certLifecycleFlow, oidcFlow);
    final Router router = handlers.router();

    final HttpServer http = HttpServer.create(new InetSocketAddress(config.host(), config.port()), 0);
    http.createContext("/", router);
    http.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    return new ConsoleServer(http, config);
  }

  /** Start serving (non-blocking; the JDK server runs its own threads). */
  public void start() {
    httpServer.start();
  }

  /** Stop serving, allowing in-flight exchanges a moment to finish. */
  public void stop() {
    httpServer.stop(1);
  }

  /** @return the actual bound address (useful when the configured port was 0/ephemeral). */
  public InetSocketAddress address() {
    return httpServer.getAddress();
  }

  /** @return the configuration this server was built from. */
  public ConsoleConfig config() {
    return config;
  }
}

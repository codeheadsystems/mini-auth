package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniconsole.harness.ExerciseRegistry;
import com.codeheadsystems.miniconsole.harness.flows.M2mTokenFlow;
import com.codeheadsystems.miniconsole.server.http.Router;
import com.codeheadsystems.minidirectory.client.MiniDirectoryClient;
import com.codeheadsystems.miniidp.client.MiniIdpClient;
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
   * Build a server, optionally wiring the mini-directory and mini-idp clients.
   *
   * @param config       the resolved configuration.
   * @param consoleToken the bootstrap console token guarding login (resolved from env/file).
   * @param directory    the wired directory client, or null when the directory is not configured.
   *                     (Tests inject a fake here to exercise the Identities pages without a real
   *                     directory.)
   * @param idp          the wired idp client, or null when mini-idp is not configured. (Tests inject
   *                     a fake here to exercise the Audit/Harness pages without a real IDP.)
   * @param clock        the clock shared by the session store and the exercise harness.
   * @return a built, not-yet-started server.
   * @throws IOException if the listening socket cannot be opened.
   */
  public static ConsoleServer create(final ConsoleConfig config, final String consoleToken,
                                     final MiniDirectoryClient directory, final MiniIdpClient idp,
                                     final Clock clock) throws IOException {
    final ConsoleSession session = new ConsoleSession(config.dataDir(), clock, config.sessionTtl());
    // The exercise harness: one flow in Slice 3 (the m2m token flow), driven by the wired idp client.
    final M2mTokenFlow m2mFlow = new M2mTokenFlow(clock);
    final ExerciseRegistry exercises = new ExerciseRegistry(List.of(m2mFlow));
    final ConsoleHandlers handlers = new ConsoleHandlers(
        session, new AdminAuthenticator(consoleToken), new Cookies(config.secureCookies()),
        new Csrf(), config.sessionTtl().toSeconds(), directory, idp, exercises, m2mFlow);
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

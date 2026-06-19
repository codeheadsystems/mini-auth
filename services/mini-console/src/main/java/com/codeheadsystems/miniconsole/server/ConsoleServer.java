package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniconsole.server.http.Router;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.util.concurrent.Executors;

/**
 * Assembles the admin console and exposes it through a loopback {@link HttpServer}.
 *
 * <p>This is the composition root. It wires the console-login session ({@link ConsoleSession} over an
 * atomic-{@code 0600} JSON store), the constant-time token comparator ({@link AdminAuthenticator}),
 * the cookie/CSRF helpers, and the route table ({@link ConsoleHandlers}), then binds loopback and
 * serves each request on a virtual thread — exactly as the family's other servers do.
 *
 * <p>The console adds no new authority: Slice 0 holds only its own bootstrap console token and a
 * session store; the Dashboard calls nothing downstream.
 */
public final class ConsoleServer {

  private final HttpServer httpServer;
  private final ConsoleConfig config;

  private ConsoleServer(final HttpServer httpServer, final ConsoleConfig config) {
    this.httpServer = httpServer;
    this.config = config;
  }

  /**
   * Build a server from configuration and the resolved console token.
   *
   * @param config       the resolved configuration.
   * @param consoleToken the bootstrap console token guarding login (resolved from env/file).
   * @param clock        the clock shared by the session store.
   * @return a built, not-yet-started server.
   * @throws IOException if the listening socket cannot be opened.
   */
  public static ConsoleServer create(final ConsoleConfig config, final String consoleToken,
                                     final Clock clock) throws IOException {
    final ConsoleSession session = new ConsoleSession(config.dataDir(), clock, config.sessionTtl());
    final ConsoleHandlers handlers = new ConsoleHandlers(
        session, new AdminAuthenticator(consoleToken), new Cookies(config.secureCookies()),
        new Csrf(), config.sessionTtl().toSeconds());
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

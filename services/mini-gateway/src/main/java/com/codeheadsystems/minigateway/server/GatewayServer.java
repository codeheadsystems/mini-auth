package com.codeheadsystems.minigateway.server;

import com.codeheadsystems.minigateway.auth.BearerAuthenticator;
import com.codeheadsystems.minigateway.auth.HttpJwksProvider;
import com.codeheadsystems.minigateway.auth.JwksProvider;
import com.codeheadsystems.minigateway.auth.SessionAuthenticator;
import com.codeheadsystems.minigateway.model.GatewayRoutes;
import com.codeheadsystems.minigateway.server.http.Json;
import com.codeheadsystems.minigateway.server.http.Router;
import com.codeheadsystems.minigateway.service.RoutePolicy;
import com.codeheadsystems.minigateway.store.JsonStore;
import com.codeheadsystems.minitoken.session.SessionService;
import com.codeheadsystems.minitoken.session.Sessions;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.Executors;

/**
 * Assembles the forward-auth gateway and exposes it on a loopback {@link HttpServer}.
 *
 * <p>Composition root: it opens the <b>shared</b> session store (the same {@code sessions.json}
 * mini-oidc writes), loads the config-driven route policy, wires the session + bearer authenticators,
 * and serves the verify endpoint. The bearer {@link JwksProvider} is injectable so a test can supply
 * a fixed key set; production fetches mini-oidc's {@code /jwks.json}.
 */
public final class GatewayServer {

  private final HttpServer httpServer;
  private final ServerConfig config;

  private GatewayServer(final HttpServer httpServer, final ServerConfig config) {
    this.httpServer = httpServer;
    this.config = config;
  }

  /**
   * @param config       the resolved configuration.
   * @param clock        the clock (for session expiry + JWKS cache + token time checks).
   * @param jwksOverride an explicit JWKS provider (tests), or null to build the HTTP one from config.
   */
  public static GatewayServer create(final ServerConfig config, final Clock clock,
                                     final JwksProvider jwksOverride) throws IOException {
    final SessionService sessions = new SessionService(
        new JsonStore<>(config.sessionsFile(), Sessions.class), clock, Duration.ZERO);
    final SessionAuthenticator sessionAuth = new SessionAuthenticator(sessions);

    final JwksProvider jwks = jwksOverride != null ? jwksOverride
        : (config.bearerEnabled() ? new HttpJwksProvider(config.jwksUrl(), clock, Duration.ofMinutes(5)) : null);
    final BearerAuthenticator bearerAuth = jwks == null ? null
        : new BearerAuthenticator(jwks, config.issuer(), config.audience(), clock, 5);

    final RoutePolicy policy = new RoutePolicy(loadRoutes(config));
    final GatewayHandlers handlers = new GatewayHandlers(config, policy, sessionAuth, bearerAuth);
    final Router router = handlers.router();

    final HttpServer http = HttpServer.create(new InetSocketAddress(config.host(), config.port()), 0);
    http.createContext("/", router);
    http.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    return new GatewayServer(http, config);
  }

  private static GatewayRoutes loadRoutes(final ServerConfig config) throws IOException {
    if (config.routesFile() == null) {
      return GatewayRoutes.defaults();
    }
    return Json.MAPPER.readValue(Files.readAllBytes(config.routesFile()), GatewayRoutes.class);
  }

  /** Start serving (non-blocking). */
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
  public ServerConfig config() {
    return config;
  }
}

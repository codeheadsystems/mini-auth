package com.codeheadsystems.miniidp.server;

import com.codeheadsystems.miniidp.secret.Argon2SecretHasher;
import com.codeheadsystems.miniidp.server.http.Router;
import com.codeheadsystems.miniidp.service.AuditService;
import com.codeheadsystems.miniidp.service.ClientService;
import com.codeheadsystems.miniidp.service.RevocationService;
import com.codeheadsystems.miniidp.service.SigningKeyService;
import com.codeheadsystems.miniidp.service.TokenIssuer;
import com.codeheadsystems.miniidp.store.JsonStore;
import com.codeheadsystems.miniidp.store.StoreDocuments.Audit;
import com.codeheadsystems.miniidp.store.StoreDocuments.ClientRegistry;
import com.codeheadsystems.miniidp.store.StoreDocuments.Revocations;
import com.codeheadsystems.miniidp.store.StoreDocuments.SigningKeys;
import com.codeheadsystems.miniidp.util.RandomIds;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.util.concurrent.Executors;

/**
 * Assembles the core services over the JSON stores and exposes them through a loopback
 * {@link HttpServer}.
 *
 * <p>This is the composition root: it builds the stores (paths under the configured data dir),
 * the services (sharing one {@link Clock} and {@link RandomIds}), the {@link ApiHandlers}/router,
 * and the JDK HTTP server. Each request runs on a <b>virtual thread</b> (the executor below), so
 * the handful of blocking handlers scale without a thread pool to size — the same per-connection
 * model mini-kms uses for its sockets.
 *
 * <p>Binding is loopback-only by default (see {@link ServerConfig#host()}): like mini-kms, this is
 * a local-trust service, and exposing it beyond loopback is an explicit operator decision.
 */
public final class IdpServer {

  private final HttpServer httpServer;
  private final ServerConfig config;

  private IdpServer(final HttpServer httpServer, final ServerConfig config) {
    this.httpServer = httpServer;
    this.config = config;
  }

  /**
   * Build a server from configuration and a resolved admin token.
   *
   * @param config     the resolved configuration.
   * @param adminToken the bootstrap admin token (already resolved from env/file by the caller).
   * @param clock      the clock shared by every time-dependent service.
   * @return a built, not-yet-started server.
   */
  public static IdpServer create(final ServerConfig config, final String adminToken, final Clock clock)
      throws IOException {
    final RandomIds ids = new RandomIds();
    final Argon2SecretHasher hasher = new Argon2SecretHasher(config.argonSettings());

    final ClientService clients = new ClientService(
        new JsonStore<>(config.dataDir().resolve("clients.json"), ClientRegistry.class),
        hasher, ids, clock);
    final SigningKeyService signingKeys = new SigningKeyService(
        new JsonStore<>(config.dataDir().resolve("signing-keys.json"), SigningKeys.class),
        ids, clock, config.retiredKeyRetention());
    final RevocationService revocations = new RevocationService(
        new JsonStore<>(config.dataDir().resolve("revocations.json"), Revocations.class), clock);
    final AuditService audit = new AuditService(
        new JsonStore<>(config.dataDir().resolve("audit.json"), Audit.class), clock);

    final TokenIssuer issuer = new TokenIssuer(
        signingKeys, ids, clock, config.issuer(), config.audience(), config.tokenTtl());
    final ApiHandlers handlers = new ApiHandlers(config, clients, signingKeys, revocations, audit,
        issuer, new AdminAuthenticator(adminToken), OpenApiDocument.load(), clock);
    final Router router = handlers.router();

    final HttpServer http = HttpServer.create(new InetSocketAddress(config.host(), config.port()), 0);
    http.createContext("/", router);
    http.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    return new IdpServer(http, config);
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
  public ServerConfig config() {
    return config;
  }
}

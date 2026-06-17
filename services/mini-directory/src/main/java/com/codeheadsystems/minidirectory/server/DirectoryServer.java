package com.codeheadsystems.minidirectory.server;

import com.codeheadsystems.minidirectory.secret.Argon2SecretHasher;
import com.codeheadsystems.minidirectory.server.http.Router;
import com.codeheadsystems.minidirectory.service.DirectoryService;
import com.codeheadsystems.minidirectory.store.DirectoryDocument;
import com.codeheadsystems.minidirectory.store.JsonStore;
import com.codeheadsystems.minidirectory.util.RandomIds;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

/**
 * Assembles the {@link DirectoryService} over its JSON store and exposes it through a loopback
 * {@link HttpServer}.
 *
 * <p>This is the composition root: it builds the store (a single {@code directory.json} under the
 * configured data dir), the Argon2 hasher for service-account secrets, the service, the
 * {@link ApiHandlers}/router, and the JDK HTTP server. Each request runs on a <b>virtual thread</b>,
 * the same per-request model mini-idp and mini-kms use.
 *
 * <p>Binding is loopback-only by default (see {@link ServerConfig#host()}): like its siblings, this
 * is a local-trust service, and exposing it beyond loopback is an explicit operator decision.
 */
public final class DirectoryServer {

  private final HttpServer httpServer;
  private final ServerConfig config;

  private DirectoryServer(final HttpServer httpServer, final ServerConfig config) {
    this.httpServer = httpServer;
    this.config = config;
  }

  /**
   * Build a server from configuration and a resolved admin token.
   *
   * @param config     the resolved configuration.
   * @param adminToken the bootstrap admin token (already resolved from env/file by the caller).
   * @return a built, not-yet-started server.
   */
  public static DirectoryServer create(final ServerConfig config, final String adminToken)
      throws IOException {
    final Argon2SecretHasher hasher = new Argon2SecretHasher(config.argonSettings());
    final JsonStore<DirectoryDocument> store = new JsonStore<>(
        config.dataDir().resolve("directory.json"), DirectoryDocument.class);
    final DirectoryService directory = new DirectoryService(store, hasher, new RandomIds());

    final ApiHandlers handlers = new ApiHandlers(directory, new AdminAuthenticator(adminToken),
        OpenApiDocument.load());
    final Router router = handlers.router();

    final HttpServer http = HttpServer.create(new InetSocketAddress(config.host(), config.port()), 0);
    http.createContext("/", router);
    http.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    return new DirectoryServer(http, config);
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

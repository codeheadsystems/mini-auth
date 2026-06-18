package com.codeheadsystems.miniidp.server;

import com.codeheadsystems.miniidp.directory.ServiceAccountDirectory;
import com.codeheadsystems.miniidp.server.http.Router;
import com.codeheadsystems.miniidp.store.JsonStore;
import com.codeheadsystems.minikms.client.KmsSigningKeyStore;
import com.codeheadsystems.minitoken.service.AuditService;
import com.codeheadsystems.minitoken.service.RevocationService;
import com.codeheadsystems.minitoken.service.SigningKeyService;
import com.codeheadsystems.minitoken.service.TokenIssuer;
import com.codeheadsystems.minitoken.store.DocumentStore;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.Audit;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.Revocations;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import com.codeheadsystems.minitoken.util.RandomIds;
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
   * Build a server sourcing client identity from {@code directory} (signing keys stored plaintext).
   *
   * @param config     the resolved configuration.
   * @param adminToken the bootstrap admin token (already resolved from env/file by the caller).
   * @param directory  the service-account source (mini-directory) used at token issuance.
   * @param clock      the clock shared by every time-dependent service.
   * @return a built, not-yet-started server.
   */
  public static IdpServer create(final ServerConfig config, final String adminToken,
                                 final ServiceAccountDirectory directory, final Clock clock)
      throws IOException {
    return create(config, adminToken, null, directory, clock);
  }

  /**
   * Build a server, optionally wrapping signing keys under mini-kms.
   *
   * @param config      the resolved configuration.
   * @param adminToken  the bootstrap admin token.
   * @param kmsApiToken the mini-kms data-plane API token (env/file-resolved by the caller), or null
   *                    to store signing keys plaintext-at-0600 (the default educational path).
   * @param directory   the service-account source (mini-directory) used at token issuance.
   * @param clock       the clock shared by every time-dependent service.
   * @return a built, not-yet-started server.
   */
  public static IdpServer create(final ServerConfig config, final String adminToken,
                                 final String kmsApiToken, final ServiceAccountDirectory directory,
                                 final Clock clock) throws IOException {
    final RandomIds ids = new RandomIds();
    final SigningKeyService signingKeys = new SigningKeyService(
        signingKeyStore(config, kmsApiToken),
        ids, clock, config.retiredKeyRetention());
    final RevocationService revocations = new RevocationService(
        new JsonStore<>(config.dataDir().resolve("revocations.json"), Revocations.class), clock);
    final AuditService audit = new AuditService(
        new JsonStore<>(config.dataDir().resolve("audit.json"), Audit.class), clock);

    final TokenIssuer issuer = new TokenIssuer(
        signingKeys, ids, clock, config.issuer(), config.audience(), config.tokenTtl());
    final ApiHandlers handlers = new ApiHandlers(config, directory, signingKeys, revocations, audit,
        issuer, new AdminAuthenticator(adminToken), OpenApiDocument.load(), clock);
    final Router router = handlers.router();

    final HttpServer http = HttpServer.create(new InetSocketAddress(config.host(), config.port()), 0);
    http.createContext("/", router);
    http.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    return new IdpServer(http, config);
  }

  /**
   * The signing-key store: plaintext-at-0600 by default, or — when {@code --kms-*} is configured and
   * an API token was resolved — the same JSON store wrapped by {@link KmsSigningKeyStore} so the
   * private keys are envelope-encrypted under a mini-kms key group and never written in the clear.
   */
  private static DocumentStore<SigningKeys> signingKeyStore(final ServerConfig config,
                                                            final String kmsApiToken) {
    final JsonStore<SigningKeys> file =
        new JsonStore<>(config.dataDir().resolve("signing-keys.json"), SigningKeys.class);
    if (config.kmsEnabled() && kmsApiToken != null) {
      return KmsSigningKeyStore.overTcp(
          file, config.kmsHost(), config.kmsPort(), kmsApiToken, config.kmsKeyGroup());
    }
    return file;
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

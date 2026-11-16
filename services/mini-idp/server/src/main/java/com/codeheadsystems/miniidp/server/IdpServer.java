package com.codeheadsystems.miniidp.server;

import com.codeheadsystems.miniidp.directory.ServiceAccountDirectory;
import com.codeheadsystems.miniidp.server.http.Router;
import com.codeheadsystems.miniidp.store.JsonStore;
import com.codeheadsystems.minikms.client.KmsSigningKeyStore;
import com.codeheadsystems.minitoken.crypto.SigningAlgorithm;
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
import java.util.EnumMap;
import java.util.Map;
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
 * <p><b>Signing keys per algorithm.</b> Ed25519 ({@code signing-keys.json}) always exists and signs
 * every token for the default audience. When any audience is mapped to ES256
 * ({@code --audience-algorithm config-server=ES256}), a second, independent key set
 * ({@code signing-keys-es256.json}) is created with the same rotation/retention rules and the same
 * at-rest protection (KMS-wrapped when {@code --kms-*} is set), and its public keys are published in
 * the same JWKS. Without such a mapping nothing about the key material or JWKS changes.
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
    // Bind first, so an ephemeral port (--port 0) is known before the issuer URL is fixed: with no
    // explicit --issuer, iss / discovery / jwks_uri then name the address that actually answers.
    final HttpServer http = HttpServer.create(new InetSocketAddress(config.host(), config.port()), 0);
    final ServerConfig bound = config.withBoundPort(http.getAddress().getPort());
    try {
      return assemble(http, bound, adminToken, kmsApiToken, directory, clock);
    } catch (final IOException | RuntimeException e) {
      http.stop(0);
      throw e;
    }
  }

  private static IdpServer assemble(final HttpServer http, final ServerConfig config,
                                    final String adminToken, final String kmsApiToken,
                                    final ServiceAccountDirectory directory, final Clock clock)
      throws IOException {
    final RandomIds ids = new RandomIds();
    final SigningKeyService signingKeys = new SigningKeyService(
        signingKeyStore(config, kmsApiToken, "signing-keys.json"),
        ids, clock, config.retiredKeyRetention());
    final Map<SigningAlgorithm, SigningKeyService> keySets = new EnumMap<>(SigningAlgorithm.class);
    keySets.put(SigningAlgorithm.EDDSA, signingKeys);
    if (config.es256Enabled()) {
      keySets.put(SigningAlgorithm.ES256, new SigningKeyService(
          signingKeyStore(config, kmsApiToken, "signing-keys-es256.json"),
          SigningAlgorithm.ES256, ids, clock, config.retiredKeyRetention()));
    }
    final RevocationService revocations = new RevocationService(
        new JsonStore<>(config.dataDir().resolve("revocations.json"), Revocations.class), clock);
    final AuditService audit = new AuditService(
        new JsonStore<>(config.dataDir().resolve("audit.json"), Audit.class), clock);

    final TokenIssuer issuer = new TokenIssuer(
        signingKeys, ids, clock, config.issuer(), config.audience(), config.tokenTtl());
    final ApiHandlers handlers = new ApiHandlers(config, directory, keySets, revocations, audit,
        issuer, new AdminAuthenticator(adminToken), OpenApiDocument.load(), clock);
    final Router router = handlers.router();

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
                                                            final String kmsApiToken,
                                                            final String fileName) {
    final JsonStore<SigningKeys> file =
        new JsonStore<>(config.dataDir().resolve(fileName), SigningKeys.class);
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

  /**
   * @return the configuration this server runs with: the one it was built from, with the bound port
   *     (and, when the issuer was derived rather than given, the issuer) filled in.
   */
  public ServerConfig config() {
    return config;
  }
}

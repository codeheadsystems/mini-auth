package com.codeheadsystems.minica.server;

import com.codeheadsystems.minica.server.http.Router;
import com.codeheadsystems.minica.service.CaService;
import com.codeheadsystems.minica.store.CaDocuments.CaCertificate;
import com.codeheadsystems.minica.store.CaDocuments.IssuanceLog;
import com.codeheadsystems.minica.store.CaDocuments.RevocationList;
import com.codeheadsystems.minica.store.JsonStore;
import com.codeheadsystems.minikms.client.KmsSigningKeyStore;
import com.codeheadsystems.minitoken.store.DocumentStore;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.util.concurrent.Executors;

/**
 * Assembles the CA over its JSON stores and exposes it on a loopback {@link HttpServer}.
 *
 * <p>Composition root: it opens the CA-key store (plaintext, or — when {@code --kms-*} is configured
 * — wrapped by {@link KmsSigningKeyStore} so the CA private key is envelope-encrypted under mini-kms),
 * the public root-cert / issuance-log / revocation stores, the {@link CaService} (which bootstraps a
 * fresh CA on first run), and the {@link ApiHandlers}/router. Each request runs on a virtual thread;
 * binding is loopback-only.
 */
public final class CaServer {

  private final HttpServer httpServer;
  private final ServerConfig config;

  private CaServer(final HttpServer httpServer, final ServerConfig config) {
    this.httpServer = httpServer;
    this.config = config;
  }

  /** Build a server with the CA key stored plaintext-at-0600. */
  public static CaServer create(final ServerConfig config, final String adminToken, final Clock clock)
      throws IOException {
    return create(config, adminToken, null, clock);
  }

  /**
   * Build a server, optionally wrapping the CA key under mini-kms.
   *
   * @param config      the resolved configuration.
   * @param adminToken  the bootstrap admin token guarding issuance/renewal/revocation/log.
   * @param kmsApiToken the mini-kms data-plane API token (env/file-resolved), or null for plaintext.
   * @param clock       the clock shared by every time-dependent operation.
   * @return a built, not-yet-started server.
   */
  public static CaServer create(final ServerConfig config, final String adminToken,
                                final String kmsApiToken, final Clock clock) throws IOException {
    final CaService ca = new CaService(
        caKeyStore(config, kmsApiToken),
        new JsonStore<>(config.dataDir().resolve("ca-cert.json"), CaCertificate.class),
        new JsonStore<>(config.dataDir().resolve("issuance-log.json"), IssuanceLog.class),
        new JsonStore<>(config.dataDir().resolve("revocations.json"), RevocationList.class),
        config.caSubject(), config.caValidity(), clock);

    final ApiHandlers handlers = new ApiHandlers(config, ca, new AdminAuthenticator(adminToken),
        OpenApiDocument.load());
    final Router router = handlers.router();

    final HttpServer http = HttpServer.create(new InetSocketAddress(config.host(), config.port()), 0);
    http.createContext("/", router);
    http.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    return new CaServer(http, config);
  }

  /** The CA-key store: plaintext-at-0600, or wrapped under mini-kms when configured. */
  private static DocumentStore<SigningKeys> caKeyStore(final ServerConfig config, final String kmsApiToken) {
    final JsonStore<SigningKeys> file =
        new JsonStore<>(config.dataDir().resolve("ca-key.json"), SigningKeys.class);
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

  /** @return the actual bound address. */
  public InetSocketAddress address() {
    return httpServer.getAddress();
  }

  /** @return the configuration this server was built from. */
  public ServerConfig config() {
    return config;
  }
}

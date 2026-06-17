package com.codeheadsystems.minioidc.server;

import com.codeheadsystems.minioidc.auth.HumanAuthenticator;
import com.codeheadsystems.minioidc.auth.RecoveryAuthenticator;
import com.codeheadsystems.minioidc.directory.UserDirectory;
import com.codeheadsystems.minioidc.secret.Argon2SecretHasher;
import com.codeheadsystems.minioidc.server.http.Router;
import com.codeheadsystems.minioidc.service.AuthorizationCodeStore;
import com.codeheadsystems.minioidc.service.ClientService;
import com.codeheadsystems.minioidc.service.OidcTokens;
import com.codeheadsystems.minioidc.service.PendingAuthorizationStore;
import com.codeheadsystems.minioidc.service.RefreshTokenService;
import com.codeheadsystems.minioidc.service.ScopeAuthorizer;
import com.codeheadsystems.minioidc.service.SessionService;
import com.codeheadsystems.minioidc.store.ClientRegistry;
import com.codeheadsystems.minioidc.store.JsonStore;
import com.codeheadsystems.minioidc.util.Tokens;
import com.codeheadsystems.minitoken.service.SigningKeyService;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import com.codeheadsystems.minitoken.util.RandomIds;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.Executors;

/**
 * Assembles the OpenID Provider over its stores and the shared token plane, and exposes it through a
 * loopback {@link HttpServer}.
 *
 * <p>This is the composition root. The human-authentication collaborators ({@link UserDirectory},
 * {@link HumanAuthenticator}, {@link RecoveryAuthenticator}) are injected so the wiring is explicit
 * and testable — production builds them from {@link ServerConfig} (a pk-auth stack + an HTTP
 * mini-directory client), while a test can substitute an in-memory directory and a pk-auth stack
 * driven by a fake authenticator. The signing keys, JWKS, and rotation come from mini-token's
 * {@link SigningKeyService}; mini-oidc only composes claim sets on top.
 *
 * <p>Each request runs on a virtual thread; binding is loopback-only by default.
 */
public final class OidcServer {

  private final HttpServer httpServer;
  private final ServerConfig config;

  private OidcServer(final HttpServer httpServer, final ServerConfig config) {
    this.httpServer = httpServer;
    this.config = config;
  }

  /**
   * Build a server from configuration, a resolved admin token, and the authentication collaborators.
   *
   * @param config     the resolved configuration.
   * @param adminToken the bootstrap admin token guarding {@code /admin/**} (resolved from env/file).
   * @param directory  resolves an authenticated human to a principal + grants (via mini-directory).
   * @param humans     the passkey (WebAuthn) authenticator.
   * @param recovery   the fallback/recovery authenticator (backup codes).
   * @param clock      the clock shared by every time-dependent service.
   * @return a built, not-yet-started server.
   */
  public static OidcServer create(final ServerConfig config, final String adminToken,
                                  final UserDirectory directory, final HumanAuthenticator humans,
                                  final RecoveryAuthenticator recovery, final Clock clock)
      throws IOException {
    final Tokens tokenGen = new Tokens();
    final Argon2SecretHasher hasher = new Argon2SecretHasher(config.argonSettings());

    final ClientService clients = new ClientService(
        new JsonStore<>(config.dataDir().resolve("clients.json"), ClientRegistry.class),
        hasher, tokenGen, clock);

    // Retired signing keys stay published well past the longest token TTL so in-flight tokens verify.
    final Duration retention = maxTtl(config).multipliedBy(2);
    final SigningKeyService signingKeys = new SigningKeyService(
        new JsonStore<>(config.dataDir().resolve("signing-keys.json"), SigningKeys.class),
        new RandomIds(), clock, retention);
    final OidcTokens tokens = new OidcTokens(signingKeys, clock, config.issuer(),
        config.accessAudience(), config.idTtl(), config.accessTtl());

    final OidcHandlers handlers = new OidcHandlers(config, clients, tokens, new ScopeAuthorizer(),
        directory, humans, recovery, new SessionService(clock, tokenGen, config.sessionTtl()),
        new PendingAuthorizationStore(clock, Duration.ofMinutes(10)),
        new AuthorizationCodeStore(clock),
        new RefreshTokenService(clock, tokenGen, config.refreshTtl()),
        new AdminAuthenticator(adminToken), OpenApiDocument.load(), tokenGen, clock);
    final Router router = handlers.router();

    final HttpServer http = HttpServer.create(new InetSocketAddress(config.host(), config.port()), 0);
    http.createContext("/", router);
    http.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    return new OidcServer(http, config);
  }

  private static Duration maxTtl(final ServerConfig config) {
    return config.idTtl().compareTo(config.accessTtl()) >= 0 ? config.idTtl() : config.accessTtl();
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

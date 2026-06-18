package com.codeheadsystems.minioidc;

import com.codeheadsystems.minioidc.auth.PasskeyStack;
import com.codeheadsystems.minioidc.directory.HttpUserDirectory;
import com.codeheadsystems.minioidc.directory.InMemoryUserDirectory;
import com.codeheadsystems.minioidc.directory.UserDirectory;
import com.codeheadsystems.minioidc.server.OidcServer;
import com.codeheadsystems.minioidc.server.ServerConfig;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * mini-oidc entry point — the human SSO / OpenID Provider.
 *
 * <p>Startup mirrors the siblings: resolve {@link ServerConfig}, resolve the bootstrap admin token
 * (env/file, never argv, never logged), build the production collaborators — the embedded pk-auth
 * passkey stack and the mini-directory client (an {@link HttpUserDirectory} when
 * {@code --directory-url} is set, else an empty in-memory directory) — then bind loopback and serve.
 *
 * <p><b>Loopback / TLS.</b> The server binds {@code 127.0.0.1} by default. Exposing it on a LAN is
 * an explicit operator decision and MUST be done behind a TLS-terminating reverse proxy, with
 * {@code --secure-cookies} enabled (WebAuthn and secure cookies both require a secure context).
 */
public final class ServerMain {

  static final String ENV_ADMIN_TOKEN = "MINIOIDC_ADMIN_TOKEN";
  static final String ENV_DIRECTORY_TOKEN = "MINIOIDC_DIRECTORY_TOKEN";
  static final String ENV_KMS_API_TOKEN = "MINIOIDC_KMS_API_TOKEN";

  private ServerMain() {
  }

  /** @param args CLI arguments (see {@link ServerConfig}). */
  public static void main(final String[] args) {
    try {
      run(args, System.getenv());
    } catch (final IllegalArgumentException | IllegalStateException e) {
      System.err.println("Configuration error: " + e.getMessage());
      System.exit(64);
    } catch (final IOException e) {
      System.err.println("I/O error: " + e.getMessage());
      System.exit(74);
    }
  }

  private static void run(final String[] args, final Map<String, String> env) throws IOException {
    final ServerConfig config = ServerConfig.resolve(args, env);
    final String adminToken = resolveToken(env.get(ENV_ADMIN_TOKEN), config.adminTokenFilePath(),
        "no admin token configured: set " + ENV_ADMIN_TOKEN + " or provide --admin-token-file");
    final String kmsApiToken = config.kmsEnabled()
        ? resolveToken(env.get(ENV_KMS_API_TOKEN), config.kmsApiTokenFilePath(),
            "--kms-* is set but no mini-kms API token: set " + ENV_KMS_API_TOKEN
                + " or provide --kms-api-token-file")
        : null;

    final PasskeyStack passkeys = PasskeyStack.inMemory(
        new RelyingPartyConfig(config.rpId(), config.rpName(), config.rpOrigins()),
        ClockProvider.system());
    final UserDirectory directory = resolveDirectory(config, env);

    final OidcServer server = OidcServer.create(config, adminToken, kmsApiToken, directory,
        passkeys.humanAuthenticator(), passkeys.recoveryAuthenticator(), Clock.systemUTC());

    final CountDownLatch shutdown = new CountDownLatch(1);
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      server.stop();
      shutdown.countDown();
    }, "minioidc-shutdown"));

    server.start();
    System.out.println("mini-oidc is running on http://" + server.address().getHostString()
        + ":" + server.address().getPort());
    System.out.println("issuer=" + config.issuer() + "  rpId=" + config.rpId());
    System.out.println("discovery: " + config.issuer() + "/.well-known/openid-configuration");
    System.out.println("docs: http://" + server.address().getHostString() + ":"
        + server.address().getPort() + "/docs");
    System.out.println("Press Ctrl-C to stop.");
    awaitShutdown(shutdown);
  }

  private static UserDirectory resolveDirectory(final ServerConfig config, final Map<String, String> env)
      throws IOException {
    if (config.directoryUrl() == null || config.directoryUrl().isBlank()) {
      System.out.println("No --directory-url configured: using an empty in-memory directory "
          + "(no human will resolve until one is added). Point at a running mini-directory for real use.");
      return new InMemoryUserDirectory();
    }
    final String token = resolveToken(env.get(ENV_DIRECTORY_TOKEN), config.directoryTokenFilePath(),
        "a directory URL was set but no admin token: set " + ENV_DIRECTORY_TOKEN
            + " or provide --directory-token-file");
    return new HttpUserDirectory(config.directoryUrl(), token);
  }

  private static String resolveToken(final String fromEnv, final Path file, final String missingMessage)
      throws IOException {
    if (fromEnv != null && !fromEnv.isBlank()) {
      return fromEnv.trim();
    }
    if (file != null) {
      final String fromFile = Files.readString(file, StandardCharsets.UTF_8).strip();
      if (!fromFile.isEmpty()) {
        return fromFile;
      }
    }
    throw new IllegalStateException(missingMessage);
  }

  private static void awaitShutdown(final CountDownLatch shutdown) {
    try {
      shutdown.await();
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }
}

package com.codeheadsystems.miniidp.server;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * Server entry point.
 *
 * <p>Startup sequence (mirrors mini-kms's {@code ServerMain}):
 * <ol>
 *   <li>Resolve {@link ServerConfig} from flags + environment.</li>
 *   <li>Resolve the <b>bootstrap admin token</b> from an env var or a token file — never a
 *       plaintext CLI arg, never logged.</li>
 *   <li>Build the {@link IdpServer} (services over the JSON stores; mints the initial signing key
 *       on first run).</li>
 *   <li>Bind loopback and serve until interrupted; a shutdown hook stops the HTTP server.</li>
 * </ol>
 */
public final class ServerMain {

  /** Env var carrying the bootstrap admin token value. */
  static final String ENV_ADMIN_TOKEN = "MINIIDP_ADMIN_TOKEN";

  /** Env var carrying the mini-kms data-plane API token (when signing keys are KMS-wrapped). */
  static final String ENV_KMS_API_TOKEN = "MINIIDP_KMS_API_TOKEN";

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
    final String adminToken = resolveAdminToken(env, config.adminTokenFilePath());
    final String kmsApiToken = resolveKmsApiToken(env, config);

    final IdpServer server = IdpServer.create(config, adminToken, kmsApiToken, Clock.systemUTC());

    final CountDownLatch shutdown = new CountDownLatch(1);
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      server.stop();
      shutdown.countDown();
    }, "miniidp-shutdown"));

    server.start();
    // Never print the admin token or any secret — only non-sensitive runtime facts.
    System.out.println("mini-idp is running on http://" + server.address().getHostString()
        + ":" + server.address().getPort());
    System.out.println("issuer=" + config.issuer() + "  audience=" + config.audience()
        + "  token TTL=" + config.tokenTtl().toSeconds() + "s");
    System.out.println("signing keys: " + (config.kmsEnabled()
        ? "wrapped under mini-kms group '" + config.kmsKeyGroup() + "' at " + config.kmsHost() + ":" + config.kmsPort()
        : "local file (plaintext, 0600)"));
    System.out.println("docs: http://" + server.address().getHostString() + ":"
        + server.address().getPort() + "/docs");
    System.out.println("Press Ctrl-C to stop.");
    awaitShutdown(shutdown);
  }

  private static void awaitShutdown(final CountDownLatch shutdown) {
    try {
      shutdown.await();
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  /** Resolve the admin token from its env var or a token file; required (no default). */
  private static String resolveAdminToken(final Map<String, String> env, final Path tokenFile)
      throws IOException {
    final String fromEnv = env.get(ENV_ADMIN_TOKEN);
    if (fromEnv != null && !fromEnv.isBlank()) {
      return fromEnv.trim();
    }
    if (tokenFile != null) {
      final String fromFile = Files.readString(tokenFile, StandardCharsets.UTF_8).strip();
      if (!fromFile.isEmpty()) {
        return fromFile;
      }
    }
    throw new IllegalStateException("no admin token configured: set " + ENV_ADMIN_TOKEN
        + " or provide --admin-token-file");
  }

  /** Resolve the mini-kms API token (env or file) when KMS wrapping is enabled, else null. */
  private static String resolveKmsApiToken(final Map<String, String> env, final ServerConfig config)
      throws IOException {
    if (!config.kmsEnabled()) {
      return null;
    }
    final String fromEnv = env.get(ENV_KMS_API_TOKEN);
    if (fromEnv != null && !fromEnv.isBlank()) {
      return fromEnv.trim();
    }
    if (config.kmsApiTokenFilePath() != null) {
      final String fromFile = Files.readString(config.kmsApiTokenFilePath(), StandardCharsets.UTF_8).strip();
      if (!fromFile.isEmpty()) {
        return fromFile;
      }
    }
    throw new IllegalStateException("--kms-* is set but no mini-kms API token: set " + ENV_KMS_API_TOKEN
        + " or provide --kms-api-token-file");
  }
}

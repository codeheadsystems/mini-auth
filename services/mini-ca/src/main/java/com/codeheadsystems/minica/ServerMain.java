package com.codeheadsystems.minica;

import com.codeheadsystems.minica.server.CaServer;
import com.codeheadsystems.minica.server.ServerConfig;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * mini-ca entry point — a small internal certificate authority for the homelab.
 *
 * <p>Startup mirrors the family: resolve {@link ServerConfig}, resolve the bootstrap admin token
 * (env/file, never argv, never logged), resolve the mini-kms token if the CA key is KMS-wrapped,
 * build the {@link CaServer} (which mints a fresh CA on first run), bind loopback, and serve.
 *
 * <p><b>Loopback / TLS.</b> Binds {@code 127.0.0.1} by default. The CA issues the certs that secure
 * the LAN; it must not itself be exposed beyond loopback / the trusted reverse proxy.
 */
public final class ServerMain {

  static final String ENV_ADMIN_TOKEN = "MINICA_ADMIN_TOKEN";
  static final String ENV_KMS_API_TOKEN = "MINICA_KMS_API_TOKEN";

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

    final CaServer server = CaServer.create(config, adminToken, kmsApiToken, Clock.systemUTC());

    final CountDownLatch shutdown = new CountDownLatch(1);
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      server.stop();
      shutdown.countDown();
    }, "minica-shutdown"));

    server.start();
    System.out.println("mini-ca is running on http://" + server.address().getHostString()
        + ":" + server.address().getPort());
    System.out.println("CA subject: " + config.caSubject()
        + "   CA key: " + (config.kmsEnabled() ? "wrapped under mini-kms" : "local file (0600)"));
    System.out.println("trust anchor: GET /ca   |   docs: http://" + server.address().getHostString()
        + ":" + server.address().getPort() + "/docs");
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

  private static String resolveToken(final String fromEnv, final Path file, final String message)
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
    throw new IllegalStateException(message);
  }
}

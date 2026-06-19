package com.codeheadsystems.miniconsole;

import com.codeheadsystems.miniconsole.server.ConsoleConfig;
import com.codeheadsystems.miniconsole.server.ConsoleServer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * mini-console entry point — the optional unified admin console over the mini- family.
 *
 * <p>Startup mirrors the siblings: resolve {@link ConsoleConfig}, resolve the bootstrap console token
 * (env/file, never argv, never logged), build {@link ConsoleServer}, then bind loopback and serve.
 *
 * <p><b>Loopback / TLS.</b> The server binds {@code 127.0.0.1} by default. Exposing it on a LAN is an
 * explicit operator decision and MUST be done behind a TLS-terminating reverse proxy, with
 * {@code --secure-cookies} enabled.
 */
public final class ServerMain {

  static final String ENV_ADMIN_TOKEN = "MINICONSOLE_ADMIN_TOKEN";

  private ServerMain() {
  }

  /** @param args CLI arguments (see {@link ConsoleConfig}). */
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
    final ConsoleConfig config = ConsoleConfig.resolve(args, env);
    final String consoleToken = resolveToken(env.get(ENV_ADMIN_TOKEN), config.adminTokenFilePath(),
        "no console token configured: set " + ENV_ADMIN_TOKEN + " or provide --admin-token-file");

    final ConsoleServer server = ConsoleServer.create(config, consoleToken, Clock.systemUTC());

    final CountDownLatch shutdown = new CountDownLatch(1);
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      server.stop();
      shutdown.countDown();
    }, "miniconsole-shutdown"));

    server.start();
    System.out.println("mini-console is running on http://" + server.address().getHostString()
        + ":" + server.address().getPort());
    System.out.println("data dir: " + config.dataDir());
    System.out.println("Sign in at http://" + server.address().getHostString() + ":"
        + server.address().getPort() + "/login");
    System.out.println("Press Ctrl-C to stop.");
    awaitShutdown(shutdown);
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

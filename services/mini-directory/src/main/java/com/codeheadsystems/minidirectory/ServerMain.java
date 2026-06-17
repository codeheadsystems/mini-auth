package com.codeheadsystems.minidirectory;

import com.codeheadsystems.minidirectory.server.DirectoryServer;
import com.codeheadsystems.minidirectory.server.ServerConfig;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * mini-directory entry point — the identity source of truth: humans, groups, roles, and service
 * accounts, each resolvable to a mini-policy principal with grants.
 *
 * <p>Startup sequence (mirrors mini-idp's {@code ServerMain}):
 * <ol>
 *   <li>Resolve {@link ServerConfig} from flags + environment.</li>
 *   <li>Resolve the <b>bootstrap admin token</b> from an env var or a token file — never a
 *       plaintext CLI arg, never logged.</li>
 *   <li>Build the {@link DirectoryServer} (the directory service over its JSON store).</li>
 *   <li>Bind loopback and serve until interrupted; a shutdown hook stops the HTTP server.</li>
 * </ol>
 *
 * <p>This service does <b>not</b> yet wire into mini-idp or mini-oidc — it stands alone. Those
 * issuers will later read identities and grants from it (see {@code docs/DIRECTION.md}).
 */
public final class ServerMain {

  /** Env var carrying the bootstrap admin token value. */
  static final String ENV_ADMIN_TOKEN = "MINIDIR_ADMIN_TOKEN";

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

    final DirectoryServer server = DirectoryServer.create(config, adminToken);

    final CountDownLatch shutdown = new CountDownLatch(1);
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      server.stop();
      shutdown.countDown();
    }, "minidirectory-shutdown"));

    server.start();
    // Never print the admin token or any secret — only non-sensitive runtime facts.
    System.out.println("mini-directory is running on http://" + server.address().getHostString()
        + ":" + server.address().getPort());
    System.out.println("data dir: " + config.dataDir());
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
}

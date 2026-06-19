package com.codeheadsystems.miniconsole;

import com.codeheadsystems.miniclient.common.TokenResolver;
import com.codeheadsystems.miniconsole.kms.KeyGroupAdmin;
import com.codeheadsystems.miniconsole.kms.KmsKeyGroupAdmin;
import com.codeheadsystems.miniconsole.server.ConsoleConfig;
import com.codeheadsystems.miniconsole.server.ConsoleServer;
import com.codeheadsystems.minica.client.MiniCaClient;
import com.codeheadsystems.minidirectory.client.MiniDirectoryClient;
import com.codeheadsystems.miniidp.client.MiniIdpClient;
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
  static final String ENV_DIRECTORY_TOKEN = "MINICONSOLE_DIRECTORY_TOKEN";
  static final String ENV_IDP_TOKEN = "MINICONSOLE_IDP_TOKEN";
  static final String ENV_KMS_API_TOKEN = "MINICONSOLE_KMS_API_TOKEN";
  static final String ENV_KMS_ADMIN_TOKEN = "MINICONSOLE_KMS_ADMIN_TOKEN";
  static final String ENV_CA_TOKEN = "MINICONSOLE_CA_TOKEN";

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
    final MiniDirectoryClient directory = wireDirectory(config, env);
    final MiniIdpClient idp = wireIdp(config, env);
    final KeyGroupAdmin keys = wireKms(config, env);
    final MiniCaClient ca = wireCa(config, env);

    final ConsoleServer server =
        ConsoleServer.create(config, consoleToken, directory, idp, keys, ca, Clock.systemUTC());

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

  /**
   * Build the mini-directory client if (and only if) a directory URL is configured. The directory
   * admin token is resolved from {@code MINICONSOLE_DIRECTORY_TOKEN} or {@code --directory-token-file}
   * (console-scoped, never argv, never logged) and is required once a URL is set.
   *
   * @return the wired client, or null when the directory is not configured (the console then shows
   *     "directory not configured" rather than failing to start).
   */
  private static MiniDirectoryClient wireDirectory(final ConsoleConfig config,
                                                   final Map<String, String> env) throws IOException {
    if (config.directoryUrl() == null) {
      return null;
    }
    final String token = TokenResolver.require(env.get(ENV_DIRECTORY_TOKEN),
        config.directoryTokenFilePath(),
        "--directory-url is set but no directory token: set " + ENV_DIRECTORY_TOKEN
            + " or provide --directory-token-file");
    return MiniDirectoryClient.http(config.directoryUrl(), token);
  }

  /**
   * Build the mini-idp client if (and only if) an idp URL is configured. The idp admin token is
   * resolved from {@code MINICONSOLE_IDP_TOKEN} or {@code --idp-token-file} (console-scoped, never
   * argv, never logged) and is required once a URL is set (the audit page needs it; the public token
   * and JWKS calls do not, but the client holds one token for the admin surface).
   *
   * @return the wired client, or null when mini-idp is not configured.
   */
  private static MiniIdpClient wireIdp(final ConsoleConfig config, final Map<String, String> env)
      throws IOException {
    if (config.idpUrl() == null) {
      return null;
    }
    final String token = TokenResolver.require(env.get(ENV_IDP_TOKEN), config.idpTokenFilePath(),
        "--idp-url is set but no idp token: set " + ENV_IDP_TOKEN + " or provide --idp-token-file");
    return MiniIdpClient.http(config.idpUrl(), token);
  }

  /**
   * Build the mini-kms key-group admin if (and only if) a KMS endpoint is configured. Two tokens are
   * resolved (console-scoped, never argv, never logged): the data-plane API token (for health) and
   * the control-plane admin token (for key-group operations); both are required once {@code --kms-tcp}
   * is set.
   *
   * @return the wired admin port, or null when mini-kms is not configured.
   */
  private static KeyGroupAdmin wireKms(final ConsoleConfig config, final Map<String, String> env)
      throws IOException {
    if (!config.kmsConfigured()) {
      return null;
    }
    final String apiToken = TokenResolver.require(env.get(ENV_KMS_API_TOKEN),
        config.kmsApiTokenFilePath(),
        "--kms-tcp is set but no KMS API token: set " + ENV_KMS_API_TOKEN
            + " or provide --kms-api-token-file");
    final String adminToken = TokenResolver.require(env.get(ENV_KMS_ADMIN_TOKEN),
        config.kmsAdminTokenFilePath(),
        "--kms-tcp is set but no KMS admin token: set " + ENV_KMS_ADMIN_TOKEN
            + " or provide --kms-admin-token-file");
    return new KmsKeyGroupAdmin(config.kmsHost(), config.kmsPort(), apiToken, adminToken);
  }

  /**
   * Build the mini-ca client if (and only if) a CA URL is configured. The CA admin token is resolved
   * from {@code MINICONSOLE_CA_TOKEN} or {@code --ca-token-file} (console-scoped, never argv, never
   * logged) and is required once a URL is set (issuance/renewal/revocation/log need it; the public
   * trust-anchor and revocation reads do not, but the client holds one token for the admin surface).
   *
   * @return the wired client, or null when mini-ca is not configured.
   */
  private static MiniCaClient wireCa(final ConsoleConfig config, final Map<String, String> env)
      throws IOException {
    if (config.caUrl() == null) {
      return null;
    }
    final String token = TokenResolver.require(env.get(ENV_CA_TOKEN), config.caTokenFilePath(),
        "--ca-url is set but no ca token: set " + ENV_CA_TOKEN + " or provide --ca-token-file");
    return MiniCaClient.http(config.caUrl(), token);
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

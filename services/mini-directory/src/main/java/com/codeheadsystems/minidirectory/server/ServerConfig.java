package com.codeheadsystems.minidirectory.server;

import com.codeheadsystems.minidirectory.secret.Argon2Settings;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/**
 * Resolved server configuration: where to listen, where the JSON store lives, the Argon2 cost for
 * service-account secrets, and where the bootstrap admin token comes from. Values come from CLI
 * flags (highest priority), then environment variables, then sensible per-user defaults — mirroring
 * mini-idp's and mini-kms's {@code ServerConfig}.
 *
 * <p>Secrets are deliberately NOT stored here as plaintext: the admin token is resolved from its
 * source by {@link ServerMain} (env var or file) and handed straight to the authenticator; only the
 * token <em>file path</em> (config, not a secret) lives here.
 *
 * <p>Recognized flags / env vars:
 * <pre>
 *   --host H                 MINIDIR_HOST              loopback bind host (default 127.0.0.1)
 *   --port N                 MINIDIR_PORT              TCP port (default 8466)
 *   --data-dir PATH          MINIDIR_DATA_DIR          directory for the JSON store
 *   --admin-token-file PATH  MINIDIR_ADMIN_TOKEN_FILE  file holding the admin token
 *                                                      (alt: MINIDIR_ADMIN_TOKEN env)
 *   --argon-memory-kib N     MINIDIR_ARGON_MEMORY_KIB  Argon2 memory cost for service-account secrets
 *   --argon-iterations N     MINIDIR_ARGON_ITERATIONS  Argon2 time cost
 *   --argon-parallelism N    MINIDIR_ARGON_PARALLELISM Argon2 lanes
 * </pre>
 */
public final class ServerConfig {

  /** Default loopback bind host. */
  public static final String DEFAULT_HOST = "127.0.0.1";

  /** Default TCP port (one above mini-idp's 8455, so the family's services don't collide locally). */
  public static final int DEFAULT_PORT = 8466;

  private final String host;
  private final int port;
  private final Path dataDir;
  private final Path adminTokenFilePath;
  private final Argon2Settings argonSettings;

  ServerConfig(final String host, final int port, final Path dataDir,
               final Path adminTokenFilePath, final Argon2Settings argonSettings) {
    this.host = host;
    this.port = port;
    this.dataDir = dataDir;
    this.adminTokenFilePath = adminTokenFilePath;
    this.argonSettings = argonSettings;
  }

  /**
   * Resolve configuration from CLI args and the process environment.
   *
   * @param args the raw CLI arguments.
   * @param env  the environment (injectable for testing; usually {@code System.getenv()}).
   * @return the resolved, validated configuration.
   */
  public static ServerConfig resolve(final String[] args, final Map<String, String> env) {
    String host = env.get("MINIDIR_HOST");
    Integer port = envInt(env, "MINIDIR_PORT");
    String dataDir = env.get("MINIDIR_DATA_DIR");
    String adminTokenFile = env.get("MINIDIR_ADMIN_TOKEN_FILE");
    Integer argonMemory = envInt(env, "MINIDIR_ARGON_MEMORY_KIB");
    Integer argonIterations = envInt(env, "MINIDIR_ARGON_ITERATIONS");
    Integer argonParallelism = envInt(env, "MINIDIR_ARGON_PARALLELISM");

    for (int i = 0; i < args.length; i++) {
      final String arg = args[i];
      switch (arg) {
        case "--host" -> host = requireValue(args, ++i, arg);
        case "--port" -> port = Integer.parseInt(requireValue(args, ++i, arg));
        case "--data-dir" -> dataDir = requireValue(args, ++i, arg);
        case "--admin-token-file" -> adminTokenFile = requireValue(args, ++i, arg);
        case "--argon-memory-kib" -> argonMemory = Integer.parseInt(requireValue(args, ++i, arg));
        case "--argon-iterations" -> argonIterations = Integer.parseInt(requireValue(args, ++i, arg));
        case "--argon-parallelism" -> argonParallelism = Integer.parseInt(requireValue(args, ++i, arg));
        default -> throw new IllegalArgumentException("unknown argument: " + arg);
      }
    }

    final String resolvedHost = host != null && !host.isBlank() ? host : DEFAULT_HOST;
    final int resolvedPort = port != null ? port : DEFAULT_PORT;
    if (resolvedPort < 0 || resolvedPort > 65535) {
      throw new IllegalArgumentException("port must be in 0..65535");
    }

    final Path resolvedDataDir = dataDir != null ? Paths.get(dataDir) : defaultDataDir(env);
    final Path adminTokenFilePath = adminTokenFile != null ? Paths.get(adminTokenFile) : null;

    final Argon2Settings argon = new Argon2Settings(
        argonMemory != null ? argonMemory : Argon2Settings.DEFAULT_MEMORY_KIB,
        argonIterations != null ? argonIterations : Argon2Settings.DEFAULT_ITERATIONS,
        argonParallelism != null ? argonParallelism : Argon2Settings.DEFAULT_PARALLELISM);

    return new ServerConfig(resolvedHost, resolvedPort, resolvedDataDir, adminTokenFilePath, argon);
  }

  private static Path defaultDataDir(final Map<String, String> env) {
    final String xdg = env.get("XDG_DATA_HOME");
    if (xdg != null && !xdg.isBlank()) {
      return Paths.get(xdg, "mini-directory");
    }
    final String home = env.getOrDefault("HOME", System.getProperty("user.home", "."));
    return Paths.get(home, ".mini-directory");
  }

  private static Integer envInt(final Map<String, String> env, final String key) {
    final String value = env.get(key);
    return value == null ? null : Integer.valueOf(value.trim());
  }

  private static String requireValue(final String[] args, final int index, final String flag) {
    if (index >= args.length) {
      throw new IllegalArgumentException("flag " + flag + " requires a value");
    }
    return args[index];
  }

  /** @return the loopback bind host. */
  public String host() {
    return host;
  }

  /** @return the TCP port (0 means an ephemeral port is chosen). */
  public int port() {
    return port;
  }

  /** @return the directory holding the JSON store. */
  public Path dataDir() {
    return dataDir;
  }

  /** @return the file to read the admin token from, or null (env is then required). */
  public Path adminTokenFilePath() {
    return adminTokenFilePath;
  }

  /** @return the Argon2 parameters used to hash service-account secrets. */
  public Argon2Settings argonSettings() {
    return argonSettings;
  }
}

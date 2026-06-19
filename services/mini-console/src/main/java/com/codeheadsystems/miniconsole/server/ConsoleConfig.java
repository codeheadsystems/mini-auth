package com.codeheadsystems.miniconsole.server;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Map;

/**
 * Resolved server configuration for the admin console. Values come from CLI flags (highest
 * priority), then environment variables, then per-user defaults — mirroring the family's other
 * {@code ServerConfig}s, trimmed to what a console needs (it has no issuer/argon/KMS knobs in
 * Slice 0).
 *
 * <pre>
 *   --host H                  MINICONSOLE_HOST                loopback bind host (default 127.0.0.1)
 *   --port N                  MINICONSOLE_PORT                TCP port (default 8500)
 *   --data-dir PATH           MINICONSOLE_DATA_DIR            directory for the session store
 *   --admin-token-file PATH   MINICONSOLE_ADMIN_TOKEN_FILE    file holding the console token (alt: MINICONSOLE_ADMIN_TOKEN env)
 *   --secure-cookies          MINICONSOLE_SECURE_COOKIES      set the Secure flag on cookies (use behind TLS)
 *   --session-ttl-seconds N   MINICONSOLE_SESSION_TTL_SECONDS console-login session lifetime (default 43200 = 12h)
 * </pre>
 */
public final class ConsoleConfig {

  /** Default loopback bind host. */
  public static final String DEFAULT_HOST = "127.0.0.1";
  /** Default TCP port (one above mini-ca's 8499). */
  public static final int DEFAULT_PORT = 8500;
  /** Default console-login session lifetime (12 hours). */
  public static final int DEFAULT_SESSION_TTL_SECONDS = 43_200;

  private final String host;
  private final int port;
  private final Path dataDir;
  private final Path adminTokenFilePath;
  private final boolean secureCookies;
  private final Duration sessionTtl;

  ConsoleConfig(final String host, final int port, final Path dataDir, final Path adminTokenFilePath,
                final boolean secureCookies, final Duration sessionTtl) {
    this.host = host;
    this.port = port;
    this.dataDir = dataDir;
    this.adminTokenFilePath = adminTokenFilePath;
    this.secureCookies = secureCookies;
    this.sessionTtl = sessionTtl;
  }

  /** Resolve configuration from CLI args and the environment. */
  public static ConsoleConfig resolve(final String[] args, final Map<String, String> env) {
    String host = env.get("MINICONSOLE_HOST");
    Integer port = envInt(env, "MINICONSOLE_PORT");
    String dataDir = env.get("MINICONSOLE_DATA_DIR");
    String adminTokenFile = env.get("MINICONSOLE_ADMIN_TOKEN_FILE");
    boolean secureCookies = "true".equalsIgnoreCase(env.get("MINICONSOLE_SECURE_COOKIES"));
    Integer sessionTtl = envInt(env, "MINICONSOLE_SESSION_TTL_SECONDS");

    for (int i = 0; i < args.length; i++) {
      final String arg = args[i];
      switch (arg) {
        case "--host" -> host = requireValue(args, ++i, arg);
        case "--port" -> port = Integer.parseInt(requireValue(args, ++i, arg));
        case "--data-dir" -> dataDir = requireValue(args, ++i, arg);
        case "--admin-token-file" -> adminTokenFile = requireValue(args, ++i, arg);
        case "--secure-cookies" -> secureCookies = true;
        case "--session-ttl-seconds" -> sessionTtl = Integer.parseInt(requireValue(args, ++i, arg));
        default -> throw new IllegalArgumentException("unknown argument: " + arg);
      }
    }

    final String resolvedHost = host != null && !host.isBlank() ? host : DEFAULT_HOST;
    final int resolvedPort = port != null ? port : DEFAULT_PORT;
    if (resolvedPort < 0 || resolvedPort > 65535) {
      throw new IllegalArgumentException("port must be in 0..65535");
    }

    return new ConsoleConfig(
        resolvedHost, resolvedPort,
        dataDir != null ? Paths.get(dataDir) : defaultDataDir(env),
        adminTokenFile != null ? Paths.get(adminTokenFile) : null,
        secureCookies,
        Duration.ofSeconds(positiveOr(sessionTtl, DEFAULT_SESSION_TTL_SECONDS)));
  }

  /** @return the loopback bind host. */
  public String host() {
    return host;
  }

  /** @return the TCP port (0 binds an ephemeral port — useful in tests). */
  public int port() {
    return port;
  }

  /** @return the directory holding the console session store. */
  public Path dataDir() {
    return dataDir;
  }

  /** @return the file the console token may be read from, or null (then the env var is required). */
  public Path adminTokenFilePath() {
    return adminTokenFilePath;
  }

  /** @return whether to set the {@code Secure} flag on cookies (enable behind TLS). */
  public boolean secureCookies() {
    return secureCookies;
  }

  /** @return the console-login session lifetime. */
  public Duration sessionTtl() {
    return sessionTtl;
  }

  private static int positiveOr(final Integer value, final int fallback) {
    if (value == null) {
      return fallback;
    }
    if (value < 1) {
      throw new IllegalArgumentException("session TTL must be at least 1 second");
    }
    return value;
  }

  private static Path defaultDataDir(final Map<String, String> env) {
    final String xdg = env.get("XDG_DATA_HOME");
    if (xdg != null && !xdg.isBlank()) {
      return Paths.get(xdg, "mini-console");
    }
    final String home = env.getOrDefault("HOME", System.getProperty("user.home", "."));
    return Paths.get(home, ".mini-console");
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
}

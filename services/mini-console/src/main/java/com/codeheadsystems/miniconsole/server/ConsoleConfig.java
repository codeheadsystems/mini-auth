package com.codeheadsystems.miniconsole.server;

import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Map;

/**
 * Resolved server configuration for the admin console. Values come from CLI flags (highest
 * priority), then environment variables, then per-user defaults — mirroring the family's other
 * {@code ServerConfig}s, trimmed to what a console needs.
 *
 * <pre>
 *   --host H                  MINICONSOLE_HOST                loopback bind host (default 127.0.0.1)
 *   --port N                  MINICONSOLE_PORT                TCP port (default 8500)
 *   --data-dir PATH           MINICONSOLE_DATA_DIR            directory for the session store
 *   --admin-token-file PATH   MINICONSOLE_ADMIN_TOKEN_FILE    file holding the console token (alt: MINICONSOLE_ADMIN_TOKEN env)
 *   --secure-cookies          MINICONSOLE_SECURE_COOKIES      set the Secure flag on cookies (use behind TLS)
 *   --session-ttl-seconds N   MINICONSOLE_SESSION_TTL_SECONDS console-login session lifetime (default 43200 = 12h)
 *   --directory-url URL       MINICONSOLE_DIRECTORY_URL       mini-directory origin to wire (optional)
 *   --directory-token-file P  MINICONSOLE_DIRECTORY_TOKEN_FILE file holding the directory admin token (alt: MINICONSOLE_DIRECTORY_TOKEN env)
 *   --idp-url URL             MINICONSOLE_IDP_URL             mini-idp origin to wire (optional)
 *   --idp-token-file PATH     MINICONSOLE_IDP_TOKEN_FILE      file holding the idp admin token (alt: MINICONSOLE_IDP_TOKEN env)
 *   --kms-tcp HOST:PORT       MINICONSOLE_KMS_TCP             mini-kms loopback endpoint to wire (optional)
 *   --kms-api-token-file P    MINICONSOLE_KMS_API_TOKEN_FILE  file holding the KMS data-plane token (alt: MINICONSOLE_KMS_API_TOKEN env)
 *   --kms-admin-token-file P  MINICONSOLE_KMS_ADMIN_TOKEN_FILE file holding the KMS control-plane token (alt: MINICONSOLE_KMS_ADMIN_TOKEN env)
 *   --ca-url URL              MINICONSOLE_CA_URL              mini-ca origin to wire (optional)
 *   --ca-token-file PATH      MINICONSOLE_CA_TOKEN_FILE       file holding the ca admin token (alt: MINICONSOLE_CA_TOKEN env)
 * </pre>
 *
 * <p><b>Downstream tokens are console-scoped.</b> The console holds a copy of each downstream
 * service's admin token to call it on the operator's behalf. These use {@code MINICONSOLE_*} names
 * (e.g. {@code MINICONSOLE_DIRECTORY_TOKEN}), NOT the downstream service's own var (e.g.
 * {@code MINIDIR_ADMIN_TOKEN}) — so a co-hosted console never silently inherits another service's
 * environment, and the held-token concentration is explicit. (A refinement of the design doc's §6,
 * which used the downstream var names as shorthand.)
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
  private final URI directoryUrl;
  private final Path directoryTokenFilePath;
  private final URI idpUrl;
  private final Path idpTokenFilePath;
  private final String kmsHost;
  private final int kmsPort;
  private final Path kmsApiTokenFilePath;
  private final Path kmsAdminTokenFilePath;
  private final URI caUrl;
  private final Path caTokenFilePath;

  ConsoleConfig(final String host, final int port, final Path dataDir, final Path adminTokenFilePath,
                final boolean secureCookies, final Duration sessionTtl, final URI directoryUrl,
                final Path directoryTokenFilePath, final URI idpUrl, final Path idpTokenFilePath,
                final String kmsHost, final int kmsPort, final Path kmsApiTokenFilePath,
                final Path kmsAdminTokenFilePath, final URI caUrl, final Path caTokenFilePath) {
    this.host = host;
    this.port = port;
    this.dataDir = dataDir;
    this.adminTokenFilePath = adminTokenFilePath;
    this.secureCookies = secureCookies;
    this.sessionTtl = sessionTtl;
    this.directoryUrl = directoryUrl;
    this.directoryTokenFilePath = directoryTokenFilePath;
    this.idpUrl = idpUrl;
    this.idpTokenFilePath = idpTokenFilePath;
    this.kmsHost = kmsHost;
    this.kmsPort = kmsPort;
    this.kmsApiTokenFilePath = kmsApiTokenFilePath;
    this.kmsAdminTokenFilePath = kmsAdminTokenFilePath;
    this.caUrl = caUrl;
    this.caTokenFilePath = caTokenFilePath;
  }

  /** Resolve configuration from CLI args and the environment. */
  public static ConsoleConfig resolve(final String[] args, final Map<String, String> env) {
    String host = env.get("MINICONSOLE_HOST");
    Integer port = envInt(env, "MINICONSOLE_PORT");
    String dataDir = env.get("MINICONSOLE_DATA_DIR");
    String adminTokenFile = env.get("MINICONSOLE_ADMIN_TOKEN_FILE");
    boolean secureCookies = "true".equalsIgnoreCase(env.get("MINICONSOLE_SECURE_COOKIES"));
    Integer sessionTtl = envInt(env, "MINICONSOLE_SESSION_TTL_SECONDS");
    String directoryUrl = env.get("MINICONSOLE_DIRECTORY_URL");
    String directoryTokenFile = env.get("MINICONSOLE_DIRECTORY_TOKEN_FILE");
    String idpUrl = env.get("MINICONSOLE_IDP_URL");
    String idpTokenFile = env.get("MINICONSOLE_IDP_TOKEN_FILE");
    String kmsTcp = env.get("MINICONSOLE_KMS_TCP");
    String kmsApiTokenFile = env.get("MINICONSOLE_KMS_API_TOKEN_FILE");
    String kmsAdminTokenFile = env.get("MINICONSOLE_KMS_ADMIN_TOKEN_FILE");
    String caUrl = env.get("MINICONSOLE_CA_URL");
    String caTokenFile = env.get("MINICONSOLE_CA_TOKEN_FILE");

    for (int i = 0; i < args.length; i++) {
      final String arg = args[i];
      switch (arg) {
        case "--host" -> host = requireValue(args, ++i, arg);
        case "--port" -> port = Integer.parseInt(requireValue(args, ++i, arg));
        case "--data-dir" -> dataDir = requireValue(args, ++i, arg);
        case "--admin-token-file" -> adminTokenFile = requireValue(args, ++i, arg);
        case "--secure-cookies" -> secureCookies = true;
        case "--session-ttl-seconds" -> sessionTtl = Integer.parseInt(requireValue(args, ++i, arg));
        case "--directory-url" -> directoryUrl = requireValue(args, ++i, arg);
        case "--directory-token-file" -> directoryTokenFile = requireValue(args, ++i, arg);
        case "--idp-url" -> idpUrl = requireValue(args, ++i, arg);
        case "--idp-token-file" -> idpTokenFile = requireValue(args, ++i, arg);
        case "--kms-tcp" -> kmsTcp = requireValue(args, ++i, arg);
        case "--kms-api-token-file" -> kmsApiTokenFile = requireValue(args, ++i, arg);
        case "--kms-admin-token-file" -> kmsAdminTokenFile = requireValue(args, ++i, arg);
        case "--ca-url" -> caUrl = requireValue(args, ++i, arg);
        case "--ca-token-file" -> caTokenFile = requireValue(args, ++i, arg);
        default -> throw new IllegalArgumentException("unknown argument: " + arg);
      }
    }

    final String resolvedHost = host != null && !host.isBlank() ? host : DEFAULT_HOST;
    final int resolvedPort = port != null ? port : DEFAULT_PORT;
    if (resolvedPort < 0 || resolvedPort > 65535) {
      throw new IllegalArgumentException("port must be in 0..65535");
    }
    final String[] kms = parseHostPort(kmsTcp);

    return new ConsoleConfig(
        resolvedHost, resolvedPort,
        dataDir != null ? Paths.get(dataDir) : defaultDataDir(env),
        adminTokenFile != null ? Paths.get(adminTokenFile) : null,
        secureCookies,
        Duration.ofSeconds(positiveOr(sessionTtl, DEFAULT_SESSION_TTL_SECONDS)),
        directoryUrl != null && !directoryUrl.isBlank() ? URI.create(directoryUrl.trim()) : null,
        directoryTokenFile != null ? Paths.get(directoryTokenFile) : null,
        idpUrl != null && !idpUrl.isBlank() ? URI.create(idpUrl.trim()) : null,
        idpTokenFile != null ? Paths.get(idpTokenFile) : null,
        kms == null ? null : kms[0], kms == null ? 0 : Integer.parseInt(kms[1]),
        kmsApiTokenFile != null ? Paths.get(kmsApiTokenFile) : null,
        kmsAdminTokenFile != null ? Paths.get(kmsAdminTokenFile) : null,
        caUrl != null && !caUrl.isBlank() ? URI.create(caUrl.trim()) : null,
        caTokenFile != null ? Paths.get(caTokenFile) : null);
  }

  /** @return {host, port} parsed from a {@code HOST:PORT} value, or null when not set. */
  private static String[] parseHostPort(final String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    final int colon = value.lastIndexOf(':');
    if (colon < 1 || colon == value.length() - 1) {
      throw new IllegalArgumentException("--kms-tcp must be HOST:PORT");
    }
    final String[] parts = {value.substring(0, colon).trim(), value.substring(colon + 1).trim()};
    final int port = Integer.parseInt(parts[1]);
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("--kms-tcp port must be in 1..65535");
    }
    return parts;
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

  /** @return the mini-directory origin to wire, or null if the directory is not configured. */
  public URI directoryUrl() {
    return directoryUrl;
  }

  /** @return the file the directory admin token may be read from, or null (then the env var). */
  public Path directoryTokenFilePath() {
    return directoryTokenFilePath;
  }

  /** @return the mini-idp origin to wire, or null if mini-idp is not configured. */
  public URI idpUrl() {
    return idpUrl;
  }

  /** @return the file the idp admin token may be read from, or null (then the env var). */
  public Path idpTokenFilePath() {
    return idpTokenFilePath;
  }

  /** @return whether a mini-kms endpoint is configured (then the Keys page's KMS section is live). */
  public boolean kmsConfigured() {
    return kmsHost != null;
  }

  /** @return the mini-kms loopback host, or null if mini-kms is not configured. */
  public String kmsHost() {
    return kmsHost;
  }

  /** @return the mini-kms TCP port (meaningful only when {@link #kmsConfigured()}). */
  public int kmsPort() {
    return kmsPort;
  }

  /** @return the file the KMS data-plane API token may be read from, or null (then the env var). */
  public Path kmsApiTokenFilePath() {
    return kmsApiTokenFilePath;
  }

  /** @return the file the KMS control-plane admin token may be read from, or null (then env). */
  public Path kmsAdminTokenFilePath() {
    return kmsAdminTokenFilePath;
  }

  /** @return the mini-ca origin to wire, or null if mini-ca is not configured. */
  public URI caUrl() {
    return caUrl;
  }

  /** @return the file the ca admin token may be read from, or null (then the env var). */
  public Path caTokenFilePath() {
    return caTokenFilePath;
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

package com.codeheadsystems.minica.server;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Map;

/**
 * Resolved mini-ca configuration. Values come from CLI flags, then environment, then defaults —
 * mirroring the family's other {@code ServerConfig}s.
 *
 * <p>Notable knobs: the CA subject + root validity (used only when bootstrapping a fresh CA), the
 * default and maximum leaf TTLs (leaves are short-lived; a request may ask for less than the max),
 * and the optional mini-kms wrapping of the CA private key ({@code --kms-*}, the same shape mini-idp
 * uses) — without it the key is stored plaintext-{@code 0600}.
 *
 * <pre>
 *   --host H                  MINICA_HOST                  loopback bind host (default 127.0.0.1)
 *   --port N                  MINICA_PORT                  TCP port (default 8499)
 *   --data-dir PATH           MINICA_DATA_DIR              directory for the JSON stores
 *   --admin-token-file PATH   MINICA_ADMIN_TOKEN_FILE      file holding the admin token (alt: MINICA_ADMIN_TOKEN env)
 *   --ca-subject DN           MINICA_CA_SUBJECT            CA subject DN (default CN=mini-ca), fresh-bootstrap only
 *   --ca-validity-days N      MINICA_CA_VALIDITY_DAYS      root validity (default 3650), fresh-bootstrap only
 *   --leaf-ttl-seconds N      MINICA_LEAF_TTL_SECONDS      default leaf lifetime (default 86400 = 1d)
 *   --max-leaf-ttl-seconds N  MINICA_MAX_LEAF_TTL_SECONDS  cap on a requested leaf lifetime (default 604800 = 7d)
 *   --kms-tcp HOST:PORT       MINICA_KMS_TCP               wrap the CA key under mini-kms (optional)
 *   --kms-key-group NAME      MINICA_KMS_KEY_GROUP         the mini-kms key group
 *   --kms-api-token-file PATH MINICA_KMS_API_TOKEN_FILE    mini-kms data-plane token file (alt: MINICA_KMS_API_TOKEN env)
 * </pre>
 */
public final class ServerConfig {

  public static final String DEFAULT_HOST = "127.0.0.1";
  public static final int DEFAULT_PORT = 8499;

  private final String host;
  private final int port;
  private final Path dataDir;
  private final Path adminTokenFilePath;
  private final String caSubject;
  private final Duration caValidity;
  private final Duration defaultLeafTtl;
  private final Duration maxLeafTtl;
  private final String kmsHost;
  private final int kmsPort;
  private final String kmsKeyGroup;
  private final Path kmsApiTokenFilePath;

  ServerConfig(final String host, final int port, final Path dataDir, final Path adminTokenFilePath,
               final String caSubject, final Duration caValidity, final Duration defaultLeafTtl,
               final Duration maxLeafTtl, final String kmsHost, final int kmsPort,
               final String kmsKeyGroup, final Path kmsApiTokenFilePath) {
    this.host = host;
    this.port = port;
    this.dataDir = dataDir;
    this.adminTokenFilePath = adminTokenFilePath;
    this.caSubject = caSubject;
    this.caValidity = caValidity;
    this.defaultLeafTtl = defaultLeafTtl;
    this.maxLeafTtl = maxLeafTtl;
    this.kmsHost = kmsHost;
    this.kmsPort = kmsPort;
    this.kmsKeyGroup = kmsKeyGroup;
    this.kmsApiTokenFilePath = kmsApiTokenFilePath;
  }

  /** Resolve configuration from CLI args and the environment. */
  public static ServerConfig resolve(final String[] args, final Map<String, String> env) {
    String host = env.get("MINICA_HOST");
    Integer port = envInt(env, "MINICA_PORT");
    String dataDir = env.get("MINICA_DATA_DIR");
    String adminTokenFile = env.get("MINICA_ADMIN_TOKEN_FILE");
    String caSubject = env.get("MINICA_CA_SUBJECT");
    Integer caValidityDays = envInt(env, "MINICA_CA_VALIDITY_DAYS");
    Integer leafTtl = envInt(env, "MINICA_LEAF_TTL_SECONDS");
    Integer maxLeafTtl = envInt(env, "MINICA_MAX_LEAF_TTL_SECONDS");
    String kmsTcp = env.get("MINICA_KMS_TCP");
    String kmsKeyGroup = env.get("MINICA_KMS_KEY_GROUP");
    String kmsApiTokenFile = env.get("MINICA_KMS_API_TOKEN_FILE");

    for (int i = 0; i < args.length; i++) {
      final String arg = args[i];
      switch (arg) {
        case "--host" -> host = requireValue(args, ++i, arg);
        case "--port" -> port = Integer.parseInt(requireValue(args, ++i, arg));
        case "--data-dir" -> dataDir = requireValue(args, ++i, arg);
        case "--admin-token-file" -> adminTokenFile = requireValue(args, ++i, arg);
        case "--ca-subject" -> caSubject = requireValue(args, ++i, arg);
        case "--ca-validity-days" -> caValidityDays = Integer.parseInt(requireValue(args, ++i, arg));
        case "--leaf-ttl-seconds" -> leafTtl = Integer.parseInt(requireValue(args, ++i, arg));
        case "--max-leaf-ttl-seconds" -> maxLeafTtl = Integer.parseInt(requireValue(args, ++i, arg));
        case "--kms-tcp" -> kmsTcp = requireValue(args, ++i, arg);
        case "--kms-key-group" -> kmsKeyGroup = requireValue(args, ++i, arg);
        case "--kms-api-token-file" -> kmsApiTokenFile = requireValue(args, ++i, arg);
        default -> throw new IllegalArgumentException("unknown argument: " + arg);
      }
    }

    final String resolvedHost = host != null && !host.isBlank() ? host : DEFAULT_HOST;
    final int resolvedPort = port != null ? port : DEFAULT_PORT;
    if (resolvedPort < 0 || resolvedPort > 65535) {
      throw new IllegalArgumentException("port must be in 0..65535");
    }
    final Duration defaultLeaf = Duration.ofSeconds(positive(leafTtl, 86_400));
    final Duration maxLeaf = Duration.ofSeconds(positive(maxLeafTtl, 604_800));
    if (defaultLeaf.compareTo(maxLeaf) > 0) {
      throw new IllegalArgumentException("default leaf TTL must not exceed the max leaf TTL");
    }
    return new ServerConfig(resolvedHost, resolvedPort,
        dataDir != null ? Paths.get(dataDir) : defaultDataDir(env),
        adminTokenFile != null ? Paths.get(adminTokenFile) : null,
        caSubject != null && !caSubject.isBlank() ? caSubject : "CN=mini-ca",
        Duration.ofDays(positive(caValidityDays, 3650)), defaultLeaf, maxLeaf,
        kmsTcp == null ? null : hostOf(kmsTcp), kmsTcp == null ? 0 : portOf(kmsTcp),
        kmsKeyGroup, kmsApiTokenFile != null ? Paths.get(kmsApiTokenFile) : null);
  }

  private static int positive(final Integer value, final int fallback) {
    if (value == null) {
      return fallback;
    }
    if (value < 1) {
      throw new IllegalArgumentException("value must be at least 1");
    }
    return value;
  }

  private static Path defaultDataDir(final Map<String, String> env) {
    final String xdg = env.get("XDG_DATA_HOME");
    if (xdg != null && !xdg.isBlank()) {
      return Paths.get(xdg, "mini-ca");
    }
    final String home = env.getOrDefault("HOME", System.getProperty("user.home", "."));
    return Paths.get(home, ".mini-ca");
  }

  private static String hostOf(final String hostPort) {
    final int colon = hostPort.lastIndexOf(':');
    if (colon <= 0) {
      throw new IllegalArgumentException("--kms-tcp must be HOST:PORT");
    }
    return hostPort.substring(0, colon);
  }

  private static int portOf(final String hostPort) {
    final int colon = hostPort.lastIndexOf(':');
    if (colon <= 0) {
      throw new IllegalArgumentException("--kms-tcp must be HOST:PORT");
    }
    return Integer.parseInt(hostPort.substring(colon + 1));
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

  public String host() {
    return host;
  }

  public int port() {
    return port;
  }

  public Path dataDir() {
    return dataDir;
  }

  public Path adminTokenFilePath() {
    return adminTokenFilePath;
  }

  public String caSubject() {
    return caSubject;
  }

  public Duration caValidity() {
    return caValidity;
  }

  public Duration defaultLeafTtl() {
    return defaultLeafTtl;
  }

  public Duration maxLeafTtl() {
    return maxLeafTtl;
  }

  /** @return the leaf TTL to use for a request, clamped to the configured maximum. */
  public Duration clampLeafTtl(final Long requestedSeconds) {
    final long seconds = requestedSeconds == null || requestedSeconds < 1
        ? defaultLeafTtl.toSeconds()
        : Math.min(requestedSeconds, maxLeafTtl.toSeconds());
    return Duration.ofSeconds(seconds);
  }

  public boolean kmsEnabled() {
    return kmsHost != null && !kmsHost.isBlank() && kmsKeyGroup != null && !kmsKeyGroup.isBlank();
  }

  public String kmsHost() {
    return kmsHost;
  }

  public int kmsPort() {
    return kmsPort;
  }

  public String kmsKeyGroup() {
    return kmsKeyGroup;
  }

  public Path kmsApiTokenFilePath() {
    return kmsApiTokenFilePath;
  }
}

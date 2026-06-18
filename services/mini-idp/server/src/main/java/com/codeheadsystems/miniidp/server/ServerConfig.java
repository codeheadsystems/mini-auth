package com.codeheadsystems.miniidp.server;

import com.codeheadsystems.miniidp.secret.Argon2Settings;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Map;

/**
 * Resolved server configuration: where to listen, who we are (issuer/audience), how long tokens
 * live, the Argon2 cost for client secrets, where the JSON stores live, and where the bootstrap
 * admin token comes from. Values come from CLI flags (highest priority), then environment
 * variables, then sensible per-user defaults — mirroring mini-kms's {@code ServerConfig}.
 *
 * <p>Secrets are deliberately NOT stored here as plaintext: the admin token is resolved from its
 * source by {@link ServerMain} (env var or file) and handed straight to the authenticator; only
 * the token <em>file path</em> (config, not a secret) lives here.
 *
 * <p>Recognized flags / env vars:
 * <pre>
 *   --host H                 MINIIDP_HOST              loopback bind host (default 127.0.0.1)
 *   --port N                 MINIIDP_PORT              TCP port (default 8455)
 *   --issuer URL             MINIIDP_ISSUER            issuer URL (default http://&lt;host&gt;:&lt;port&gt;)
 *   --audience AUD           MINIIDP_AUDIENCE          token audience (default mini-kms)
 *   --token-ttl-seconds N    MINIIDP_TOKEN_TTL_SECONDS access-token lifetime (default 300)
 *   --data-dir PATH          MINIIDP_DATA_DIR          directory for the JSON stores
 *   --admin-token-file PATH  MINIIDP_ADMIN_TOKEN_FILE  file holding the admin token
 *                                                      (alt: MINIIDP_ADMIN_TOKEN env)
 *   --argon-memory-kib N     MINIIDP_ARGON_MEMORY_KIB  Argon2 memory cost for client secrets
 *   --argon-iterations N     MINIIDP_ARGON_ITERATIONS  Argon2 time cost
 *   --argon-parallelism N    MINIIDP_ARGON_PARALLELISM Argon2 lanes
 * </pre>
 */
public final class ServerConfig {

  /** Default loopback bind host. */
  public static final String DEFAULT_HOST = "127.0.0.1";

  /** Default TCP port. */
  public static final int DEFAULT_PORT = 8455;

  /** Default token audience (the mini-kms service these tokens are for). */
  public static final String DEFAULT_AUDIENCE = "mini-kms";

  /** Default access-token lifetime: 5 minutes. */
  public static final int DEFAULT_TOKEN_TTL_SECONDS = 300;

  private final String host;
  private final int port;
  private final String issuer;
  private final String audience;
  private final Duration tokenTtl;
  private final Path dataDir;
  private final Path adminTokenFilePath;
  private final Argon2Settings argonSettings;
  private final String kmsHost;
  private final int kmsPort;
  private final String kmsKeyGroup;
  private final Path kmsApiTokenFilePath;

  ServerConfig(final String host, final int port, final String issuer, final String audience,
               final Duration tokenTtl, final Path dataDir, final Path adminTokenFilePath,
               final Argon2Settings argonSettings, final String kmsHost, final int kmsPort,
               final String kmsKeyGroup, final Path kmsApiTokenFilePath) {
    this.host = host;
    this.port = port;
    this.issuer = issuer;
    this.audience = audience;
    this.tokenTtl = tokenTtl;
    this.dataDir = dataDir;
    this.adminTokenFilePath = adminTokenFilePath;
    this.argonSettings = argonSettings;
    this.kmsHost = kmsHost;
    this.kmsPort = kmsPort;
    this.kmsKeyGroup = kmsKeyGroup;
    this.kmsApiTokenFilePath = kmsApiTokenFilePath;
  }

  /**
   * Resolve configuration from CLI args and the process environment.
   *
   * @param args the raw CLI arguments.
   * @param env  the environment (injectable for testing; usually {@code System.getenv()}).
   * @return the resolved, validated configuration.
   */
  public static ServerConfig resolve(final String[] args, final Map<String, String> env) {
    String host = env.get("MINIIDP_HOST");
    Integer port = envInt(env, "MINIIDP_PORT");
    String issuer = env.get("MINIIDP_ISSUER");
    String audience = env.get("MINIIDP_AUDIENCE");
    Integer ttlSeconds = envInt(env, "MINIIDP_TOKEN_TTL_SECONDS");
    String dataDir = env.get("MINIIDP_DATA_DIR");
    String adminTokenFile = env.get("MINIIDP_ADMIN_TOKEN_FILE");
    Integer argonMemory = envInt(env, "MINIIDP_ARGON_MEMORY_KIB");
    Integer argonIterations = envInt(env, "MINIIDP_ARGON_ITERATIONS");
    Integer argonParallelism = envInt(env, "MINIIDP_ARGON_PARALLELISM");
    String kmsTcp = env.get("MINIIDP_KMS_TCP");
    String kmsKeyGroup = env.get("MINIIDP_KMS_KEY_GROUP");
    String kmsApiTokenFile = env.get("MINIIDP_KMS_API_TOKEN_FILE");

    for (int i = 0; i < args.length; i++) {
      final String arg = args[i];
      switch (arg) {
        case "--host" -> host = requireValue(args, ++i, arg);
        case "--port" -> port = Integer.parseInt(requireValue(args, ++i, arg));
        case "--issuer" -> issuer = requireValue(args, ++i, arg);
        case "--audience" -> audience = requireValue(args, ++i, arg);
        case "--token-ttl-seconds" -> ttlSeconds = Integer.parseInt(requireValue(args, ++i, arg));
        case "--data-dir" -> dataDir = requireValue(args, ++i, arg);
        case "--admin-token-file" -> adminTokenFile = requireValue(args, ++i, arg);
        case "--argon-memory-kib" -> argonMemory = Integer.parseInt(requireValue(args, ++i, arg));
        case "--argon-iterations" -> argonIterations = Integer.parseInt(requireValue(args, ++i, arg));
        case "--argon-parallelism" -> argonParallelism = Integer.parseInt(requireValue(args, ++i, arg));
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
    final String resolvedAudience = audience != null && !audience.isBlank() ? audience : DEFAULT_AUDIENCE;
    final int resolvedTtl = ttlSeconds != null ? ttlSeconds : DEFAULT_TOKEN_TTL_SECONDS;
    if (resolvedTtl < 1) {
      throw new IllegalArgumentException("token TTL must be at least 1 second");
    }
    // Default issuer is derived from the bind address; an operator behind a reverse proxy should
    // set --issuer explicitly to the externally-reachable URL.
    final String resolvedIssuer = issuer != null && !issuer.isBlank()
        ? stripTrailingSlash(issuer)
        : "http://" + resolvedHost + ":" + resolvedPort;

    final Path resolvedDataDir = dataDir != null ? Paths.get(dataDir) : defaultDataDir(env);
    final Path adminTokenFilePath = adminTokenFile != null ? Paths.get(adminTokenFile) : null;

    final Argon2Settings argon = new Argon2Settings(
        argonMemory != null ? argonMemory : Argon2Settings.DEFAULT_MEMORY_KIB,
        argonIterations != null ? argonIterations : Argon2Settings.DEFAULT_ITERATIONS,
        argonParallelism != null ? argonParallelism : Argon2Settings.DEFAULT_PARALLELISM);

    // mini-kms key wrapping (optional): --kms-tcp HOST:PORT --kms-key-group NAME enable it.
    final String kmsHost = kmsTcp == null ? null : hostOf(kmsTcp);
    final int kmsPort = kmsTcp == null ? 0 : portOf(kmsTcp);
    final Path kmsApiTokenFilePath = kmsApiTokenFile != null ? Paths.get(kmsApiTokenFile) : null;

    return new ServerConfig(resolvedHost, resolvedPort, resolvedIssuer, resolvedAudience,
        Duration.ofSeconds(resolvedTtl), resolvedDataDir, adminTokenFilePath, argon,
        kmsHost, kmsPort, kmsKeyGroup, kmsApiTokenFilePath);
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

  private static Path defaultDataDir(final Map<String, String> env) {
    final String xdg = env.get("XDG_DATA_HOME");
    if (xdg != null && !xdg.isBlank()) {
      return Paths.get(xdg, "mini-idp");
    }
    final String home = env.getOrDefault("HOME", System.getProperty("user.home", "."));
    return Paths.get(home, ".mini-idp");
  }

  private static String stripTrailingSlash(final String url) {
    return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
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

  /** @return the issuer URL ({@code iss} claim and discovery base). */
  public String issuer() {
    return issuer;
  }

  /** @return the token audience ({@code aud} claim). */
  public String audience() {
    return audience;
  }

  /** @return the access-token lifetime. */
  public Duration tokenTtl() {
    return tokenTtl;
  }

  /**
   * @return how long a retired signing key stays published in the JWKS. Set to twice the token TTL
   *     so any token signed just before a rotation still finds its {@code kid} until it expires.
   */
  public Duration retiredKeyRetention() {
    return tokenTtl.multipliedBy(2);
  }

  /** @return the directory holding the JSON stores. */
  public Path dataDir() {
    return dataDir;
  }

  /** @return the file to read the admin token from, or null (env is then required). */
  public Path adminTokenFilePath() {
    return adminTokenFilePath;
  }

  /** @return the Argon2 parameters used to hash client secrets. */
  public Argon2Settings argonSettings() {
    return argonSettings;
  }

  /** @return the token endpoint URL. */
  public String tokenEndpoint() {
    return issuer + "/oauth/token";
  }

  /** @return the JWKS URL. */
  public String jwksUri() {
    return issuer + "/.well-known/jwks.json";
  }

  /** @return whether to wrap signing keys under mini-kms (both {@code --kms-tcp} and a key group set). */
  public boolean kmsEnabled() {
    return kmsHost != null && !kmsHost.isBlank() && kmsKeyGroup != null && !kmsKeyGroup.isBlank();
  }

  /** @return the mini-kms host (when {@link #kmsEnabled()}). */
  public String kmsHost() {
    return kmsHost;
  }

  /** @return the mini-kms TCP port (when {@link #kmsEnabled()}). */
  public int kmsPort() {
    return kmsPort;
  }

  /** @return the mini-kms key group the signing keys are wrapped under (when {@link #kmsEnabled()}). */
  public String kmsKeyGroup() {
    return kmsKeyGroup;
  }

  /** @return the file holding the mini-kms data-plane API token, or null (env is then required). */
  public Path kmsApiTokenFilePath() {
    return kmsApiTokenFilePath;
  }
}

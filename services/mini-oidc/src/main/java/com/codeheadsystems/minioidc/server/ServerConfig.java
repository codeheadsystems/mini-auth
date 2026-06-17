package com.codeheadsystems.minioidc.server;

import com.codeheadsystems.minioidc.secret.Argon2Settings;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Resolved server configuration for the OpenID Provider. Values come from CLI flags (highest
 * priority), then environment variables, then per-user defaults — mirroring the family's other
 * {@code ServerConfig}s.
 *
 * <p>The OIDC/SSO knobs worth calling out: the WebAuthn <b>relying-party</b> identity ({@code rpId}
 * + {@code origins}) is what pk-auth validates ceremonies against and is independent of the bind
 * port; the <b>session lifetime</b> is deliberately separate from the (short) token TTLs; and
 * <b>secure cookies</b> default off so the loopback HTTP dev flow works, but MUST be enabled behind
 * the TLS reverse proxy that any LAN exposure requires.
 *
 * <pre>
 *   --host H                  MINIOIDC_HOST              loopback bind host (default 127.0.0.1)
 *   --port N                  MINIOIDC_PORT              TCP port (default 8477)
 *   --issuer URL              MINIOIDC_ISSUER            issuer URL (default http://&lt;host&gt;:&lt;port&gt;)
 *   --rp-id ID                MINIOIDC_RP_ID             WebAuthn relying-party id (default localhost)
 *   --rp-name NAME            MINIOIDC_RP_NAME           relying-party display name
 *   --rp-origin O[,O...]      MINIOIDC_RP_ORIGINS        acceptable WebAuthn origins (default http://localhost:&lt;port&gt;)
 *   --data-dir PATH           MINIOIDC_DATA_DIR          directory for the JSON stores
 *   --admin-token-file PATH   MINIOIDC_ADMIN_TOKEN_FILE  file holding the admin token (alt: MINIOIDC_ADMIN_TOKEN env)
 *   --directory-url URL       MINIOIDC_DIRECTORY_URL     mini-directory base URL (else in-memory directory)
 *   --directory-token-file P  MINIOIDC_DIRECTORY_TOKEN_FILE  mini-directory admin token file (alt: MINIOIDC_DIRECTORY_TOKEN)
 *   --secure-cookies          MINIOIDC_SECURE_COOKIES    set the Secure flag on cookies (use behind TLS)
 *   --session-ttl-seconds N   MINIOIDC_SESSION_TTL_SECONDS   SSO session lifetime (default 43200 = 12h)
 *   --access-ttl-seconds N    MINIOIDC_ACCESS_TTL_SECONDS    access-token TTL (default 300)
 *   --id-ttl-seconds N        MINIOIDC_ID_TTL_SECONDS        ID-token TTL (default 300)
 *   --refresh-ttl-seconds N   MINIOIDC_REFRESH_TTL_SECONDS   refresh-token TTL (default 2592000 = 30d)
 *   --code-ttl-seconds N      MINIOIDC_CODE_TTL_SECONDS      authorization-code TTL (default 60)
 *   --argon-memory-kib N / --argon-iterations N / --argon-parallelism N   client-secret Argon2 cost
 * </pre>
 */
public final class ServerConfig {

  /** Default loopback bind host. */
  public static final String DEFAULT_HOST = "127.0.0.1";
  /** Default TCP port (one above mini-directory's 8466). */
  public static final int DEFAULT_PORT = 8477;

  private final String host;
  private final int port;
  private final String issuer;
  private final String rpId;
  private final String rpName;
  private final Set<String> rpOrigins;
  private final Path dataDir;
  private final Path adminTokenFilePath;
  private final String directoryUrl;
  private final Path directoryTokenFilePath;
  private final boolean secureCookies;
  private final Duration sessionTtl;
  private final Duration accessTtl;
  private final Duration idTtl;
  private final Duration refreshTtl;
  private final Duration codeTtl;
  private final Argon2Settings argonSettings;

  ServerConfig(final String host, final int port, final String issuer, final String rpId,
               final String rpName, final Set<String> rpOrigins, final Path dataDir,
               final Path adminTokenFilePath, final String directoryUrl,
               final Path directoryTokenFilePath, final boolean secureCookies, final Duration sessionTtl,
               final Duration accessTtl, final Duration idTtl, final Duration refreshTtl,
               final Duration codeTtl, final Argon2Settings argonSettings) {
    this.host = host;
    this.port = port;
    this.issuer = issuer;
    this.rpId = rpId;
    this.rpName = rpName;
    this.rpOrigins = Set.copyOf(rpOrigins);
    this.dataDir = dataDir;
    this.adminTokenFilePath = adminTokenFilePath;
    this.directoryUrl = directoryUrl;
    this.directoryTokenFilePath = directoryTokenFilePath;
    this.secureCookies = secureCookies;
    this.sessionTtl = sessionTtl;
    this.accessTtl = accessTtl;
    this.idTtl = idTtl;
    this.refreshTtl = refreshTtl;
    this.codeTtl = codeTtl;
    this.argonSettings = argonSettings;
  }

  /** Resolve configuration from CLI args and the environment. */
  public static ServerConfig resolve(final String[] args, final Map<String, String> env) {
    String host = env.get("MINIOIDC_HOST");
    Integer port = envInt(env, "MINIOIDC_PORT");
    String issuer = env.get("MINIOIDC_ISSUER");
    String rpId = env.get("MINIOIDC_RP_ID");
    String rpName = env.get("MINIOIDC_RP_NAME");
    String rpOrigins = env.get("MINIOIDC_RP_ORIGINS");
    String dataDir = env.get("MINIOIDC_DATA_DIR");
    String adminTokenFile = env.get("MINIOIDC_ADMIN_TOKEN_FILE");
    String directoryUrl = env.get("MINIOIDC_DIRECTORY_URL");
    String directoryTokenFile = env.get("MINIOIDC_DIRECTORY_TOKEN_FILE");
    boolean secureCookies = "true".equalsIgnoreCase(env.get("MINIOIDC_SECURE_COOKIES"));
    Integer sessionTtl = envInt(env, "MINIOIDC_SESSION_TTL_SECONDS");
    Integer accessTtl = envInt(env, "MINIOIDC_ACCESS_TTL_SECONDS");
    Integer idTtl = envInt(env, "MINIOIDC_ID_TTL_SECONDS");
    Integer refreshTtl = envInt(env, "MINIOIDC_REFRESH_TTL_SECONDS");
    Integer codeTtl = envInt(env, "MINIOIDC_CODE_TTL_SECONDS");
    Integer argonMemory = envInt(env, "MINIOIDC_ARGON_MEMORY_KIB");
    Integer argonIterations = envInt(env, "MINIOIDC_ARGON_ITERATIONS");
    Integer argonParallelism = envInt(env, "MINIOIDC_ARGON_PARALLELISM");

    for (int i = 0; i < args.length; i++) {
      final String arg = args[i];
      switch (arg) {
        case "--host" -> host = requireValue(args, ++i, arg);
        case "--port" -> port = Integer.parseInt(requireValue(args, ++i, arg));
        case "--issuer" -> issuer = requireValue(args, ++i, arg);
        case "--rp-id" -> rpId = requireValue(args, ++i, arg);
        case "--rp-name" -> rpName = requireValue(args, ++i, arg);
        case "--rp-origin" -> rpOrigins = requireValue(args, ++i, arg);
        case "--data-dir" -> dataDir = requireValue(args, ++i, arg);
        case "--admin-token-file" -> adminTokenFile = requireValue(args, ++i, arg);
        case "--directory-url" -> directoryUrl = requireValue(args, ++i, arg);
        case "--directory-token-file" -> directoryTokenFile = requireValue(args, ++i, arg);
        case "--secure-cookies" -> secureCookies = true;
        case "--session-ttl-seconds" -> sessionTtl = Integer.parseInt(requireValue(args, ++i, arg));
        case "--access-ttl-seconds" -> accessTtl = Integer.parseInt(requireValue(args, ++i, arg));
        case "--id-ttl-seconds" -> idTtl = Integer.parseInt(requireValue(args, ++i, arg));
        case "--refresh-ttl-seconds" -> refreshTtl = Integer.parseInt(requireValue(args, ++i, arg));
        case "--code-ttl-seconds" -> codeTtl = Integer.parseInt(requireValue(args, ++i, arg));
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
    final String resolvedIssuer = issuer != null && !issuer.isBlank()
        ? stripTrailingSlash(issuer) : "http://" + resolvedHost + ":" + resolvedPort;
    final String resolvedRpId = rpId != null && !rpId.isBlank() ? rpId : "localhost";
    final String resolvedRpName = rpName != null && !rpName.isBlank() ? rpName : "mini-oidc";
    final Set<String> resolvedOrigins = new LinkedHashSet<>();
    if (rpOrigins != null && !rpOrigins.isBlank()) {
      for (final String origin : rpOrigins.split(",")) {
        if (!origin.isBlank()) {
          resolvedOrigins.add(origin.trim());
        }
      }
    } else {
      resolvedOrigins.add("http://localhost:" + resolvedPort);
    }

    return new ServerConfig(resolvedHost, resolvedPort, resolvedIssuer, resolvedRpId, resolvedRpName,
        resolvedOrigins,
        dataDir != null ? Paths.get(dataDir) : defaultDataDir(env),
        adminTokenFile != null ? Paths.get(adminTokenFile) : null,
        directoryUrl, directoryTokenFile != null ? Paths.get(directoryTokenFile) : null,
        secureCookies,
        Duration.ofSeconds(positiveOr(sessionTtl, 43_200)),
        Duration.ofSeconds(positiveOr(accessTtl, 300)),
        Duration.ofSeconds(positiveOr(idTtl, 300)),
        Duration.ofSeconds(positiveOr(refreshTtl, 2_592_000)),
        Duration.ofSeconds(positiveOr(codeTtl, 60)),
        new Argon2Settings(
            argonMemory != null ? argonMemory : Argon2Settings.DEFAULT_MEMORY_KIB,
            argonIterations != null ? argonIterations : Argon2Settings.DEFAULT_ITERATIONS,
            argonParallelism != null ? argonParallelism : Argon2Settings.DEFAULT_PARALLELISM));
  }

  private static int positiveOr(final Integer value, final int fallback) {
    if (value == null) {
      return fallback;
    }
    if (value < 1) {
      throw new IllegalArgumentException("TTL must be at least 1 second");
    }
    return value;
  }

  private static Path defaultDataDir(final Map<String, String> env) {
    final String xdg = env.get("XDG_DATA_HOME");
    if (xdg != null && !xdg.isBlank()) {
      return Paths.get(xdg, "mini-oidc");
    }
    final String home = env.getOrDefault("HOME", System.getProperty("user.home", "."));
    return Paths.get(home, ".mini-oidc");
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

  public String host() {
    return host;
  }

  public int port() {
    return port;
  }

  public String issuer() {
    return issuer;
  }

  /** @return the access token / userinfo audience (this OP's resource identifier). */
  public String accessAudience() {
    return issuer + "/userinfo";
  }

  public String rpId() {
    return rpId;
  }

  public String rpName() {
    return rpName;
  }

  public Set<String> rpOrigins() {
    return rpOrigins;
  }

  public Path dataDir() {
    return dataDir;
  }

  public Path adminTokenFilePath() {
    return adminTokenFilePath;
  }

  /** @return the mini-directory base URL, or null to use the in-memory directory. */
  public String directoryUrl() {
    return directoryUrl;
  }

  public Path directoryTokenFilePath() {
    return directoryTokenFilePath;
  }

  /** @return whether to set the {@code Secure} attribute on cookies (enable behind TLS). */
  public boolean secureCookies() {
    return secureCookies;
  }

  public Duration sessionTtl() {
    return sessionTtl;
  }

  public Duration accessTtl() {
    return accessTtl;
  }

  public Duration idTtl() {
    return idTtl;
  }

  public Duration refreshTtl() {
    return refreshTtl;
  }

  public Duration codeTtl() {
    return codeTtl;
  }

  public Argon2Settings argonSettings() {
    return argonSettings;
  }
}

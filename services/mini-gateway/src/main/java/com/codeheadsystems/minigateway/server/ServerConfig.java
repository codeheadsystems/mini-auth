package com.codeheadsystems.minigateway.server;

import com.codeheadsystems.minitoken.session.SessionService;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/**
 * Resolved gateway configuration. Values come from CLI flags, then environment, then defaults —
 * mirroring the family's other {@code ServerConfig}s.
 *
 * <p>The load-bearing settings: {@code sessionsFile} points at the SAME {@code sessions.json}
 * mini-oidc writes (so the two share one session store); {@code loginUrl} is where an unauthenticated
 * browser is sent (mini-oidc's authorization endpoint), with the original URL appended as
 * {@code returnParam}; and the optional {@code jwksUrl}/{@code issuer}/{@code audience} enable bearer
 * (API-client) verification against mini-oidc's published keys.
 *
 * <pre>
 *   --host H                MINIGW_HOST           loopback bind host (default 127.0.0.1)
 *   --port N                MINIGW_PORT           TCP port (default 8488)
 *   --sessions-file PATH    MINIGW_SESSIONS_FILE  shared SSO session store (default ~/.mini-oidc/sessions.json)
 *   --cookie-name NAME      MINIGW_COOKIE_NAME    SSO session cookie name (default mioidc_session)
 *   --routes-file PATH      MINIGW_ROUTES_FILE    per-route policy (JSON); default: gate everything behind login
 *   --login-url URL         MINIGW_LOGIN_URL      where to send unauthenticated browsers (mini-oidc /authorize)
 *   --return-param NAME     MINIGW_RETURN_PARAM   query param carrying the original URL (default rd)
 *   --jwks-url URL          MINIGW_JWKS_URL       OP JWKS for bearer verification (else bearer disabled)
 *   --issuer URL            MINIGW_ISSUER         expected bearer token iss
 *   --audience AUD          MINIGW_AUDIENCE       expected bearer token aud
 * </pre>
 */
public final class ServerConfig {

  public static final String DEFAULT_HOST = "127.0.0.1";
  public static final int DEFAULT_PORT = 8488;

  private final String host;
  private final int port;
  private final Path sessionsFile;
  private final String cookieName;
  private final Path routesFile;
  private final String loginUrl;
  private final String returnParam;
  private final String jwksUrl;
  private final String issuer;
  private final String audience;

  ServerConfig(final String host, final int port, final Path sessionsFile, final String cookieName,
               final Path routesFile, final String loginUrl, final String returnParam,
               final String jwksUrl, final String issuer, final String audience) {
    this.host = host;
    this.port = port;
    this.sessionsFile = sessionsFile;
    this.cookieName = cookieName;
    this.routesFile = routesFile;
    this.loginUrl = loginUrl;
    this.returnParam = returnParam;
    this.jwksUrl = jwksUrl;
    this.issuer = issuer;
    this.audience = audience;
  }

  /** Resolve configuration from CLI args and the environment. */
  public static ServerConfig resolve(final String[] args, final Map<String, String> env) {
    String host = env.get("MINIGW_HOST");
    Integer port = envInt(env, "MINIGW_PORT");
    String sessionsFile = env.get("MINIGW_SESSIONS_FILE");
    String cookieName = env.get("MINIGW_COOKIE_NAME");
    String routesFile = env.get("MINIGW_ROUTES_FILE");
    String loginUrl = env.get("MINIGW_LOGIN_URL");
    String returnParam = env.get("MINIGW_RETURN_PARAM");
    String jwksUrl = env.get("MINIGW_JWKS_URL");
    String issuer = env.get("MINIGW_ISSUER");
    String audience = env.get("MINIGW_AUDIENCE");

    for (int i = 0; i < args.length; i++) {
      final String arg = args[i];
      switch (arg) {
        case "--host" -> host = requireValue(args, ++i, arg);
        case "--port" -> port = Integer.parseInt(requireValue(args, ++i, arg));
        case "--sessions-file" -> sessionsFile = requireValue(args, ++i, arg);
        case "--cookie-name" -> cookieName = requireValue(args, ++i, arg);
        case "--routes-file" -> routesFile = requireValue(args, ++i, arg);
        case "--login-url" -> loginUrl = requireValue(args, ++i, arg);
        case "--return-param" -> returnParam = requireValue(args, ++i, arg);
        case "--jwks-url" -> jwksUrl = requireValue(args, ++i, arg);
        case "--issuer" -> issuer = requireValue(args, ++i, arg);
        case "--audience" -> audience = requireValue(args, ++i, arg);
        default -> throw new IllegalArgumentException("unknown argument: " + arg);
      }
    }

    final String resolvedHost = host != null && !host.isBlank() ? host : DEFAULT_HOST;
    final int resolvedPort = port != null ? port : DEFAULT_PORT;
    if (resolvedPort < 0 || resolvedPort > 65535) {
      throw new IllegalArgumentException("port must be in 0..65535");
    }
    return new ServerConfig(resolvedHost, resolvedPort,
        Paths.get(sessionsFile != null ? sessionsFile : defaultSessionsFile(env)),
        cookieName != null && !cookieName.isBlank() ? cookieName : SessionService.DEFAULT_COOKIE_NAME,
        routesFile != null ? Paths.get(routesFile) : null,
        loginUrl, returnParam != null && !returnParam.isBlank() ? returnParam : "rd",
        jwksUrl, issuer, audience);
  }

  private static String defaultSessionsFile(final Map<String, String> env) {
    final String home = env.getOrDefault("HOME", System.getProperty("user.home", "."));
    return Paths.get(home, ".mini-oidc", "sessions.json").toString();
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

  public Path sessionsFile() {
    return sessionsFile;
  }

  public String cookieName() {
    return cookieName;
  }

  /** @return the per-route policy file, or null to gate everything behind login. */
  public Path routesFile() {
    return routesFile;
  }

  /** @return where to send unauthenticated browsers, or null (then they get 401 too). */
  public String loginUrl() {
    return loginUrl;
  }

  public String returnParam() {
    return returnParam;
  }

  /** @return the OP JWKS URL for bearer verification, or null to disable bearer auth. */
  public String jwksUrl() {
    return jwksUrl;
  }

  public String issuer() {
    return issuer;
  }

  public String audience() {
    return audience;
  }

  /** @return whether bearer (API-client) verification is configured. */
  public boolean bearerEnabled() {
    return jwksUrl != null && !jwksUrl.isBlank();
  }
}

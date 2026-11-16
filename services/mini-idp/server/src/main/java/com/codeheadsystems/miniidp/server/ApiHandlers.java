package com.codeheadsystems.miniidp.server;

import com.codeheadsystems.miniidp.directory.ServiceAccountDirectory;
import com.codeheadsystems.miniidp.directory.ServiceAccountDirectory.ResolvedClient;
import com.codeheadsystems.miniidp.server.dto.Dtos.RevocationRequest;
import com.codeheadsystems.miniidp.server.http.ApiException;
import com.codeheadsystems.miniidp.server.http.HttpResponse;
import com.codeheadsystems.miniidp.server.http.Json;
import com.codeheadsystems.miniidp.server.http.RequestContext;
import com.codeheadsystems.miniidp.server.http.Router;
import com.codeheadsystems.minitoken.crypto.SigningAlgorithm;
import com.codeheadsystems.minitoken.jwks.Jwk;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.service.AuditService;
import com.codeheadsystems.minitoken.service.RevocationService;
import com.codeheadsystems.minitoken.service.SigningKeyService;
import com.codeheadsystems.minitoken.service.TokenIssuer;
import com.codeheadsystems.minitoken.service.TokenIssuer.IssuedToken;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Builds the {@link Router} wiring every documented endpoint to a handler.
 *
 * <p>Public endpoints (token, JWKS, discovery, health, spec, docs) are open; every {@code /admin}
 * endpoint first calls {@link AdminAuthenticator#requireAdmin}. Handlers stay thin: validate input,
 * call a collaborator, map the result to an {@link HttpResponse}.
 *
 * <p>mini-idp no longer owns a client registry — client identity, credentials, and grants come from
 * <b>mini-directory</b> via the {@link ServiceAccountDirectory} seam (so service accounts live in one
 * place). The token endpoint's contract is unchanged: client_credentials only, the same claim set,
 * and a single generic {@code invalid_client} for any authentication failure (no oracle). The
 * remaining admin endpoints are mini-idp's own concern — key rotation, revocation, and the audit log.
 *
 * <p><b>Per-token audience (additive).</b> A client may name the audience it wants with RFC 8707's
 * {@code resource} or the {@code audience} form parameter. With neither, the token carries the
 * configured default audience exactly as before. A named audience must be the default or one of the
 * client's allowlisted audiences ({@link ResolvedClient#audiences()}); anything else is a 400
 * {@code invalid_target} — returned only <em>after</em> the client authenticated, so it reveals
 * nothing to an unauthenticated caller. The audience also picks the signing algorithm
 * ({@link ServerConfig#signingAlgorithmFor}): EdDSA unless the operator mapped it to ES256.
 */
public final class ApiHandlers {

  private final ServerConfig config;
  private final ServiceAccountDirectory directory;
  private final SigningKeyService signingKeys;
  private final Map<SigningAlgorithm, SigningKeyService> keySets;
  private final RevocationService revocations;
  private final AuditService audit;
  private final TokenIssuer tokenIssuer;
  private final AdminAuthenticator adminAuth;
  private final OpenApiDocument openApi;
  private final Clock clock;

  /** Wire the handlers with their collaborators (Ed25519 signing only). */
  public ApiHandlers(final ServerConfig config, final ServiceAccountDirectory directory,
                     final SigningKeyService signingKeys, final RevocationService revocations,
                     final AuditService audit, final TokenIssuer tokenIssuer,
                     final AdminAuthenticator adminAuth, final OpenApiDocument openApi,
                     final Clock clock) {
    this(config, directory, Map.of(SigningAlgorithm.EDDSA, signingKeys), revocations, audit,
        tokenIssuer, adminAuth, openApi, clock);
  }

  /**
   * Wire the handlers with one signing-key set per algorithm. The EdDSA set is required (it signs
   * the default audience); others are present only when an audience is mapped to them.
   */
  public ApiHandlers(final ServerConfig config, final ServiceAccountDirectory directory,
                     final Map<SigningAlgorithm, SigningKeyService> keySets,
                     final RevocationService revocations, final AuditService audit,
                     final TokenIssuer tokenIssuer, final AdminAuthenticator adminAuth,
                     final OpenApiDocument openApi, final Clock clock) {
    final SigningKeyService eddsa = keySets.get(SigningAlgorithm.EDDSA);
    if (eddsa == null) {
      throw new IllegalArgumentException("an EdDSA signing-key set is required");
    }
    for (final SigningAlgorithm needed : config.audienceAlgorithms().values()) {
      if (!keySets.containsKey(needed)) {
        throw new IllegalArgumentException("no signing-key set for " + needed.jwsName());
      }
    }
    this.config = config;
    this.directory = directory;
    this.signingKeys = eddsa;
    this.keySets = new EnumMap<>(keySets);
    this.revocations = revocations;
    this.audit = audit;
    this.tokenIssuer = tokenIssuer;
    this.adminAuth = adminAuth;
    this.openApi = openApi;
    this.clock = clock;
  }

  /** @return a router with every route registered. */
  public Router router() {
    final Router router = new Router();
    // Public endpoints.
    router.route("POST", "/oauth/token", this::token);
    router.route("GET", "/.well-known/jwks.json", this::jwks);
    router.route("GET", "/.well-known/idp-configuration", this::discovery);
    // The same document under the standard names: OpenID Connect Discovery 1.0 (what config-server
    // and most JOSE stacks fetch) and RFC 8414 OAuth 2.0 Authorization Server Metadata.
    router.route("GET", "/.well-known/openid-configuration", this::discovery);
    router.route("GET", "/.well-known/oauth-authorization-server", this::discovery);
    router.route("GET", "/health", this::health);
    router.route("GET", "/openapi.yaml", this::openApiYaml);
    router.route("GET", "/openapi.json", this::openApiJson);
    router.route("GET", "/docs", this::docs);
    router.route("GET", "/docs/swagger-ui.css", ctx -> asset("swagger-ui.css", "text/css"));
    router.route("GET", "/docs/swagger-ui-bundle.js",
        ctx -> asset("swagger-ui-bundle.js", "application/javascript"));
    // Admin endpoints (mini-idp's own; each guarded inside the handler). Client management now lives
    // in mini-directory.
    router.route("POST", "/admin/keys/rotate", this::rotateKeys);
    router.route("POST", "/admin/revocations", this::revoke);
    router.route("GET", "/admin/revocations", this::listRevocations);
    router.route("GET", "/admin/audit", this::auditLog);
    return router;
  }

  // ---- Public endpoints ----------------------------------------------------------------------

  private HttpResponse token(final RequestContext ctx) {
    final Map<String, String> form = ctx.formParams();
    if (!"client_credentials".equals(form.get("grant_type"))) {
      throw new ApiException(400, "unsupported_grant_type",
          "only the client_credentials grant is supported");
    }

    // Credentials may arrive as form fields (client_secret_post) or HTTP Basic (client_secret_basic).
    final String[] basic = basicCredentials(ctx.header("Authorization"));
    final String clientId = form.getOrDefault("client_id", basic == null ? null : basic[0]);
    final String secret = form.getOrDefault("client_secret", basic == null ? null : basic[1]);
    if (clientId == null || secret == null) {
      throw ApiException.invalidClient();
    }

    final char[] secretChars = secret.toCharArray();
    final Optional<ResolvedClient> resolved;
    try {
      resolved = directory.authenticate(clientId, secretChars);
    } finally {
      Arrays.fill(secretChars, '\0');
    }
    // Single generic failure regardless of which check failed (no credential oracle).
    final ResolvedClient client = resolved.orElseThrow(ApiException::invalidClient);

    final String tokenAudience = requestedAudience(form, client);
    final SigningAlgorithm algorithm = config.signingAlgorithmFor(tokenAudience);
    final IssuedToken issued = tokenIssuer.issue(
        client.subject(), client.authorization(), tokenAudience, keySets.get(algorithm));
    audit.record("token.issued", client.subject(),
        "jti=" + issued.jti() + " aud=" + tokenAudience + " alg=" + algorithm.jwsName());

    final Map<String, Object> body = new LinkedHashMap<>();
    body.put("access_token", issued.accessToken());
    body.put("token_type", issued.tokenType());
    body.put("expires_in", issued.expiresIn());
    body.put("scope", issued.scope());
    return HttpResponse.json(200, body);
  }

  /**
   * The audience for this token: the default when the client names none, else the one it names via
   * {@code resource} (RFC 8707) or {@code audience}, if the client may have it.
   */
  private String requestedAudience(final Map<String, String> form, final ResolvedClient client) {
    final String resource = blankToNull(form.get("resource"));
    final String audienceParam = blankToNull(form.get("audience"));
    if (resource != null && audienceParam != null && !resource.equals(audienceParam)) {
      throw new ApiException(400, "invalid_target", "resource and audience name different targets");
    }
    final String requested = resource != null ? resource : audienceParam;
    if (requested == null || requested.equals(tokenIssuer.defaultAudience())) {
      return tokenIssuer.defaultAudience();
    }
    if (!client.audiences().contains(requested)) {
      throw new ApiException(400, "invalid_target", "the requested audience is not allowed for this client");
    }
    return requested;
  }

  private static String blankToNull(final String value) {
    return value == null || value.isBlank() ? null : value;
  }

  /** Every key set's published keys in one JWKS (EdDSA first, as before). */
  private HttpResponse jwks(final RequestContext ctx) {
    final List<Jwk> keys = new ArrayList<>();
    for (final SigningKeyService keySet : keySets.values()) {
      keys.addAll(keySet.jwkSet().keys());
    }
    return HttpResponse.json(200, new JwkSet(keys));
  }

  /** The JOSE names of the algorithms this issuer signs with ({@code ["EdDSA"]} or {@code ["EdDSA","ES256"]}). */
  private List<String> signingAlgorithms() {
    return keySets.keySet().stream().map(SigningAlgorithm::jwsName).toList();
  }

  private HttpResponse discovery(final RequestContext ctx) {
    final Map<String, Object> doc = new LinkedHashMap<>();
    doc.put("issuer", config.issuer());
    doc.put("token_endpoint", config.tokenEndpoint());
    doc.put("jwks_uri", config.jwksUri());
    doc.put("grant_types_supported", List.of("client_credentials"));
    doc.put("token_endpoint_auth_methods_supported",
        List.of("client_secret_post", "client_secret_basic"));
    doc.put("token_endpoint_auth_signing_alg_values_supported", signingAlgorithms());
    doc.put("id_token_signing_alg_values_supported", signingAlgorithms());
    return HttpResponse.json(200, doc);
  }

  private HttpResponse health(final RequestContext ctx) {
    return HttpResponse.json(200, Map.of("status", "ok"));
  }

  private HttpResponse openApiYaml(final RequestContext ctx) {
    return HttpResponse.raw(200, "application/yaml", openApi.yaml());
  }

  private HttpResponse openApiJson(final RequestContext ctx) {
    return HttpResponse.raw(200, "application/json", openApi.json());
  }

  private HttpResponse docs(final RequestContext ctx) {
    return HttpResponse.text(200, "text/html; charset=utf-8", SwaggerUiPage.HTML);
  }

  private HttpResponse asset(final String file, final String contentType) {
    return HttpResponse.raw(200, contentType,
        com.codeheadsystems.miniidp.server.http.StaticResource.bytes("/swagger-ui/" + file));
  }

  // ---- Admin endpoints (mini-idp's own) ------------------------------------------------------

  private HttpResponse rotateKeys(final RequestContext ctx) {
    requireAdmin(ctx);
    // Rotate every key set together (same rules for each). `activeKid` stays the EdDSA kid, as
    // before; `activeKids` adds one entry per algorithm.
    final Map<String, String> activeKids = new LinkedHashMap<>();
    for (final Map.Entry<SigningAlgorithm, SigningKeyService> keySet : keySets.entrySet()) {
      activeKids.put(keySet.getKey().jwsName(), keySet.getValue().rotate());
    }
    final String newKid = activeKids.get(SigningAlgorithm.EDDSA.jwsName());
    audit.record("key.rotated", null, "activeKid=" + newKid
        + (activeKids.size() > 1 ? " activeKids=" + activeKids : ""));
    final Map<String, Object> body = new LinkedHashMap<>();
    body.put("activeKid", newKid);
    body.put("activeKids", activeKids);
    return HttpResponse.json(200, body);
  }

  private HttpResponse revoke(final RequestContext ctx) {
    requireAdmin(ctx);
    final RevocationRequest request = Json.parse(ctx.body(), RevocationRequest.class);
    if (request.jti() == null || request.jti().isBlank()) {
      throw ApiException.badRequest("jti is required");
    }
    // Default the prune horizon to one full token lifetime from now if the operator did not supply
    // the revoked token's exp.
    final long expiresAt = request.expiresAt() != null
        ? request.expiresAt()
        : clock.instant().getEpochSecond() + config.tokenTtl().toSeconds();
    final var revocation = revocations.revoke(request.jti(), expiresAt, request.reason());
    audit.record("token.revoked", null, "jti=" + revocation.jti());
    return HttpResponse.json(201, revocation);
  }

  private HttpResponse listRevocations(final RequestContext ctx) {
    requireAdmin(ctx);
    return HttpResponse.json(200, revocations.activeDenylist());
  }

  private HttpResponse auditLog(final RequestContext ctx) {
    requireAdmin(ctx);
    return HttpResponse.json(200, audit.list());
  }

  // ---- Helpers -------------------------------------------------------------------------------

  private void requireAdmin(final RequestContext ctx) {
    adminAuth.requireAdmin(ctx.header("Authorization"));
  }

  /** Decode an HTTP Basic {@code Authorization} header into {clientId, secret}, or null. */
  private static String[] basicCredentials(final String authorizationHeader) {
    final String prefix = "Basic ";
    if (authorizationHeader == null
        || authorizationHeader.length() <= prefix.length()
        || !authorizationHeader.regionMatches(true, 0, prefix, 0, prefix.length())) {
      return null;
    }
    try {
      final byte[] decoded = Base64.getDecoder()
          .decode(authorizationHeader.substring(prefix.length()).trim());
      final String creds = new String(decoded, StandardCharsets.UTF_8);
      final int colon = creds.indexOf(':');
      if (colon < 0) {
        return null;
      }
      return new String[] {creds.substring(0, colon), creds.substring(colon + 1)};
    } catch (final IllegalArgumentException e) {
      return null;
    }
  }
}

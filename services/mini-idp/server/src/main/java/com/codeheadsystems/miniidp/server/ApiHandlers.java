package com.codeheadsystems.miniidp.server;

import com.codeheadsystems.miniidp.directory.ServiceAccountDirectory;
import com.codeheadsystems.miniidp.directory.ServiceAccountDirectory.ResolvedClient;
import com.codeheadsystems.miniidp.server.dto.Dtos.RevocationRequest;
import com.codeheadsystems.miniidp.server.http.ApiException;
import com.codeheadsystems.miniidp.server.http.HttpResponse;
import com.codeheadsystems.miniidp.server.http.Json;
import com.codeheadsystems.miniidp.server.http.RequestContext;
import com.codeheadsystems.miniidp.server.http.Router;
import com.codeheadsystems.minitoken.service.AuditService;
import com.codeheadsystems.minitoken.service.RevocationService;
import com.codeheadsystems.minitoken.service.SigningKeyService;
import com.codeheadsystems.minitoken.service.TokenIssuer;
import com.codeheadsystems.minitoken.service.TokenIssuer.IssuedToken;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;
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
 */
public final class ApiHandlers {

  private final ServerConfig config;
  private final ServiceAccountDirectory directory;
  private final SigningKeyService signingKeys;
  private final RevocationService revocations;
  private final AuditService audit;
  private final TokenIssuer tokenIssuer;
  private final AdminAuthenticator adminAuth;
  private final OpenApiDocument openApi;
  private final Clock clock;

  /** Wire the handlers with their collaborators. */
  public ApiHandlers(final ServerConfig config, final ServiceAccountDirectory directory,
                     final SigningKeyService signingKeys, final RevocationService revocations,
                     final AuditService audit, final TokenIssuer tokenIssuer,
                     final AdminAuthenticator adminAuth, final OpenApiDocument openApi,
                     final Clock clock) {
    this.config = config;
    this.directory = directory;
    this.signingKeys = signingKeys;
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

    final IssuedToken issued = tokenIssuer.issue(client.subject(), client.authorization());
    audit.record("token.issued", client.subject(), "jti=" + issued.jti());

    final Map<String, Object> body = new LinkedHashMap<>();
    body.put("access_token", issued.accessToken());
    body.put("token_type", issued.tokenType());
    body.put("expires_in", issued.expiresIn());
    body.put("scope", issued.scope());
    return HttpResponse.json(200, body);
  }

  private HttpResponse jwks(final RequestContext ctx) {
    return HttpResponse.json(200, signingKeys.jwkSet());
  }

  private HttpResponse discovery(final RequestContext ctx) {
    final Map<String, Object> doc = new LinkedHashMap<>();
    doc.put("issuer", config.issuer());
    doc.put("token_endpoint", config.tokenEndpoint());
    doc.put("jwks_uri", config.jwksUri());
    doc.put("grant_types_supported", List.of("client_credentials"));
    doc.put("token_endpoint_auth_methods_supported",
        List.of("client_secret_post", "client_secret_basic"));
    doc.put("token_endpoint_auth_signing_alg_values_supported", List.of("EdDSA"));
    doc.put("id_token_signing_alg_values_supported", List.of("EdDSA"));
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
    final String newKid = signingKeys.rotate();
    audit.record("key.rotated", null, "activeKid=" + newKid);
    return HttpResponse.json(200, Map.of("activeKid", newKid));
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

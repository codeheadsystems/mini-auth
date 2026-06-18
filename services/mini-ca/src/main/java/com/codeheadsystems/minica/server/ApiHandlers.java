package com.codeheadsystems.minica.server;

import com.codeheadsystems.minica.ca.CertificateAuthority.CaIssuanceException;
import com.codeheadsystems.minica.ca.Pem;
import com.codeheadsystems.minica.server.dto.Dtos.IssueRequest;
import com.codeheadsystems.minica.server.dto.Dtos.IssueResponse;
import com.codeheadsystems.minica.server.dto.Dtos.RenewRequest;
import com.codeheadsystems.minica.server.dto.Dtos.RevokeRequest;
import com.codeheadsystems.minica.server.http.ApiException;
import com.codeheadsystems.minica.server.http.HttpResponse;
import com.codeheadsystems.minica.server.http.Json;
import com.codeheadsystems.minica.server.http.RequestContext;
import com.codeheadsystems.minica.server.http.Router;
import com.codeheadsystems.minica.server.http.StaticResource;
import com.codeheadsystems.minica.service.CaService;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * Builds the {@link Router} for the CA. Public endpoints expose the trust anchor and revocation list
 * (verifiers need them); the issuance/renewal/revocation/log endpoints are guarded by the bootstrap
 * admin bearer token. Handlers stay thin — all crypto lives in {@link CaService} /
 * {@code CertificateAuthority}.
 *
 * <p>A malformed/invalid CSR collapses to one generic 400 (no oracle); no private key or admin token
 * is ever logged. The CA never sees a requester's private key — only its CSR.
 */
public final class ApiHandlers {

  private final ServerConfig config;
  private final CaService ca;
  private final AdminAuthenticator adminAuth;
  private final OpenApiDocument openApi;

  public ApiHandlers(final ServerConfig config, final CaService ca, final AdminAuthenticator adminAuth,
                     final OpenApiDocument openApi) {
    this.config = config;
    this.ca = ca;
    this.adminAuth = adminAuth;
    this.openApi = openApi;
  }

  /** @return a router with every route registered. */
  public Router router() {
    final Router router = new Router();
    // Public: meta + the trust anchor + the revocation list (a verifier needs these, no token).
    router.route("GET", "/health", ctx -> HttpResponse.json(200, Map.of("status", "ok")));
    router.route("GET", "/ca", this::caCertificate);
    router.route("GET", "/revocations", this::revocations);
    router.route("GET", "/openapi.yaml", ctx -> HttpResponse.raw(200, "application/yaml", openApi.yaml()));
    router.route("GET", "/openapi.json", ctx -> HttpResponse.raw(200, "application/json", openApi.json()));
    router.route("GET", "/docs", ctx -> HttpResponse.text(200, "text/html; charset=utf-8", SwaggerUiPage.HTML));
    router.route("GET", "/docs/swagger-ui.css",
        ctx -> HttpResponse.raw(200, "text/css", StaticResource.bytes("/swagger-ui/swagger-ui.css")));
    router.route("GET", "/docs/swagger-ui-bundle.js",
        ctx -> HttpResponse.raw(200, "application/javascript", StaticResource.bytes("/swagger-ui/swagger-ui-bundle.js")));
    // Admin: issuance, renewal, revocation, and the issuance log.
    router.route("POST", "/issue", this::issue);
    router.route("POST", "/renew", this::renew);
    router.route("POST", "/revoke", this::revoke);
    router.route("GET", "/log", this::log);
    return router;
  }

  // ---- Public --------------------------------------------------------------------------------

  private HttpResponse caCertificate(final RequestContext ctx) {
    return HttpResponse.text(200, "application/x-pem-file", ca.caCertificatePem());
  }

  private HttpResponse revocations(final RequestContext ctx) {
    return HttpResponse.json(200, ca.revocations());
  }

  // ---- Admin ---------------------------------------------------------------------------------

  private HttpResponse issue(final RequestContext ctx) {
    adminAuth.requireAdmin(ctx.header("Authorization"));
    final IssueRequest request = Json.parse(ctx.body(), IssueRequest.class);
    if (request.csr() == null || request.csr().isBlank()) {
      throw ApiException.badRequest("csr is required");
    }
    final X509Certificate cert = issueOrFail(() ->
        ca.issue(request.csr(), request.sans(), config.clampLeafTtl(request.ttlSeconds())));
    return HttpResponse.json(201, response(cert));
  }

  private HttpResponse renew(final RequestContext ctx) {
    adminAuth.requireAdmin(ctx.header("Authorization"));
    final RenewRequest request = Json.parse(ctx.body(), RenewRequest.class);
    if (request.csr() == null || request.csr().isBlank()) {
      throw ApiException.badRequest("csr is required");
    }
    final X509Certificate cert = issueOrFail(() -> ca.renew(request.csr(), request.sans(),
        config.clampLeafTtl(request.ttlSeconds()), request.previousSerial()));
    return HttpResponse.json(201, response(cert));
  }

  private HttpResponse revoke(final RequestContext ctx) {
    adminAuth.requireAdmin(ctx.header("Authorization"));
    final RevokeRequest request = Json.parse(ctx.body(), RevokeRequest.class);
    if (request.serial() == null || request.serial().isBlank()) {
      throw ApiException.badRequest("serial is required");
    }
    ca.revoke(request.serial(), request.reason());
    return HttpResponse.json(200, Map.of("revoked", request.serial()));
  }

  private HttpResponse log(final RequestContext ctx) {
    adminAuth.requireAdmin(ctx.header("Authorization"));
    return HttpResponse.json(200, ca.issuanceLog());
  }

  // ---- Helpers -------------------------------------------------------------------------------

  private IssueResponse response(final X509Certificate cert) {
    return new IssueResponse(CaService.serialOf(cert),
        Pem.encode(Pem.CERTIFICATE, encoded(cert)), ca.caCertificatePem(),
        cert.getNotAfter().toInstant().getEpochSecond());
  }

  private static X509Certificate issueOrFail(final java.util.function.Supplier<X509Certificate> issue) {
    try {
      return issue.get();
    } catch (final CaIssuanceException e) {
      // One generic 400 for any bad CSR — never an oracle for which check failed.
      throw ApiException.badRequest("invalid certificate request");
    }
  }

  private static byte[] encoded(final X509Certificate cert) {
    try {
      return cert.getEncoded();
    } catch (final java.security.cert.CertificateEncodingException e) {
      throw new IllegalStateException("failed to encode certificate", e);
    }
  }
}

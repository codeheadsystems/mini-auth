package com.codeheadsystems.minigateway.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minigateway.auth.JwksProvider;
import com.codeheadsystems.minigateway.store.JsonStore;
import com.codeheadsystems.minitoken.auth.Authorization;
import com.codeheadsystems.minitoken.auth.Grant;
import com.codeheadsystems.minitoken.auth.KeyOperation;
import com.codeheadsystems.minitoken.service.SigningKeyService;
import com.codeheadsystems.minitoken.service.SigningKeyService.Signer;
import com.codeheadsystems.minitoken.session.SessionService;
import com.codeheadsystems.minitoken.session.Sessions;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import com.codeheadsystems.minitoken.token.GrantsClaim;
import com.codeheadsystems.minitoken.token.Jws;
import com.codeheadsystems.minitoken.token.JwsHeader;
import com.codeheadsystems.minitoken.util.RandomIds;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Drives the live forward-auth endpoint with the headers a reverse proxy would send, covering the
 * core outcomes: allow (shared SSO session and bearer token), deny (401 for an API client, 403 for
 * an authenticated-but-forbidden caller), and redirect-to-login for an unauthenticated browser.
 */
class ForwardAuthTest {

  private static final String ISSUER = "http://oidc.test";
  private static final String AUDIENCE = "http://oidc.test/userinfo";
  private static final String LOGIN_URL = "http://oidc.test/authorize?client_id=gw";

  private final Clock clock = Clock.systemUTC();
  private GatewayServer server;
  private HttpClient client;
  private String baseUrl;
  private SessionService sessions;       // stands in for mini-oidc, writing the shared session store
  private SigningKeyService signingKeys;  // stands in for mini-oidc's token plane

  @BeforeEach
  void setUp(@TempDir final Path dir) throws IOException {
    final Path sessionsFile = dir.resolve("sessions.json");
    // The SAME store mini-oidc would write: the gateway reads it (shared mechanism, not a copy).
    sessions = new SessionService(new JsonStore<>(sessionsFile, Sessions.class), clock, Duration.ofHours(12));
    signingKeys = new SigningKeyService(
        new JsonStore<>(dir.resolve("signing-keys.json"), SigningKeys.class),
        new RandomIds(), clock, Duration.ofMinutes(30));

    final Path routes = dir.resolve("routes.json");
    // The /kms route is gated on a mini-idp machine-token scope (keyGroup:OPERATION) — the dialect a
    // grants claim maps to — so the SCOPE branch can be exercised by a machine token, not just an
    // OIDC-shaped one.
    Files.writeString(routes, """
        {"routes":[
          {"pathPrefix":"/public","access":"PUBLIC"},
          {"pathPrefix":"/admin","access":"SCOPE","scope":"admin"},
          {"pathPrefix":"/kms","access":"SCOPE","scope":"billing:ENCRYPT"},
          {"pathPrefix":"/","access":"AUTHENTICATED"}
        ]}""");

    final ServerConfig config = ServerConfig.resolve(new String[] {
        "--port", "0", "--sessions-file", sessionsFile.toString(), "--routes-file", routes.toString(),
        "--login-url", LOGIN_URL, "--issuer", ISSUER, "--audience", AUDIENCE}, Map.of());
    // Inject a JWKS provider backed by our local signing keys so bearer verification needs no network.
    final JwksProvider jwks = signingKeys::jwkSet;
    server = GatewayServer.create(config, clock, jwks);
    server.start();
    baseUrl = "http://127.0.0.1:" + server.address().getPort();
    client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
  }

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void validSsoSessionIsAllowedWithIdentityHeaders() throws Exception {
    final String sessionId = sessions.create("alice", clock.instant().getEpochSecond());
    final HttpResponse<String> response = verify("GET", "/app/page", Map.of(
        "Cookie", SessionService.DEFAULT_COOKIE_NAME + "=" + sessionId,
        "Accept", "text/html"));
    assertEquals(200, response.statusCode());
    assertEquals("alice", response.headers().firstValue("X-Auth-Subject").orElse(null));
    assertEquals("session", response.headers().firstValue("X-Auth-Source").orElse(null));
  }

  @Test
  void unauthenticatedBrowserIsRedirectedToLogin() throws Exception {
    final HttpResponse<String> response = verify("GET", "/app/page", Map.of("Accept", "text/html"));
    assertEquals(302, response.statusCode());
    final String location = response.headers().firstValue("Location").orElseThrow();
    assertTrue(location.startsWith(LOGIN_URL), "redirect to the configured login URL");
    assertTrue(location.contains("rd="), "carries the original URL to return to");
  }

  @Test
  void unauthenticatedApiClientGets401() throws Exception {
    final HttpResponse<String> response = verify("GET", "/app/data", Map.of("Accept", "application/json"));
    assertEquals(401, response.statusCode());
    assertTrue(response.headers().firstValue("WWW-Authenticate").isPresent());
  }

  @Test
  void publicRouteAllowsAnonymous() throws Exception {
    assertEquals(200, verify("GET", "/public/health", Map.of("Accept", "application/json")).statusCode());
  }

  @Test
  void authenticatedSessionWithoutTheScopeIsForbidden() throws Exception {
    // A session carries no scopes, so the scope-gated /admin route forbids it (mini-policy deny).
    final String sessionId = sessions.create("alice", clock.instant().getEpochSecond());
    final HttpResponse<String> response = verify("GET", "/admin/panel", Map.of(
        "Cookie", SessionService.DEFAULT_COOKIE_NAME + "=" + sessionId,
        "Accept", "text/html"));
    assertEquals(403, response.statusCode());
  }

  @Test
  void bearerTokenWithTheRequiredScopeIsAllowed() throws Exception {
    final String token = mintAccessToken("svc", "openid admin", AUDIENCE);
    final HttpResponse<String> response = verify("GET", "/admin/panel", Map.of(
        "Authorization", "Bearer " + token, "Accept", "application/json"));
    assertEquals(200, response.statusCode());
    assertEquals("svc", response.headers().firstValue("X-Auth-Subject").orElse(null));
    assertEquals("token", response.headers().firstValue("X-Auth-Source").orElse(null));
  }

  @Test
  void bearerTokenForTheWrongAudienceIsRejected() throws Exception {
    final String token = mintAccessToken("svc", "openid admin", "some-other-audience");
    final HttpResponse<String> response = verify("GET", "/admin/panel", Map.of(
        "Authorization", "Bearer " + token, "Accept", "application/json"));
    assertEquals(401, response.statusCode(), "a wrong-audience token does not authenticate");
  }

  @Test
  void miniIdpMachineTokenSatisfiesAScopeRouteFromItsGrantsClaim() throws Exception {
    // A mini-idp machine token carries NO top-level `scope` — its authority is in the `grants` claim.
    // The gateway maps grants → keyGroup:OPERATION scopes, so this token satisfies the /kms SCOPE
    // route (billing:ENCRYPT). Before the dialect fix it authenticated but carried zero scopes.
    final String token = mintMachineToken("svc-kms", new Authorization(false,
        List.of(Grant.of("billing", KeyOperation.ENCRYPT, KeyOperation.DECRYPT))));
    final HttpResponse<String> response = verify("GET", "/kms/encrypt", Map.of(
        "Authorization", "Bearer " + token, "Accept", "application/json"));
    assertEquals(200, response.statusCode(), "the machine token's grant covers billing:ENCRYPT");
    assertEquals("svc-kms", response.headers().firstValue("X-Auth-Subject").orElse(null));
  }

  @Test
  void miniIdpMachineTokenWithoutTheGrantedOperationIsForbidden() throws Exception {
    // The same machine identity, but only DECRYPT on billing — it must NOT satisfy billing:ENCRYPT.
    final String token = mintMachineToken("svc-kms", new Authorization(false,
        List.of(Grant.of("billing", KeyOperation.DECRYPT))));
    final HttpResponse<String> response = verify("GET", "/kms/encrypt", Map.of(
        "Authorization", "Bearer " + token, "Accept", "application/json"));
    assertEquals(403, response.statusCode(), "DECRYPT does not cover the route's billing:ENCRYPT");
  }

  @Test
  void miniIdpControlPlaneTokenIsAllowedEverywhere() throws Exception {
    // grants.control → admin: a control-plane machine token is allowed at any SCOPE route.
    final String token = mintMachineToken("svc-root", new Authorization(true, List.of()));
    final HttpResponse<String> response = verify("GET", "/admin/panel", Map.of(
        "Authorization", "Bearer " + token, "Accept", "application/json"));
    assertEquals(200, response.statusCode(), "grants.control maps to admin, allowed everywhere");
  }

  // ---- helpers -------------------------------------------------------------------------------

  private String mintAccessToken(final String subject, final String scope, final String audience) {
    final long now = clock.instant().getEpochSecond();
    final Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("iss", ISSUER);
    claims.put("sub", subject);
    claims.put("aud", audience);
    claims.put("scope", scope);
    claims.put("iat", now);
    claims.put("nbf", now);
    claims.put("exp", now + 300);
    final Signer signer = signingKeys.currentSigner();
    return Jws.sign(JwsHeader.forKid(signer.kid()), claims, signer.privateKey());
  }

  /** Mint a mini-idp-shaped machine token: authority in a {@code grants} claim, no top-level scope. */
  private String mintMachineToken(final String subject, final Authorization authorization) {
    final long now = clock.instant().getEpochSecond();
    final Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("iss", ISSUER);
    claims.put("sub", subject);
    claims.put("aud", AUDIENCE);
    claims.put("grants", GrantsClaim.from(authorization));
    claims.put("iat", now);
    claims.put("nbf", now);
    claims.put("exp", now + 300);
    final Signer signer = signingKeys.currentSigner();
    return Jws.sign(JwsHeader.forKid(signer.kid()), claims, signer.privateKey());
  }

  private HttpResponse<String> verify(final String method, final String uri,
                                      final Map<String, String> headers) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + "/verify"))
        .GET()
        .header("X-Forwarded-Method", method)
        .header("X-Forwarded-Uri", uri)
        .header("X-Forwarded-Host", "app.example")
        .header("X-Forwarded-Proto", "https");
    headers.forEach(builder::header);
    return client.send(builder.build(), BodyHandlers.ofString());
  }
}

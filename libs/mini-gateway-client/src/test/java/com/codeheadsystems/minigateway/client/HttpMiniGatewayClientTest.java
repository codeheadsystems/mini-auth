package com.codeheadsystems.minigateway.client;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.codeheadsystems.minigateway.auth.JwksProvider;
import com.codeheadsystems.minigateway.server.GatewayServer;
import com.codeheadsystems.minigateway.server.ServerConfig;
import com.codeheadsystems.minigateway.store.JsonStore;
import com.codeheadsystems.minitoken.service.SigningKeyService;
import com.codeheadsystems.minitoken.service.SigningKeyService.Signer;
import com.codeheadsystems.minitoken.session.SessionService;
import com.codeheadsystems.minitoken.session.Sessions;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import com.codeheadsystems.minitoken.token.Jws;
import com.codeheadsystems.minitoken.token.JwsHeader;
import com.codeheadsystems.minitoken.util.RandomIds;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Behavior proof for {@link MiniGatewayClient}: boot the REAL mini-gateway on an ephemeral loopback
 * port (with a routes file gating {@code /admin} on the {@code admin} scope and everything else behind
 * login), then drive every {@code /verify} branch over HTTP and confirm the client maps each status
 * to the right {@link VerifyOutcome} — anonymous browser → 302, anonymous API → 401, a bearer with the
 * scope → 200, a bearer without it → 403. Bearer tokens are minted through mini-token, exactly as
 * mini-oidc would issue them, and verified by the gateway against an injected JWKS (no network).
 */
class HttpMiniGatewayClientTest {

  private static final String ISSUER = "http://oidc.test";
  private static final String AUDIENCE = "http://oidc.test/userinfo";
  private static final String LOGIN_URL = "http://oidc.test/authorize?client_id=gw";

  private final Clock clock = Clock.systemUTC();
  private GatewayServer server;
  private MiniGatewayClient client;
  private SigningKeyService signingKeys;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws IOException {
    final Path sessionsFile = dir.resolve("sessions.json");
    // Touch the shared session store so the gateway's SessionService can open it.
    new SessionService(new JsonStore<>(sessionsFile, Sessions.class), clock, Duration.ofHours(12));
    signingKeys = new SigningKeyService(
        new JsonStore<>(dir.resolve("signing-keys.json"), SigningKeys.class),
        new RandomIds(), clock, Duration.ofMinutes(30));

    final Path routes = dir.resolve("routes.json");
    Files.writeString(routes, """
        {"routes":[
          {"pathPrefix":"/admin","access":"SCOPE","scope":"admin"},
          {"pathPrefix":"/","access":"AUTHENTICATED"}
        ]}""");

    final ServerConfig config = ServerConfig.resolve(new String[] {
        "--port", "0", "--sessions-file", sessionsFile.toString(), "--routes-file", routes.toString(),
        "--login-url", LOGIN_URL, "--issuer", ISSUER, "--audience", AUDIENCE}, Map.of());
    final JwksProvider jwks = signingKeys::jwkSet;
    server = GatewayServer.create(config, clock, jwks);
    server.start();
    client = MiniGatewayClient.http(URI.create("http://127.0.0.1:" + server.address().getPort()));
  }

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void health_reportsOk() {
    assertEquals("ok", client.health().status());
  }

  @Test
  void anonymousBrowser_isRedirectedToLogin() {
    assertEquals(VerifyOutcome.REDIRECT_LOGIN,
        client.verify(VerifyRequest.anonymous("GET", "/app/page", true)));
  }

  @Test
  void anonymousApiClient_isUnauthenticated() {
    assertEquals(VerifyOutcome.UNAUTHENTICATED,
        client.verify(VerifyRequest.anonymous("GET", "/app/data", false)));
  }

  @Test
  void bearerWithTheScope_isAuthorized() {
    final String token = mintAccessToken("svc", "openid admin", AUDIENCE);
    assertEquals(VerifyOutcome.AUTHORIZED,
        client.verify(VerifyRequest.withBearer("GET", "/admin/panel", token)));
  }

  @Test
  void bearerWithoutTheScope_isForbidden() {
    final String token = mintAccessToken("svc", "openid", AUDIENCE);
    assertEquals(VerifyOutcome.FORBIDDEN,
        client.verify(VerifyRequest.withBearer("GET", "/admin/panel", token)));
  }

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
}

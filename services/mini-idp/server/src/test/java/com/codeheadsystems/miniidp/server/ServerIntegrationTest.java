package com.codeheadsystems.miniidp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.service.TokenVerifier;
import com.codeheadsystems.minitoken.service.TokenVerifier.Result;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Full HTTP integration test: starts the real {@link IdpServer} on an ephemeral loopback port and
 * drives it with an HTTP client, then verifies issued tokens offline against the live JWKS.
 */
class ServerIntegrationTest {

  private static final String ADMIN_TOKEN = "test-admin-token";
  private static final String ISSUER = "http://idp.test";
  private static final String AUDIENCE = "mini-kms";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private IdpServer server;
  private HttpClient client;
  private String baseUrl;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws IOException {
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString(),
            "--issuer", ISSUER, "--audience", AUDIENCE,
            "--argon-memory-kib", "1024", "--argon-iterations", "1", "--argon-parallelism", "1"},
        Map.of());
    server = IdpServer.create(config, ADMIN_TOKEN, Clock.systemUTC());
    server.start();
    baseUrl = "http://127.0.0.1:" + server.address().getPort();
    client = HttpClient.newHttpClient();
  }

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void healthReturnsOk() throws Exception {
    final HttpResponse<String> response = get("/health", null);
    assertEquals(200, response.statusCode());
    assertEquals("ok", MAPPER.readTree(response.body()).get("status").asText());
  }

  @Test
  void adminEndpointsRequireTheAdminToken() throws Exception {
    assertEquals(401, get("/admin/clients", null).statusCode());
    assertEquals(401, get("/admin/clients", "wrong-token").statusCode());
    assertEquals(200, get("/admin/clients", ADMIN_TOKEN).statusCode());
  }

  @Test
  void issuedTokenVerifiesAgainstLiveJwks() throws Exception {
    final Client registered = registerClient("{\"displayName\":\"svc\",\"authorization\":"
        + "{\"control\":false,\"groups\":[{\"keyGroup\":\"billing\",\"operations\":[\"ENCRYPT\",\"DECRYPT\"]}]}}");

    final HttpResponse<String> tokenResponse = requestToken(registered.clientId, registered.secret);
    assertEquals(200, tokenResponse.statusCode());
    final JsonNode body = MAPPER.readTree(tokenResponse.body());
    assertEquals("Bearer", body.get("token_type").asText());
    assertTrue(body.get("expires_in").asLong() > 0);
    final String accessToken = body.get("access_token").asText();

    final Result result = verifyAgainstLiveJwks(accessToken);
    assertTrue(result.valid(), "token from the server must verify against its published JWKS");
    assertEquals(registered.clientId, result.claims().subject());
    assertEquals(AUDIENCE, result.claims().audience());
    // The admin-set grants are present in the token.
    assertEquals("billing", result.claims().grants().groups().get(0).keyGroup());
    assertTrue(result.claims().grants().groups().get(0).operations().contains("ENCRYPT"));
  }

  @Test
  void badClientSecretIsRejectedWithGenericError() throws Exception {
    final Client registered = registerClient(
        "{\"authorization\":{\"control\":false,\"groups\":[]}}");
    final HttpResponse<String> response = requestToken(registered.clientId, "wrong-secret");
    assertEquals(401, response.statusCode());
    // Generic error code, no detail distinguishing unknown-client from wrong-secret.
    assertEquals("invalid_client", MAPPER.readTree(response.body()).get("error").asText());
  }

  @Test
  void rotationKeepsOldTokensValidAndNewTokensUseNewKid() throws Exception {
    final Client registered = registerClient(
        "{\"authorization\":{\"control\":false,\"groups\":[]}}");
    final String oldToken = MAPPER.readTree(requestToken(registered.clientId, registered.secret).body())
        .get("access_token").asText();
    final String oldKid = kidOf(oldToken);

    final HttpResponse<String> rotate = postJson("/admin/keys/rotate", "", ADMIN_TOKEN);
    assertEquals(200, rotate.statusCode());
    final String newKid = MAPPER.readTree(rotate.body()).get("activeKid").asText();
    assertNotEquals(oldKid, newKid);

    // Old token still verifies (its kid stays published).
    assertTrue(verifyAgainstLiveJwks(oldToken).valid());

    // A freshly issued token uses the new kid and verifies.
    final String newToken = MAPPER.readTree(requestToken(registered.clientId, registered.secret).body())
        .get("access_token").asText();
    assertEquals(newKid, kidOf(newToken));
    assertTrue(verifyAgainstLiveJwks(newToken).valid());
  }

  @Test
  void revokedJtiAppearsInDenylist() throws Exception {
    final Client registered = registerClient(
        "{\"authorization\":{\"control\":false,\"groups\":[]}}");
    final String token = MAPPER.readTree(requestToken(registered.clientId, registered.secret).body())
        .get("access_token").asText();
    final String jti = MAPPER.readTree(payloadJson(token)).get("jti").asText();

    final HttpResponse<String> revoke = postJson("/admin/revocations",
        "{\"jti\":\"" + jti + "\",\"reason\":\"test\"}", ADMIN_TOKEN);
    assertEquals(201, revoke.statusCode());

    final HttpResponse<String> denylist = get("/admin/revocations", ADMIN_TOKEN);
    assertEquals(200, denylist.statusCode());
    boolean found = false;
    for (final JsonNode entry : MAPPER.readTree(denylist.body())) {
      found |= entry.get("jti").asText().equals(jti);
    }
    assertTrue(found, "revoked jti must appear in the pollable denylist");

    // And a verifier polling the denylist now rejects the token.
    final Result result = verifyAgainstLiveJwks(token, jti::equals);
    assertFalse(result.valid());
  }

  @Test
  void discoveryDocumentExposesTheContractUrls() throws Exception {
    final JsonNode doc = MAPPER.readTree(get("/.well-known/idp-configuration", null).body());
    assertEquals(ISSUER, doc.get("issuer").asText());
    assertEquals(ISSUER + "/oauth/token", doc.get("token_endpoint").asText());
    assertEquals(ISSUER + "/.well-known/jwks.json", doc.get("jwks_uri").asText());
  }

  // ---- helpers -------------------------------------------------------------------------------

  private record Client(String clientId, String secret) {
  }

  private Client registerClient(final String json) throws Exception {
    final HttpResponse<String> response = postJson("/admin/clients", json, ADMIN_TOKEN);
    assertEquals(201, response.statusCode(), response.body());
    final JsonNode body = MAPPER.readTree(response.body());
    return new Client(body.get("clientId").asText(), body.get("secret").asText());
  }

  private HttpResponse<String> requestToken(final String clientId, final String secret) throws Exception {
    final String form = "grant_type=client_credentials"
        + "&client_id=" + urlEncode(clientId)
        + "&client_secret=" + urlEncode(secret);
    final HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/oauth/token"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(BodyPublishers.ofString(form))
        .build();
    return client.send(request, BodyHandlers.ofString());
  }

  private HttpResponse<String> get(final String path, final String adminToken) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET();
    if (adminToken != null) {
      builder.header("Authorization", "Bearer " + adminToken);
    }
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  private HttpResponse<String> postJson(final String path, final String json, final String adminToken)
      throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Content-Type", "application/json")
        .POST(BodyPublishers.ofString(json));
    if (adminToken != null) {
      builder.header("Authorization", "Bearer " + adminToken);
    }
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  private Result verifyAgainstLiveJwks(final String token) throws Exception {
    return verifyAgainstLiveJwks(token, jti -> false);
  }

  private Result verifyAgainstLiveJwks(final String token, final java.util.function.Predicate<String> revoked)
      throws Exception {
    final JwkSet jwkSet = MAPPER.readValue(get("/.well-known/jwks.json", null).body(), JwkSet.class);
    final TokenVerifier verifier = new TokenVerifier(ISSUER, AUDIENCE, Clock.systemUTC(), 5);
    return verifier.verify(token, jwkSet, revoked);
  }

  private static String kidOf(final String token) throws IOException {
    final String headerJson = new String(
        Base64.getUrlDecoder().decode(token.split("\\.")[0]), StandardCharsets.UTF_8);
    return MAPPER.readTree(headerJson).get("kid").asText();
  }

  private static String payloadJson(final String token) {
    return new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]), StandardCharsets.UTF_8);
  }

  private static String urlEncode(final String value) {
    return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}

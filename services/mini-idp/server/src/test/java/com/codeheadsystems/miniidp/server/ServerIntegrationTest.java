package com.codeheadsystems.miniidp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniidp.directory.InMemoryServiceAccountDirectory;
import com.codeheadsystems.minitoken.auth.Authorization;
import com.codeheadsystems.minitoken.auth.Grant;
import com.codeheadsystems.minitoken.auth.KeyOperation;
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
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Full HTTP integration test: starts the real {@link IdpServer} on an ephemeral loopback port,
 * sourcing client identity from an injected {@link InMemoryServiceAccountDirectory} (standing in for
 * mini-directory), then verifies issued tokens offline against the live JWKS.
 */
class ServerIntegrationTest {

  private static final String ADMIN_TOKEN = "test-admin-token";
  private static final String ISSUER = "http://idp.test";
  private static final String AUDIENCE = "mini-kms";
  private static final String CLIENT = "svc_demo";
  private static final String SECRET = "s3cr3t-value";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private IdpServer server;
  private HttpClient client;
  private String baseUrl;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws IOException {
    final InMemoryServiceAccountDirectory directory = new InMemoryServiceAccountDirectory().add(
        CLIENT, SECRET, new Authorization(false,
            List.of(Grant.of("billing", KeyOperation.ENCRYPT, KeyOperation.DECRYPT))));
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString(),
            "--issuer", ISSUER, "--audience", AUDIENCE}, java.util.Map.of());
    server = IdpServer.create(config, ADMIN_TOKEN, directory, Clock.systemUTC());
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
    assertEquals("ok", MAPPER.readTree(response.body()).get("status").asString());
  }

  @Test
  void adminEndpointsRequireTheAdminToken() throws Exception {
    assertEquals(401, get("/admin/audit", null).statusCode());
    assertEquals(401, get("/admin/audit", "wrong-token").statusCode());
    assertEquals(200, get("/admin/audit", ADMIN_TOKEN).statusCode());
  }

  @Test
  void issuedTokenVerifiesAgainstLiveJwks() throws Exception {
    final HttpResponse<String> tokenResponse = requestToken(CLIENT, SECRET);
    assertEquals(200, tokenResponse.statusCode());
    final JsonNode body = MAPPER.readTree(tokenResponse.body());
    assertEquals("Bearer", body.get("token_type").asString());
    final String accessToken = body.get("access_token").asString();

    final Result result = verifyAgainstLiveJwks(accessToken);
    assertTrue(result.valid(), "token from the server must verify against its published JWKS");
    assertEquals(CLIENT, result.claims().subject());
    assertEquals(AUDIENCE, result.claims().audience());
    // The directory-sourced grants are present in the token, identical to the old registry's output.
    assertEquals("billing", result.claims().grants().groups().get(0).keyGroup());
    assertTrue(result.claims().grants().groups().get(0).operations().contains("ENCRYPT"));
  }

  @Test
  void badClientSecretIsRejectedWithGenericError() throws Exception {
    final HttpResponse<String> response = requestToken(CLIENT, "wrong-secret");
    assertEquals(401, response.statusCode());
    assertEquals("invalid_client", MAPPER.readTree(response.body()).get("error").asString());
  }

  @Test
  void unknownClientIsRejectedWithTheSameGenericError() throws Exception {
    final HttpResponse<String> response = requestToken("svc_nobody", SECRET);
    assertEquals(401, response.statusCode());
    assertEquals("invalid_client", MAPPER.readTree(response.body()).get("error").asString());
  }

  @Test
  void rotationKeepsOldTokensValidAndNewTokensUseNewKid() throws Exception {
    final String oldToken = MAPPER.readTree(requestToken(CLIENT, SECRET).body()).get("access_token").asString();
    final String oldKid = kidOf(oldToken);

    final HttpResponse<String> rotate = postJson("/admin/keys/rotate", "", ADMIN_TOKEN);
    assertEquals(200, rotate.statusCode());
    final String newKid = MAPPER.readTree(rotate.body()).get("activeKid").asString();
    assertNotEquals(oldKid, newKid);

    assertTrue(verifyAgainstLiveJwks(oldToken).valid());
    final String newToken = MAPPER.readTree(requestToken(CLIENT, SECRET).body()).get("access_token").asString();
    assertEquals(newKid, kidOf(newToken));
    assertTrue(verifyAgainstLiveJwks(newToken).valid());
  }

  @Test
  void revokedJtiAppearsInDenylist() throws Exception {
    final String token = MAPPER.readTree(requestToken(CLIENT, SECRET).body()).get("access_token").asString();
    final String jti = MAPPER.readTree(payloadJson(token)).get("jti").asString();

    assertEquals(201, postJson("/admin/revocations",
        "{\"jti\":\"" + jti + "\",\"reason\":\"test\"}", ADMIN_TOKEN).statusCode());
    final JsonNode denylist = MAPPER.readTree(get("/admin/revocations", ADMIN_TOKEN).body());
    boolean found = false;
    for (final JsonNode entry : denylist) {
      found |= entry.get("jti").asString().equals(jti);
    }
    assertTrue(found, "revoked jti must appear in the pollable denylist");
    assertFalse(verifyAgainstLiveJwks(token, jti::equals).valid());
  }

  @Test
  void discoveryDocumentExposesTheContractUrls() throws Exception {
    final JsonNode doc = MAPPER.readTree(get("/.well-known/idp-configuration", null).body());
    assertEquals(ISSUER, doc.get("issuer").asString());
    assertEquals(ISSUER + "/oauth/token", doc.get("token_endpoint").asString());
    assertEquals(ISSUER + "/.well-known/jwks.json", doc.get("jwks_uri").asString());
  }

  // ---- helpers -------------------------------------------------------------------------------

  private HttpResponse<String> requestToken(final String clientId, final String secret) throws Exception {
    final String form = "grant_type=client_credentials&client_id=" + urlEncode(clientId)
        + "&client_secret=" + urlEncode(secret);
    return client.send(HttpRequest.newBuilder(URI.create(baseUrl + "/oauth/token"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(BodyPublishers.ofString(form)).build(), BodyHandlers.ofString());
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
    return client.send(HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Content-Type", "application/json").header("Authorization", "Bearer " + adminToken)
        .POST(BodyPublishers.ofString(json)).build(), BodyHandlers.ofString());
  }

  private Result verifyAgainstLiveJwks(final String token) throws Exception {
    return verifyAgainstLiveJwks(token, jti -> false);
  }

  private Result verifyAgainstLiveJwks(final String token, final java.util.function.Predicate<String> revoked)
      throws Exception {
    final JwkSet jwkSet = MAPPER.readValue(get("/.well-known/jwks.json", null).body(), JwkSet.class);
    return new TokenVerifier(ISSUER, AUDIENCE, Clock.systemUTC(), 5).verify(token, jwkSet, revoked);
  }

  private static String kidOf(final String token) {
    final String headerJson = new String(
        Base64.getUrlDecoder().decode(token.split("\\.")[0]), StandardCharsets.UTF_8);
    return MAPPER.readTree(headerJson).get("kid").asString();
  }

  private static String payloadJson(final String token) {
    return new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]), StandardCharsets.UTF_8);
  }

  private static String urlEncode(final String value) {
    return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}

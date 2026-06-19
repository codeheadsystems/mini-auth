package com.codeheadsystems.minioidc.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minioidc.auth.PasskeyStack;
import com.codeheadsystems.minioidc.directory.InMemoryUserDirectory;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Proves the new {@code POST /admin/keys/rotate} endpoint: an admin caller rotates the signing key,
 * the new active kid appears in the JWKS, and the retired kid is retained (so in-flight tokens still
 * verify). Mirrors mini-idp's existing rotation behaviour.
 */
class OidcKeyRotationTest {

  private static final JsonMapper MAPPER = JsonMapper.builder().build();
  private static final String ADMIN = "admin";

  private OidcServer server;
  private HttpClient client;
  private String baseUrl;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws IOException {
    final PasskeyStack passkeys = PasskeyStack.inMemory(
        new RelyingPartyConfig("example.com", "mini-oidc", Set.of("https://example.com")),
        ClockProvider.system());
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    server = OidcServer.create(config, ADMIN, new InMemoryUserDirectory(),
        passkeys.humanAuthenticator(), passkeys.recoveryAuthenticator(), Clock.systemUTC());
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
  void rotatePublishesNewKidAndRetainsTheOld() throws Exception {
    final Set<String> before = kids();
    assertEquals(1, before.size(), "a fresh server publishes exactly one key");
    final String oldKid = before.iterator().next();

    final HttpResponse<String> rotate = client.send(HttpRequest.newBuilder(
            URI.create(baseUrl + "/admin/keys/rotate"))
        .header("Authorization", "Bearer " + ADMIN)
        .POST(HttpRequest.BodyPublishers.noBody()).build(), BodyHandlers.ofString());
    assertEquals(200, rotate.statusCode());
    final String activeKid = MAPPER.readTree(rotate.body()).get("activeKid").asString();
    assertNotEquals(oldKid, activeKid, "rotation must produce a fresh kid");

    final Set<String> after = kids();
    assertTrue(after.contains(activeKid), "the new active kid is published");
    assertTrue(after.contains(oldKid), "the retired kid is retained so in-flight tokens still verify");
  }

  @Test
  void rotateRequiresAdmin() throws Exception {
    final HttpResponse<String> noToken = client.send(HttpRequest.newBuilder(
            URI.create(baseUrl + "/admin/keys/rotate"))
        .POST(HttpRequest.BodyPublishers.noBody()).build(), BodyHandlers.ofString());
    assertEquals(401, noToken.statusCode());
  }

  private Set<String> kids() throws Exception {
    final HttpResponse<String> jwks = client.send(HttpRequest.newBuilder(
        URI.create(baseUrl + "/jwks.json")).GET().build(), BodyHandlers.ofString());
    assertEquals(200, jwks.statusCode());
    final java.util.Set<String> kids = new java.util.HashSet<>();
    for (final JsonNode key : MAPPER.readTree(jwks.body()).get("keys")) {
      kids.add(key.get("kid").asString());
    }
    return kids;
  }
}

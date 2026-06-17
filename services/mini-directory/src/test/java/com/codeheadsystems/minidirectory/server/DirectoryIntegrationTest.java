package com.codeheadsystems.minidirectory.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minipolicy.Action;
import com.codeheadsystems.minipolicy.Decision;
import com.codeheadsystems.minipolicy.GrantBasedPolicyEngine;
import com.codeheadsystems.minipolicy.Principal;
import com.codeheadsystems.minipolicy.Resource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Full HTTP integration test: starts the real {@link DirectoryServer} on an ephemeral loopback port
 * and drives it with an HTTP client, then proves a stored principal resolves — over HTTP — into
 * inputs a mini-policy engine decides over.
 */
class DirectoryIntegrationTest {

  private static final String ADMIN_TOKEN = "test-admin-token";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private DirectoryServer server;
  private HttpClient client;
  private String baseUrl;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws IOException {
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString(),
            "--argon-memory-kib", "1024", "--argon-iterations", "1", "--argon-parallelism", "1"},
        Map.of());
    server = DirectoryServer.create(config, ADMIN_TOKEN);
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
  void healthIsPublic() throws Exception {
    final HttpResponse<String> response = get("/health", null);
    assertEquals(200, response.statusCode());
    assertEquals("ok", MAPPER.readTree(response.body()).get("status").asText());
  }

  @Test
  void adminEndpointsRequireTheAdminToken() throws Exception {
    assertEquals(401, get("/admin/principals", null).statusCode());
    assertEquals(401, get("/admin/principals", "wrong-token").statusCode());
    assertEquals(200, get("/admin/principals", ADMIN_TOKEN).statusCode());
  }

  @Test
  void storedHumanResolvesToAPolicyDecisionOverHttp() throws Exception {
    assertEquals(201, post("/admin/roles",
        "{\"id\":\"billing-operator\",\"grants\":[{\"action\":\"ENCRYPT\",\"resource\":\"billing\"}]}").statusCode());
    assertEquals(201, post("/admin/groups",
        "{\"id\":\"finance\",\"roles\":[\"billing-operator\"]}").statusCode());
    assertEquals(201, post("/admin/humans",
        "{\"id\":\"alice\",\"displayName\":\"Alice\",\"memberOf\":[\"finance\"]}").statusCode());

    // Resolve over HTTP, then reconstruct a mini-policy engine from the response and decide.
    final HttpResponse<String> resolution = get("/admin/principals/alice/resolution", ADMIN_TOKEN);
    assertEquals(200, resolution.statusCode());
    final JsonNode body = MAPPER.readTree(resolution.body());
    assertEquals("alice", body.get("id").asText());
    assertFalse(body.get("admin").asBoolean());

    final Principal principal = new Principal(body.get("id").asText(), body.get("admin").asBoolean());
    final GrantBasedPolicyEngine.Builder builder = GrantBasedPolicyEngine.builder();
    for (final JsonNode grant : body.get("grants")) {
      builder.grant(principal.id(),
          Action.of(grant.get("action").asText()), Resource.of(grant.get("resource").asText()));
    }
    final GrantBasedPolicyEngine engine = builder.build();
    assertEquals(Decision.ALLOW, engine.decide(principal, Action.of("ENCRYPT"), Resource.of("billing")));
    assertEquals(Decision.DENY, engine.decide(principal, Action.of("DECRYPT"), Resource.of("billing")));
  }

  @Test
  void serviceAccountCreationReturnsAOneTimeSecretAndListingHidesIt() throws Exception {
    final HttpResponse<String> created = post("/admin/service-accounts", "{\"displayName\":\"worker\"}");
    assertEquals(201, created.statusCode());
    final JsonNode body = MAPPER.readTree(created.body());
    final String id = body.get("id").asText();
    assertTrue(body.get("secret").asText().length() > 0, "a one-time secret must be returned");
    assertEquals("SERVICE_ACCOUNT", body.get("account").get("kind").asText());

    // The listing returns the account but never any secret material.
    final JsonNode list = MAPPER.readTree(get("/admin/principals", ADMIN_TOKEN).body());
    boolean found = false;
    for (final JsonNode account : list) {
      if (account.get("id").asText().equals(id)) {
        found = true;
        assertTrue(account.get("secret") == null, "listing must not include a secret");
        assertTrue(account.get("secretHash") == null, "listing must not include a secret hash");
      }
    }
    assertTrue(found, "the created service account must appear in the listing");
  }

  @Test
  void duplicateIdConflictsAndDanglingReferenceIsBadRequest() throws Exception {
    assertEquals(201, post("/admin/humans", "{\"id\":\"bob\"}").statusCode());
    assertEquals(409, post("/admin/humans", "{\"id\":\"bob\"}").statusCode());
    // A human referencing a non-existent group is a 400, not a silent success.
    assertEquals(400, post("/admin/humans", "{\"id\":\"carol\",\"memberOf\":[\"ghost\"]}").statusCode());
  }

  @Test
  void principalCanBeDeleted() throws Exception {
    assertEquals(201, post("/admin/humans", "{\"id\":\"dave\"}").statusCode());
    assertEquals(204, delete("/admin/principals/dave").statusCode());
    assertEquals(404, get("/admin/principals/dave", ADMIN_TOKEN).statusCode());
  }

  // ---- helpers -------------------------------------------------------------------------------

  private HttpResponse<String> get(final String path, final String token) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET();
    if (token != null) {
      builder.header("Authorization", "Bearer " + token);
    }
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  private HttpResponse<String> post(final String path, final String json) throws Exception {
    return client.send(HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer " + ADMIN_TOKEN)
        .POST(BodyPublishers.ofString(json)).build(), BodyHandlers.ofString());
  }

  private HttpResponse<String> delete(final String path) throws Exception {
    return client.send(HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Authorization", "Bearer " + ADMIN_TOKEN)
        .DELETE().build(), BodyHandlers.ofString());
  }
}

package com.codeheadsystems.miniidp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import tools.jackson.databind.JsonNode;
import tools.jackson.dataformat.yaml.YAMLMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Proves the served OpenAPI spec stays in lock-step with the implementation: every path+method the
 * spec documents must actually resolve on the live server (no 404/405), so the published contract
 * can't silently drift from the routes.
 */
class OpenApiContractTest {

  private IdpServer server;
  private HttpClient client;
  private String baseUrl;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws IOException {
    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    server = IdpServer.create(config, "admin", Clock.systemUTC());
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
  void servedSpecIsParseableAndItsPathsResolve() throws Exception {
    final HttpResponse<String> specResponse = get("/openapi.yaml");
    assertEquals(200, specResponse.statusCode());
    assertTrue(specResponse.headers().firstValue("Content-Type").orElse("").contains("yaml"));

    final JsonNode spec = new YAMLMapper().readTree(specResponse.body());
    assertEquals("3.1.0", spec.get("openapi").asText());
    final JsonNode paths = spec.get("paths");

    // Sanity: the contract must document the load-bearing endpoints.
    final List<String> documented = new ArrayList<>();
    // Jackson 3: JsonNode.fieldNames() was removed; properties() yields name/value entries.
    paths.properties().forEach(entry -> documented.add(entry.getKey()));
    assertTrue(documented.contains("/oauth/token"));
    assertTrue(documented.contains("/.well-known/jwks.json"));
    assertTrue(documented.contains("/.well-known/idp-configuration"));
    assertTrue(documented.contains("/admin/clients"));

    // Every documented path+method must resolve on the live server (never 404/405).
    final Iterator<Map.Entry<String, JsonNode>> pathEntries = paths.properties().iterator();
    while (pathEntries.hasNext()) {
      final Map.Entry<String, JsonNode> pathEntry = pathEntries.next();
      final String concretePath = pathEntry.getKey().replaceAll("\\{[^}]+}", "probe");
      for (final Map.Entry<String, JsonNode> methodEntry : pathEntry.getValue().properties()) {
        final String method = methodEntry.getKey().toUpperCase();
        final int status = probe(method, concretePath);
        assertNotEquals(404, status, method + " " + concretePath + " is documented but not routed");
        assertNotEquals(405, status, method + " " + concretePath + " is documented with the wrong method");
      }
    }
  }

  @Test
  void specIsAlsoServedAsJson() throws Exception {
    final HttpResponse<String> response = get("/openapi.json");
    assertEquals(200, response.statusCode());
    final JsonNode spec = new tools.jackson.databind.ObjectMapper().readTree(response.body());
    assertEquals("mini-idp", spec.get("info").get("title").asText());
  }

  private int probe(final String method, final String path) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path));
    // Bodyless for GET/DELETE; an empty body for POST/PUT is enough to reach the route (it may
    // then fail validation with 400/401, which still proves the route exists).
    switch (method) {
      case "GET" -> builder.GET();
      case "DELETE" -> builder.DELETE();
      default -> builder.method(method, BodyPublishers.ofString(""))
          .header("Content-Type", "application/json");
    }
    return client.send(builder.build(), BodyHandlers.ofString()).statusCode();
  }

  private HttpResponse<String> get(final String path) throws Exception {
    return client.send(HttpRequest.newBuilder(URI.create(baseUrl + path)).GET().build(),
        BodyHandlers.ofString());
  }
}

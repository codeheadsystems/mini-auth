package com.codeheadsystems.miniconsole.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.dataformat.yaml.YAMLMapper;

/**
 * Proves the console's served OpenAPI spec stays in lock-step with the routes: every path+method the
 * spec documents must actually resolve on the live console (no 404/405), so the published contract for
 * the read-only {@code /api} surface can't silently drift. The {@code /api/*} paths are bearer-guarded
 * (a probe with no token gets 401, which still resolves), so the contract check is unaffected by auth.
 */
class OpenApiContractTest {

  private static final String TOKEN = "test-console-token";

  private ConsoleServer server;
  private HttpClient client;
  private String baseUrl;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws IOException {
    final ConsoleConfig config = ConsoleConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    server = ConsoleServer.create(config, TOKEN, Clock.systemUTC());
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
    assertEquals("3.1.0", spec.get("openapi").asString());
    final JsonNode paths = spec.get("paths");

    final List<String> documented = new ArrayList<>();
    paths.properties().forEach(entry -> documented.add(entry.getKey()));
    assertTrue(documented.contains("/health"));
    assertTrue(documented.contains("/api/health"));
    assertTrue(documented.contains("/api/harness"));

    for (final Map.Entry<String, JsonNode> pathEntry : paths.properties()) {
      final String concretePath = pathEntry.getKey().replaceAll("\\{[^}]+}", "probe");
      for (final Map.Entry<String, JsonNode> methodEntry : pathEntry.getValue().properties()) {
        final String method = methodEntry.getKey();
        if (!isHttpMethod(method)) {
          continue;
        }
        final int status = probe(method.toUpperCase(), concretePath);
        assertNotEquals(404, status, method + " " + concretePath + " is documented but not routed");
        assertNotEquals(405, status, method + " " + concretePath + " is documented with the wrong method");
      }
    }
  }

  @Test
  void specIsAlsoServedAsJson() throws Exception {
    final HttpResponse<String> response = get("/openapi.json");
    assertEquals(200, response.statusCode());
    final JsonNode spec = new ObjectMapper().readTree(response.body());
    assertEquals("mini-console", spec.get("info").get("title").asString());
  }

  @Test
  void docsPageIsServedOffline() throws Exception {
    assertEquals(200, get("/docs").statusCode());
    assertEquals(200, get("/docs/swagger-ui.css").statusCode());
    assertEquals(200, get("/docs/swagger-ui-bundle.js").statusCode());
  }

  private static boolean isHttpMethod(final String key) {
    return switch (key) {
      case "get", "put", "post", "delete", "patch", "head", "options" -> true;
      default -> false;
    };
  }

  private int probe(final String method, final String path) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path));
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

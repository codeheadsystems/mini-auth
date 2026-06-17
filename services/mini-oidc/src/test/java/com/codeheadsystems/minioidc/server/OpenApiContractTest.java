package com.codeheadsystems.minioidc.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minioidc.auth.PasskeyStack;
import com.codeheadsystems.minioidc.directory.InMemoryUserDirectory;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.spi.ClockProvider;
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
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Proves the served OpenAPI spec stays in lock-step with the implementation: every documented
 * path+method resolves on the live server (no 404/405), so the published contract can't drift.
 */
class OpenApiContractTest {

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
    server = OidcServer.create(config, "admin", new InMemoryUserDirectory(),
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
  void servedSpecIsParseableAndItsPathsResolve() throws Exception {
    final HttpResponse<String> specResponse = get("/openapi.yaml");
    assertEquals(200, specResponse.statusCode());
    final JsonNode spec = new YAMLMapper().readTree(specResponse.body());
    assertEquals("3.1.0", spec.get("openapi").asText());
    final JsonNode paths = spec.get("paths");
    assertTrue(paths.has("/authorize"));
    assertTrue(paths.has("/token"));
    assertTrue(paths.has("/userinfo"));
    assertTrue(paths.has("/.well-known/openid-configuration"));

    for (final Map.Entry<String, JsonNode> pathEntry : paths.properties()) {
      final String concretePath = pathEntry.getKey().replaceAll("\\{[^}]+}", "probe");
      for (final Map.Entry<String, JsonNode> methodEntry : pathEntry.getValue().properties()) {
        if (!isHttpMethod(methodEntry.getKey())) {
          continue;
        }
        final int status = probe(methodEntry.getKey().toUpperCase(), concretePath);
        assertNotEquals(404, status, methodEntry.getKey() + " " + concretePath + " documented but not routed");
        assertNotEquals(405, status, methodEntry.getKey() + " " + concretePath + " wrong method");
      }
    }
  }

  @Test
  void specIsAlsoServedAsJson() throws Exception {
    final JsonNode spec = new tools.jackson.databind.ObjectMapper().readTree(get("/openapi.json").body());
    assertEquals("mini-oidc", spec.get("info").get("title").asText());
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
      default -> builder.method(method, BodyPublishers.ofString("")).header("Content-Type", "application/json");
    }
    return client.send(builder.build(), BodyHandlers.ofString()).statusCode();
  }

  private HttpResponse<String> get(final String path) throws Exception {
    return client.send(HttpRequest.newBuilder(URI.create(baseUrl + path)).GET().build(),
        BodyHandlers.ofString());
  }
}

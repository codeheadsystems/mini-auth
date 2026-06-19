package com.codeheadsystems.miniconsole.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Slice 8 tests for the read-only JSON {@code /api} surface and the harness "run all" summary. They
 * prove the {@code /api/*} endpoints are guarded by the console bearer token (401 without it, 200 with
 * it), that the rollup and catalog report the wired services/exercises, and that "run all" renders a
 * pass/skip/fail tally without needing (or leaking) any credential.
 */
class ConsoleApiTest {

  private static final String TOKEN = "test-console-token";

  private ConsoleServer server;
  private HttpClient client;
  private String baseUrl;

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void apiHealth_requiresTheConsoleBearerToken(@TempDir final Path dir) throws Exception {
    start(dir);
    assertEquals(401, get("/api/health", null).statusCode());
  }

  @Test
  void apiHealth_withToken_rollsUpEveryService(@TempDir final Path dir) throws Exception {
    start(dir);
    final HttpResponse<String> response = get("/api/health", "Bearer " + TOKEN);
    assertEquals(200, response.statusCode());
    final String body = response.body();
    assertTrue(body.contains("mini-directory"));
    assertTrue(body.contains("mini-gateway"));
    assertTrue(body.contains("not configured"));
  }

  @Test
  void apiHarness_withToken_listsTheExercises(@TempDir final Path dir) throws Exception {
    start(dir);
    final HttpResponse<String> response = get("/api/harness", "Bearer " + TOKEN);
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("gateway-verify"));
    assertTrue(response.body().contains("available"));
  }

  @Test
  void runAll_summarizesWithoutCredentials(@TempDir final Path dir) throws Exception {
    server = ConsoleServer.create(
        ConsoleConfig.resolve(new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of()),
        TOKEN, null, null, null, null, new FakeOidcClient(), new FakeGatewayClient(), Clock.systemUTC());
    server.start();
    baseUrl = "http://127.0.0.1:" + server.address().getPort();
    client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    final String sessionCookie = session();
    final String csrf = cookie(get("/harness", sessionCookie), Cookies.CSRF);
    final HttpResponse<String> response = post("/harness/run-all", sessionCookie, csrf, "csrf=" + csrf);
    assertEquals(200, response.statusCode());
    final String body = response.body();
    assertTrue(body.contains("passed"));
    assertTrue(body.contains("skipped"));
    // The credential-needing token flows are reported, not silently dropped.
    assertTrue(body.contains("Machine-to-machine token"));
  }

  private void start(final Path dir) throws IOException {
    server = ConsoleServer.create(
        ConsoleConfig.resolve(new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of()),
        TOKEN, Clock.systemUTC());
    server.start();
    baseUrl = "http://127.0.0.1:" + server.address().getPort();
    client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
  }

  private HttpResponse<String> get(final String path, final String authorization) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET();
    if (authorization != null) {
      if (authorization.startsWith("Bearer ")) {
        builder.header("Authorization", authorization);
      } else {
        builder.header("Cookie", authorization);
      }
    }
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  private HttpResponse<String> post(final String path, final String sessionCookie, final String csrf,
                                    final String body) throws Exception {
    final HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", sessionCookie + "; " + Cookies.CSRF + "=" + csrf)
        .POST(BodyPublishers.ofString(body))
        .build();
    return client.send(request, BodyHandlers.ofString());
  }

  private String session() throws Exception {
    final HttpResponse<String> form = get("/login", null);
    final String csrf = cookie(form, Cookies.CSRF);
    final HttpRequest login = HttpRequest.newBuilder(URI.create(baseUrl + "/login"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", Cookies.CSRF + "=" + csrf)
        .POST(BodyPublishers.ofString("csrf=" + csrf + "&token=" + TOKEN))
        .build();
    final HttpResponse<String> response = client.send(login, BodyHandlers.ofString());
    final String sessionId = cookie(response, Cookies.SESSION);
    assertNotNull(sessionId);
    return Cookies.SESSION + "=" + sessionId;
  }

  private static String cookie(final HttpResponse<?> response, final String name) {
    for (final String setCookie : response.headers().allValues("set-cookie")) {
      final String prefix = name + "=";
      if (setCookie.startsWith(prefix)) {
        final int semi = setCookie.indexOf(';');
        return setCookie.substring(prefix.length(), semi < 0 ? setCookie.length() : semi);
      }
    }
    return null;
  }
}

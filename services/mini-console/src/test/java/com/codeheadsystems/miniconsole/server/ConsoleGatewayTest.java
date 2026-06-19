package com.codeheadsystems.miniconsole.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
 * Slice 7 mini-gateway tests: a live console wired to a <b>fake</b> {@code MiniGatewayClient} (no real
 * gateway booted). They prove the gateway exercise is listed and session-guarded, that the no-bearer
 * run verifies the anonymous-denial branch and honestly SKIPs the allow/forbid branches, that a run
 * with a bearer drives all branches without ever leaking the token to the page, that a CSRF-less POST
 * is rejected, that the Dashboard shows mini-gateway live, and that the page degrades when no gateway
 * is configured.
 */
class ConsoleGatewayTest {

  private static final String TOKEN = "test-console-token";
  private static final String BEARER = "operator-supplied-access-token";

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
  void gatewayHarness_requiresSession(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeGatewayClient());
    final HttpResponse<String> response = post("/harness/gateway-verify/run", null, "x", "csrf=x&path=/");
    assertEquals(302, response.statusCode());
  }

  @Test
  void gatewayHarness_listsTheExercise(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeGatewayClient());
    final String body = get("/harness", session()).body();
    assertTrue(body.contains("Gateway forward-auth"));
  }

  @Test
  void runGateway_anonymousOnly_skipsAuthBranches(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeGatewayClient());
    final String sessionCookie = session();
    final String csrf = freshCsrf(sessionCookie);
    final HttpResponse<String> response = post("/harness/gateway-verify/run", sessionCookie, csrf,
        "csrf=" + csrf + "&path=/app");
    assertEquals(200, response.statusCode());
    // The anonymous-denial branch ran; the allow/forbid branches were honestly skipped.
    assertTrue(response.body().contains("PASS"));
    assertTrue(response.body().contains("SKIP"));
  }

  @Test
  void runGateway_withBearer_passesAndNeverLeaksTheSecret(@TempDir final Path dir) throws Exception {
    final FakeGatewayClient gateway = new FakeGatewayClient();
    startWith(dir, gateway);
    final String sessionCookie = session();
    final String csrf = freshCsrf(sessionCookie);
    final HttpResponse<String> response = post("/harness/gateway-verify/run", sessionCookie, csrf,
        "csrf=" + csrf + "&path=/app&bearerToken=" + BEARER + "&scopePath=/forbidden/area");
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("AUTHORIZED"));
    assertTrue(response.body().contains("FORBIDDEN"));
    // The bearer reached the client but is NEVER rendered to the page.
    assertEquals(BEARER, gateway.lastBearer);
    assertFalse(response.body().contains(BEARER), "the access token must never appear on the page");
  }

  @Test
  void runGateway_csrfReject(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeGatewayClient());
    final String sessionCookie = session();
    final HttpResponse<String> response = post("/harness/gateway-verify/run", sessionCookie,
        "wrong-csrf", "csrf=mismatch&path=/");
    assertEquals(400, response.statusCode());
  }

  @Test
  void dashboard_showsGatewayLive(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeGatewayClient());
    final String body = get("/", session()).body();
    assertTrue(body.contains("mini-gateway"));
    assertTrue(body.contains("healthy"));
  }

  @Test
  void gateway_whenNotConfigured_saysSo(@TempDir final Path dir) throws Exception {
    startWith(dir, null);
    final String sessionCookie = session();
    final String csrf = cookie(get("/harness", sessionCookie), Cookies.CSRF);
    final HttpResponse<String> response = post("/harness/gateway-verify/run", sessionCookie, csrf,
        "csrf=" + csrf + "&path=/");
    assertTrue(response.body().contains("No services are configured"));
  }

  private void startWith(final Path dir, final FakeGatewayClient gateway) throws IOException {
    final ConsoleConfig config = ConsoleConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    server = ConsoleServer.create(config, TOKEN, null, null, null, null, null, gateway, Clock.systemUTC());
    server.start();
    baseUrl = "http://127.0.0.1:" + server.address().getPort();
    client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
  }

  private HttpResponse<String> get(final String path, final String cookie) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET();
    if (cookie != null) {
      builder.header("Cookie", cookie);
    }
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  private HttpResponse<String> post(final String path, final String sessionCookie, final String csrf,
                                    final String body) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(BodyPublishers.ofString(body));
    final String cookie = sessionCookie == null ? Cookies.CSRF + "=" + csrf
        : sessionCookie + "; " + Cookies.CSRF + "=" + csrf;
    builder.header("Cookie", cookie);
    return client.send(builder.build(), BodyHandlers.ofString());
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

  private String freshCsrf(final String sessionCookie) throws Exception {
    return cookie(get("/harness", sessionCookie), Cookies.CSRF);
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

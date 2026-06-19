package com.codeheadsystems.miniconsole.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Live in-process tests for the Slice 0 console: a real {@link ConsoleServer} bound to an ephemeral
 * port, driven over the loopback with {@link HttpClient} (redirects disabled so 302s are asserted).
 *
 * <p>The console token is a fixed test constant passed only in request bodies; it is never asserted
 * by value.
 */
class ConsoleServerTest {

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
    client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
  }

  @AfterEach
  void tearDown() {
    server.stop();
  }

  @Test
  void health_isPublic() throws Exception {
    final HttpResponse<String> response = get("/health", null);
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("ok"));
  }

  @Test
  void dashboard_requiresSession() throws Exception {
    final HttpResponse<String> response = get("/", null);
    assertEquals(302, response.statusCode());
    assertEquals("/login", response.headers().firstValue("location").orElseThrow());
  }

  @Test
  void login_happyPath_thenDashboard() throws Exception {
    final String csrf = csrfFrom(get("/login", null));
    final HttpResponse<String> login = postForm("/login", "csrf=" + csrf + "&token=" + TOKEN,
        Cookies.CSRF + "=" + csrf);
    assertEquals(302, login.statusCode());
    assertEquals("/", login.headers().firstValue("location").orElseThrow());
    final String sessionId = cookie(login, Cookies.SESSION);
    assertNotNull(sessionId);

    final HttpResponse<String> dashboard = get("/", Cookies.SESSION + "=" + sessionId);
    assertEquals(200, dashboard.statusCode());
    assertTrue(dashboard.body().contains("mini-console"));
    assertTrue(dashboard.body().contains("console-admin"));
  }

  @Test
  void login_wrongToken_noOracle() throws Exception {
    final String csrf = csrfFrom(get("/login", null));
    final HttpResponse<String> login = postForm("/login", "csrf=" + csrf + "&token=wrong-token",
        Cookies.CSRF + "=" + csrf);
    // Re-rendered login, no session established, single generic message (no oracle).
    assertEquals(200, login.statusCode());
    assertNull(cookie(login, Cookies.SESSION));
    assertTrue(login.body().contains("Sign-in failed."));
  }

  @Test
  void login_csrfReject() throws Exception {
    final String csrf = csrfFrom(get("/login", null));
    final HttpResponse<String> login = postForm("/login", "csrf=mismatch&token=" + TOKEN,
        Cookies.CSRF + "=" + csrf);
    assertEquals(400, login.statusCode());
    assertNull(cookie(login, Cookies.SESSION));
  }

  @Test
  void logout_clearsSession() throws Exception {
    final String sessionId = signIn();
    // Re-fetch the dashboard to get a fresh CSRF for the logout form.
    final HttpResponse<String> dashboard = get("/", Cookies.SESSION + "=" + sessionId);
    final String csrf = cookie(dashboard, Cookies.CSRF);
    final HttpResponse<String> logout = postForm("/logout", "csrf=" + csrf,
        Cookies.SESSION + "=" + sessionId + "; " + Cookies.CSRF + "=" + csrf);
    assertEquals(302, logout.statusCode());
    assertEquals("/login", logout.headers().firstValue("location").orElseThrow());

    // The destroyed session no longer authorizes the dashboard.
    assertEquals(302, get("/", Cookies.SESSION + "=" + sessionId).statusCode());
  }

  @Test
  void dashboard_isHonest_aboutUnwiredClients() throws Exception {
    final HttpResponse<String> dashboard = get("/", Cookies.SESSION + "=" + signIn());
    assertEquals(200, dashboard.statusCode());
    assertTrue(dashboard.body().contains("client not wired yet"));
  }

  @Test
  void unknownPath_is404() throws Exception {
    assertEquals(404, get("/nope", null).statusCode());
  }

  // --- helpers -------------------------------------------------------------------------------

  /** Run the full login flow and return the established session id. */
  private String signIn() throws Exception {
    final String csrf = csrfFrom(get("/login", null));
    final HttpResponse<String> login = postForm("/login", "csrf=" + csrf + "&token=" + TOKEN,
        Cookies.CSRF + "=" + csrf);
    final String sessionId = cookie(login, Cookies.SESSION);
    assertNotNull(sessionId);
    return sessionId;
  }

  private HttpResponse<String> get(final String path, final String cookie) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET();
    if (cookie != null) {
      builder.header("Cookie", cookie);
    }
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  private HttpResponse<String> postForm(final String path, final String body, final String cookie)
      throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(body));
    if (cookie != null) {
      builder.header("Cookie", cookie);
    }
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  private static String csrfFrom(final HttpResponse<String> response) {
    final String value = cookie(response, Cookies.CSRF);
    assertNotNull(value, "expected a CSRF cookie on the login form");
    return value;
  }

  /** @return the value of the named cookie from a response's Set-Cookie headers, or null. */
  private static String cookie(final HttpResponse<?> response, final String name) {
    for (final String setCookie : response.headers().allValues("set-cookie")) {
      final String prefix = name + "=";
      if (setCookie.startsWith(prefix)) {
        final int semi = setCookie.indexOf(';');
        final String value = setCookie.substring(prefix.length(), semi < 0 ? setCookie.length() : semi);
        // A cleared cookie (logout) has an empty value — report it as absent for the callers here.
        return value.isEmpty() ? null : value;
      }
    }
    return null;
  }
}

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
 * Slice 6 mini-oidc tests: a live console wired to a <b>fake</b> {@code MiniOidcClient} (no real OP
 * booted). They prove the Clients page requires a session, lists clients + the register form,
 * registers a client and shows the one-time secret <b>once</b> (absent on a later page), rejects a
 * CSRF-less POST, the OIDC harness flow renders an honest SKIP, the oidc key-rotation route reaches
 * the client, the Dashboard shows mini-oidc live, and the page degrades when no OP is configured.
 */
class ConsoleOidcTest {

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
  void clients_requiresSession(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeOidcClient());
    assertEquals(302, get("/clients", null).statusCode());
  }

  @Test
  void clients_listsAndShowsRegisterForm(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeOidcClient());
    final String body = get("/clients", session()).body();
    assertTrue(body.contains("Register a client"));
  }

  @Test
  void register_confidentialClient_showsSecretOnce(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeOidcClient());
    final String sessionCookie = session();
    final String csrf = freshCsrf(sessionCookie);
    final HttpResponse<String> response = post("/clients", sessionCookie, csrf,
        "csrf=" + csrf + "&name=demo&redirectUris=https://app/cb&scopes=openid&confidential=true");
    assertEquals(200, response.statusCode());
    // The one-time secret is shown exactly once, in the banner.
    assertTrue(response.body().contains("secret-value"));
    assertTrue(response.body().contains(FakeOidcClient.SECRET));
    // A subsequent page never shows it again.
    assertFalse(get("/clients", sessionCookie).body().contains(FakeOidcClient.SECRET));
  }

  @Test
  void register_csrfReject(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeOidcClient());
    final String sessionCookie = session();
    final HttpResponse<String> response = post("/clients", sessionCookie, "wrong-csrf",
        "csrf=mismatch&name=demo&redirectUris=https://app/cb&scopes=openid");
    assertEquals(400, response.statusCode());
  }

  @Test
  void clients_whenNotConfigured_saysSo(@TempDir final Path dir) throws Exception {
    startWith(dir, null);
    assertTrue(get("/clients", session()).body().contains("not configured"));
  }

  @Test
  void oidcHarness_skipsTheInteractiveLogin(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeOidcClient());
    final String sessionCookie = session();
    final String csrf = freshCsrf(sessionCookie);
    final HttpResponse<String> response = post("/harness/oidc-pkce/run", sessionCookie, csrf,
        "csrf=" + csrf + "&clientId=client-1&redirectUri=https://app/cb&scope=openid");
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("SKIP"), "the interactive login is honestly skipped");
  }

  @Test
  void oidcKeyRotation_reachesTheClient(@TempDir final Path dir) throws Exception {
    final FakeOidcClient oidc = new FakeOidcClient();
    startWith(dir, oidc);
    final String sessionCookie = session();
    final String csrf = cookie(get("/keys", sessionCookie), Cookies.CSRF);
    final HttpResponse<String> response = post("/keys/oidc/rotate", sessionCookie, csrf,
        "csrf=" + csrf);
    assertEquals(302, response.statusCode());
    assertEquals(1, oidc.rotateCalls);
  }

  @Test
  void dashboard_showsOidcLive(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeOidcClient());
    final String body = get("/", session()).body();
    assertTrue(body.contains("/clients"), "the mini-oidc row links to the Clients page");
    assertTrue(body.contains("mini-oidc"));
  }

  private void startWith(final Path dir, final FakeOidcClient oidc) throws IOException {
    final ConsoleConfig config = ConsoleConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    server = ConsoleServer.create(config, TOKEN, null, null, null, null, oidc, Clock.systemUTC());
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

  private String freshCsrf(final String sessionCookie) throws Exception {
    return cookie(get("/clients", sessionCookie), Cookies.CSRF);
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

package com.codeheadsystems.miniconsole.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniidp.client.MiniIdpClient;
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
 * Slice 3 Audit + Harness tests: a live console wired to a <b>fake</b> {@link MiniIdpClient} (no real
 * IDP booted). They prove the pages require a session, the audit log renders, the m2m exercise runs
 * and PASSes (the fake's token verifies offline against its own JWKS), the run POST is CSRF-guarded,
 * the rendered result never leaks the supplied secret, and both pages degrade honestly when no IDP is
 * configured.
 */
class ConsoleHarnessAuditTest {

  private static final String TOKEN = "test-console-token";
  private static final String CLIENT_SECRET = "the-operators-secret";

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
  void audit_requiresSession(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeIdpClient());
    assertEquals(302, get("/audit", null).statusCode());
  }

  @Test
  void audit_rendersEntries(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeIdpClient());
    final String body = get("/audit", session()).body();
    assertTrue(body.contains("token.issued"));
  }

  @Test
  void audit_whenIdpUnavailable_degradesWithoutOracle(@TempDir final Path dir) throws Exception {
    final FakeIdpClient idp = new FakeIdpClient();
    idp.failAudit = true;
    startWith(dir, idp);
    final String body = get("/audit", session()).body();
    assertTrue(body.contains("unavailable"));
  }

  @Test
  void audit_whenNotConfigured_saysSo(@TempDir final Path dir) throws Exception {
    startWith(dir, null);
    assertTrue(get("/audit", session()).body().contains("No mini-idp is configured"));
  }

  @Test
  void harness_listsTheM2mExercise(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeIdpClient());
    assertTrue(get("/harness", session()).body().contains("Machine-to-machine"));
  }

  @Test
  void harness_whenNotConfigured_saysSo(@TempDir final Path dir) throws Exception {
    startWith(dir, null);
    // With neither mini-idp nor mini-ca wired, the harness reports no configured backends.
    assertTrue(get("/harness", session()).body().contains("No services are configured for the harness"));
  }

  @Test
  void dashboard_showsIdpRowLive(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeIdpClient());
    final String body = get("/", session()).body();
    assertTrue(body.contains("mini-idp"));
    assertTrue(body.contains("healthy"));
  }

  @Test
  void runM2m_csrfReject(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeIdpClient());
    final String session = session();
    // POST with a session but a wrong CSRF token.
    final HttpResponse<String> response = post("/harness/m2m-token/run", session, "wrong-csrf",
        "clientId=svc_demo&clientSecret=" + CLIENT_SECRET);
    assertEquals(400, response.statusCode());
  }

  @Test
  void runM2m_passesAndNeverLeaksTheSecret(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeIdpClient());
    final String session = session();
    final String csrf = freshCsrf(session);
    final HttpResponse<String> response = post("/harness/m2m-token/run", session, csrf,
        "csrf=" + csrf + "&clientId=svc_demo&clientSecret=" + CLIENT_SECRET);
    assertEquals(200, response.statusCode());
    // The fake's token verifies offline against its own JWKS → the flow PASSes.
    assertTrue(response.body().contains("PASS"));
    // The operator's secret must never appear in the rendered result.
    assertFalse(response.body().contains(CLIENT_SECRET));
  }

  // ---- harness -------------------------------------------------------------------------------

  private void startWith(final Path dir, final MiniIdpClient idp) throws IOException {
    final ConsoleConfig config = ConsoleConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    server = ConsoleServer.create(config, TOKEN, null, idp, Clock.systemUTC());
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

  /** Sign in and return the session cookie string ({@code name=value}). */
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

  /** Fetch a fresh CSRF token (and its cookie) from an authenticated page. */
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

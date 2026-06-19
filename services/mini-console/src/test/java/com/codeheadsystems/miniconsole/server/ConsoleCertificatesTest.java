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
 * Slice 5 Certificates tests: a live console wired to a <b>fake</b> {@link com.codeheadsystems.minica.client.MiniCaClient}
 * (no real CA booted). They prove the page requires a session, renders the issuance log + revocation
 * list, issues from a CSR, revokes through a confirm step, that every POST is CSRF-guarded, that the
 * page degrades without an oracle, and that the Dashboard row goes live.
 */
class ConsoleCertificatesTest {

  private static final String TOKEN = "test-console-token";

  private ConsoleServer server;
  private HttpClient client;
  private String baseUrl;
  private FakeCaClient ca;

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void certificates_requiresSession(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeCaClient());
    assertEquals(302, get("/certificates", null).statusCode());
  }

  @Test
  void certificates_rendersOverview(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeCaClient());
    final String body = get("/certificates", session()).body();
    assertTrue(body.contains("Issuance log"));
    assertTrue(body.contains("Revocation list"));
  }

  @Test
  void certificates_whenNotConfigured_saysSo(@TempDir final Path dir) throws Exception {
    startWith(dir, null);
    assertTrue(get("/certificates", session()).body().contains("No mini-ca is configured"));
  }

  @Test
  void certificates_whenUnavailable_degradesWithoutOracle(@TempDir final Path dir) throws Exception {
    final FakeCaClient failing = new FakeCaClient();
    failing.failCalls = true;
    startWith(dir, failing);
    assertTrue(get("/certificates", session()).body().contains("unavailable"));
  }

  @Test
  void issue_csrfReject(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeCaClient());
    final HttpResponse<String> response =
        post("/certificates/issue", session(), "wrong-csrf", "csr=dummycsr");
    assertEquals(400, response.statusCode());
  }

  @Test
  void issue_rendersTheIssuedCertificate(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeCaClient());
    final String session = session();
    final String csrf = freshCsrf(session);
    final HttpResponse<String> response =
        post("/certificates/issue", session, csrf, "csrf=" + csrf + "&csr=dummycsr");
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("Issued"));
    assertTrue(response.body().contains("serial-1"));
  }

  @Test
  void revoke_confirmStepThenRevokes(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeCaClient());
    final String session = session();
    // Issue a cert so there is a serial to revoke (one CSRF token for both the cookie and the body).
    final String issueCsrf = freshCsrf(session);
    post("/certificates/issue", session, issueCsrf, "csrf=" + issueCsrf + "&csr=dummycsr");
    // The confirm page (GET, no mutation) echoes the serial.
    assertTrue(get("/certificates/revoke/confirm?serial=serial-1", session).body().contains("serial-1"));
    // The actual revoke (POST) is CSRF-guarded and redirects.
    final String csrf = freshCsrf(session);
    final HttpResponse<String> response = post("/certificates/revoke", session, csrf,
        "csrf=" + csrf + "&serial=serial-1&reason=test");
    assertEquals(302, response.statusCode());
    assertTrue(ca.isRevoked("serial-1"));
  }

  @Test
  void revoke_csrfReject(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeCaClient());
    final HttpResponse<String> response =
        post("/certificates/revoke", session(), "wrong-csrf", "serial=serial-1");
    assertEquals(400, response.statusCode());
  }

  @Test
  void dashboard_showsCaRowLive(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeCaClient());
    final String body = get("/", session()).body();
    assertTrue(body.contains("mini-ca"));
    assertTrue(body.contains("healthy"));
  }

  @Test
  void harness_listsTheCertificateExercise(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeCaClient());
    assertTrue(get("/harness", session()).body().contains("Certificate lifecycle"));
  }

  // ---- harness -------------------------------------------------------------------------------

  private void startWith(final Path dir, final FakeCaClient caClient) throws IOException {
    this.ca = caClient;
    final ConsoleConfig config = ConsoleConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    server = ConsoleServer.create(config, TOKEN, null, null, null, caClient, Clock.systemUTC());
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
    return cookie(get("/certificates", sessionCookie), Cookies.CSRF);
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

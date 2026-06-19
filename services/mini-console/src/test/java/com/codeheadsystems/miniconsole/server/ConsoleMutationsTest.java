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
 * Slice 2 mutation tests: a live console wired to the capturing {@link FakeDirectory}, proving every
 * state-changing POST is session-required AND CSRF-guarded, that creating a service account shows the
 * one-time secret banner exactly once (and a later page does not), that delete has a confirm step,
 * and that a directory failure collapses to a generic page (no oracle). No secret is asserted by
 * value; the banner is checked structurally.
 */
class ConsoleMutationsTest {

  private static final String TOKEN = "test-console-token";

  private ConsoleServer server;
  private HttpClient client;
  private String baseUrl;
  private FakeDirectory fake;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws IOException {
    fake = new FakeDirectory();
    final ConsoleConfig config = ConsoleConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    server = ConsoleServer.create(config, TOKEN, fake, Clock.systemUTC());
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
  void createHuman_requiresSession() throws Exception {
    final HttpResponse<String> response = postNoCsrf("/identities/humans", null, "id=bob");
    assertEquals(302, response.statusCode());
    assertEquals("/login", response.headers().firstValue("location").orElseThrow());
  }

  @Test
  void createHuman_withoutCsrf_isRejected() throws Exception {
    final String session = signIn();
    final HttpResponse<String> response = postNoCsrf("/identities/humans", session, "id=bob");
    assertEquals(400, response.statusCode());
    assertNull(fake.createdHuman);
  }

  @Test
  void createHuman_withCsrf_callsClientAndRedirects() throws Exception {
    final String session = signIn();
    final HttpResponse<String> response = post("/identities/humans", session, "id=bob&admin=on");
    assertEquals(302, response.statusCode());
    assertEquals("/identities", response.headers().firstValue("location").orElseThrow());
    assertNotNull(fake.createdHuman);
    assertEquals("bob", fake.createdHuman.id());
    assertTrue(fake.createdHuman.admin());
  }

  @Test
  void createServiceAccount_showsSecretBannerExactlyOnce() throws Exception {
    final String session = signIn();
    final HttpResponse<String> created = post("/identities/service-accounts", session, "displayName=CI");
    assertEquals(200, created.statusCode());
    // The banner is present on the creation result (structural — we assert the secret *element* and
    // the warning text, never the secret value; note ".secret-value" also appears in shared CSS, so
    // we match the element tag, not the bare class name).
    assertTrue(created.body().contains("<code class=\"secret-value\">"));
    assertTrue(created.body().contains("will not be shown again"));

    // It is never re-served: a later authenticated page has no secret element (CSS rule aside).
    final HttpResponse<String> later = getAuth("/identities", session);
    assertFalse(later.body().contains("<code class=\"secret-value\">"));
    assertFalse(later.body().contains("will not be shown again"));
  }

  @Test
  void deleteAccount_hasConfirmStep_thenDeletes() throws Exception {
    final String session = signIn();
    // The confirm step is a GET page; nothing is deleted yet.
    final HttpResponse<String> confirm = getAuth("/identities/alice/delete", session);
    assertEquals(200, confirm.statusCode());
    assertTrue(confirm.body().contains("Really delete"));
    assertNull(fake.deletedAccountId);

    // The confirmed delete is a CSRF-guarded POST.
    final HttpResponse<String> deleted = post("/identities/alice/delete", session, "");
    assertEquals(302, deleted.statusCode());
    assertEquals("alice", fake.deletedAccountId);
  }

  @Test
  void deleteAccount_withoutCsrf_isRejected() throws Exception {
    final String session = signIn();
    final HttpResponse<String> response = postNoCsrf("/identities/alice/delete", session, "");
    assertEquals(400, response.statusCode());
    assertNull(fake.deletedAccountId);
  }

  @Test
  void updateAssignment_callsClientWithParsedForm() throws Exception {
    final String session = signIn();
    final HttpResponse<String> response = post("/identities/alice/assignment", session,
        "enabled=on&admin=on&roles=billing-reader&grants=ENCRYPT:ledger");
    assertEquals(302, response.statusCode());
    assertEquals("alice", fake.assignedId);
    assertTrue(fake.assignment.enabled());
    assertTrue(fake.assignment.admin());
    assertTrue(fake.assignment.roles().contains("billing-reader"));
    assertTrue(fake.assignment.grants().stream()
        .anyMatch(g -> g.action().equals("ENCRYPT") && g.resource().equals("ledger")));
  }

  @Test
  void mutationFailure_collapsesToGenericPage_noOracle() throws Exception {
    fake.failMutations = true;
    final String session = signIn();
    final HttpResponse<String> response = post("/identities/humans", session, "id=bob");
    // Not a 500/stack: a generic, no-detail page (the no-oracle collapse).
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("could not be reached or the request failed"));
    assertFalse(response.body().contains("internal_error"));
  }

  // --- harness -------------------------------------------------------------------------------

  /** POST a form with a valid double-submit CSRF token (cookie + matching field). */
  private HttpResponse<String> post(final String path, final String session, final String formBody)
      throws Exception {
    final String csrf = freshCsrf(session);
    final String body = formBody.isEmpty() ? "csrf=" + csrf : formBody + "&csrf=" + csrf;
    final HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", Cookies.SESSION + "=" + session + "; " + Cookies.CSRF + "=" + csrf)
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();
    return client.send(request, BodyHandlers.ofString());
  }

  /** POST without a CSRF token (no cookie, no field) — should be rejected (or redirected if no session). */
  private HttpResponse<String> postNoCsrf(final String path, final String session, final String formBody)
      throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(formBody));
    if (session != null) {
      builder.header("Cookie", Cookies.SESSION + "=" + session);
    }
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  private HttpResponse<String> getAuth(final String path, final String session) throws Exception {
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET();
    if (session != null) {
      builder.header("Cookie", Cookies.SESSION + "=" + session);
    }
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  /** Fetch a fresh CSRF cookie by rendering an authenticated page. */
  private String freshCsrf(final String session) throws Exception {
    return cookie(getAuth("/identities", session), Cookies.CSRF);
  }

  private String signIn() throws Exception {
    final HttpResponse<String> form = client.send(
        HttpRequest.newBuilder(URI.create(baseUrl + "/login")).GET().build(), BodyHandlers.ofString());
    final String csrf = cookie(form, Cookies.CSRF);
    final HttpRequest login = HttpRequest.newBuilder(URI.create(baseUrl + "/login"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", Cookies.CSRF + "=" + csrf)
        .POST(HttpRequest.BodyPublishers.ofString("csrf=" + csrf + "&token=" + TOKEN))
        .build();
    final String sessionId = cookie(client.send(login, BodyHandlers.ofString()), Cookies.SESSION);
    assertNotNull(sessionId);
    return sessionId;
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

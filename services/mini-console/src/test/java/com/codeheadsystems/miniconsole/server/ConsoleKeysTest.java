package com.codeheadsystems.miniconsole.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniconsole.kms.KeyGroupAdmin;
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
 * Slice 4 Keys tests: a live console wired to a <b>fake</b> {@link KeyGroupAdmin} and a fake
 * {@link MiniIdpClient} (no real KMS/IDP booted). They prove the page requires a session, lists key
 * groups, that every mutation is CSRF-guarded and reaches the port, that destroy goes through a
 * confirm step, that idp signing-key rotation reaches the client, and that failures degrade without
 * an oracle.
 */
class ConsoleKeysTest {

  private static final String TOKEN = "test-console-token";

  private ConsoleServer server;
  private HttpClient client;
  private String baseUrl;
  private FakeKeyGroupAdmin keys;
  private FakeIdpClient idp;

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void keys_requiresSession(@TempDir final Path dir) throws Exception {
    start(dir, new FakeKeyGroupAdmin(), new FakeIdpClient());
    assertEquals(302, get("/keys", null).statusCode());
  }

  @Test
  void keys_listsGroupsAndSigningKey(@TempDir final Path dir) throws Exception {
    start(dir, new FakeKeyGroupAdmin(), new FakeIdpClient());
    final String body = get("/keys", session()).body();
    assertTrue(body.contains("mini-kms key groups"));
    assertTrue(body.contains("billing"));
    assertTrue(body.contains("mini-idp signing key"));
    assertTrue(body.contains(FakeIdpClient.KID));
  }

  @Test
  void keys_whenKmsUnavailable_degradesWithoutOracle(@TempDir final Path dir) throws Exception {
    keys = new FakeKeyGroupAdmin();
    keys.fail = true;
    start(dir, keys, new FakeIdpClient());
    assertTrue(get("/keys", session()).body().contains("Unavailable"));
  }

  @Test
  void keys_whenKmsNotConfigured_saysSo(@TempDir final Path dir) throws Exception {
    start(dir, null, new FakeIdpClient());
    assertTrue(get("/keys", session()).body().contains("Not configured"));
  }

  @Test
  void createGroup_csrfReject(@TempDir final Path dir) throws Exception {
    start(dir, new FakeKeyGroupAdmin(), new FakeIdpClient());
    final HttpResponse<String> response =
        post("/keys/kms", session(), "wrong-csrf", "keyId=newgroup");
    assertEquals(400, response.statusCode());
    assertTrue(keys.created.isEmpty(), "no mutation must happen on a CSRF failure");
  }

  @Test
  void createGroup_callsPortAndRedirects(@TempDir final Path dir) throws Exception {
    start(dir, new FakeKeyGroupAdmin(), new FakeIdpClient());
    final String session = session();
    final String csrf = freshCsrf(session);
    final HttpResponse<String> response =
        post("/keys/kms", session, csrf, "csrf=" + csrf + "&keyId=newgroup");
    assertEquals(302, response.statusCode());
    assertEquals("/keys", response.headers().firstValue("location").orElse(null));
    assertTrue(keys.created.contains("newgroup"));
  }

  @Test
  void rotateGroup_callsPort(@TempDir final Path dir) throws Exception {
    start(dir, new FakeKeyGroupAdmin(), new FakeIdpClient());
    final String session = session();
    final String csrf = freshCsrf(session);
    post("/keys/kms/billing/rotate", session, csrf, "csrf=" + csrf);
    assertTrue(keys.rotated.contains("billing"));
  }

  @Test
  void disableVersion_callsPort(@TempDir final Path dir) throws Exception {
    start(dir, new FakeKeyGroupAdmin(), new FakeIdpClient());
    final String session = session();
    final String csrf = freshCsrf(session);
    post("/keys/kms/billing/disable", session, csrf, "csrf=" + csrf + "&version=1");
    assertTrue(keys.disabled.contains("billing:1"));
  }

  @Test
  void destroy_hasConfirmStepThenDestroys(@TempDir final Path dir) throws Exception {
    start(dir, new FakeKeyGroupAdmin(), new FakeIdpClient());
    final String session = session();
    // 1. The confirm page (GET) warns and does NOT destroy.
    final String confirm = get("/keys/kms/billing/destroy?version=1", session).body();
    assertTrue(confirm.contains("irreversible"));
    assertTrue(keys.destroyed.isEmpty(), "the confirm GET must not destroy");
    // 2. The confirmed POST destroys.
    final String csrf = freshCsrf(session);
    post("/keys/kms/billing/destroy", session, csrf, "csrf=" + csrf + "&version=1");
    assertTrue(keys.destroyed.contains("billing:1"));
  }

  @Test
  void kmsMutation_whenPortFails_degradesWithoutOracle(@TempDir final Path dir) throws Exception {
    keys = new FakeKeyGroupAdmin();
    keys.fail = true;
    start(dir, keys, new FakeIdpClient());
    final String session = session();
    final String csrf = freshCsrf(session);
    // A failed KMS op re-renders the Keys page (200) — no status/reason oracle.
    final HttpResponse<String> response =
        post("/keys/kms", session, csrf, "csrf=" + csrf + "&keyId=x");
    assertEquals(200, response.statusCode());
  }

  @Test
  void idpRotate_callsClientAndRedirects(@TempDir final Path dir) throws Exception {
    start(dir, new FakeKeyGroupAdmin(), new FakeIdpClient());
    final String session = session();
    final String csrf = freshCsrf(session);
    final HttpResponse<String> response =
        post("/keys/idp/rotate", session, csrf, "csrf=" + csrf);
    assertEquals(302, response.statusCode());
    assertEquals(1, idp.rotateCalls);
  }

  @Test
  void idpRotate_whenFails_degradesWithoutOracle(@TempDir final Path dir) throws Exception {
    idp = new FakeIdpClient();
    idp.failRotate = true;
    start(dir, new FakeKeyGroupAdmin(), idp);
    final String session = session();
    final String csrf = freshCsrf(session);
    final HttpResponse<String> response =
        post("/keys/idp/rotate", session, csrf, "csrf=" + csrf);
    assertEquals(200, response.statusCode());
  }

  @Test
  void dashboard_showsKmsRowLive(@TempDir final Path dir) throws Exception {
    start(dir, new FakeKeyGroupAdmin(), new FakeIdpClient());
    final String body = get("/", session()).body();
    assertTrue(body.contains("mini-kms"));
    assertTrue(body.contains("healthy"));
  }

  // ---- harness -------------------------------------------------------------------------------

  private void start(final Path dir, final FakeKeyGroupAdmin keyAdmin, final FakeIdpClient idpClient)
      throws IOException {
    this.keys = keyAdmin;
    this.idp = idpClient;
    final ConsoleConfig config = ConsoleConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    server = ConsoleServer.create(config, TOKEN, null, idpClient, keyAdmin, Clock.systemUTC());
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
    return cookie(get("/keys", sessionCookie), Cookies.CSRF);
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

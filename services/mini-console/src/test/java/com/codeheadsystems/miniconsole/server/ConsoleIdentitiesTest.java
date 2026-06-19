package com.codeheadsystems.miniconsole.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minidirectory.client.MiniDirectoryClient;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Slice 1 Identities tests: a live console wired to a <b>fake</b> {@link MiniDirectoryClient} (so no
 * real directory is booted), proving the read-only pages render what the client returns, require a
 * session, and degrade honestly when no directory is configured.
 */
class ConsoleIdentitiesTest {

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
  void identities_requiresSession(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeDirectory());
    final HttpResponse<String> response = get("/identities", null);
    assertEquals(302, response.statusCode());
    assertEquals("/login", response.headers().firstValue("location").orElseThrow());
  }

  @Test
  void identities_listsPrincipalsGroupsAndRoles(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeDirectory());
    final String body = get("/identities", "session").body();
    assertTrue(body.contains("alice"));
    assertTrue(body.contains("billing-team"));
    assertTrue(body.contains("billing-reader"));
  }

  @Test
  void identityDetail_showsResolvedGrants(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeDirectory());
    final String body = get("/identities/alice", "session").body();
    assertTrue(body.contains("alice"));
    // The expanded grant (via group -> role) must appear in the resolved table.
    assertTrue(body.contains("DECRYPT"));
    assertTrue(body.contains("billing"));
  }

  @Test
  void dashboard_showsDirectoryRowLive(@TempDir final Path dir) throws Exception {
    startWith(dir, new FakeDirectory());
    final String body = get("/", "session").body();
    assertTrue(body.contains("mini-directory"));
    assertTrue(body.contains("healthy"));
  }

  @Test
  void identities_whenNotConfigured_saysSo(@TempDir final Path dir) throws Exception {
    startWith(dir, null);
    final String body = get("/identities", "session").body();
    assertTrue(body.contains("not configured"));
  }

  // --- harness -------------------------------------------------------------------------------

  /** Start a console wired (or not) to the given directory, and authenticate a session for reuse. */
  private void startWith(final Path dir, final MiniDirectoryClient directory) throws IOException {
    final ConsoleConfig config = ConsoleConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString()}, Map.of());
    server = ConsoleServer.create(config, TOKEN, directory, Clock.systemUTC());
    server.start();
    baseUrl = "http://127.0.0.1:" + server.address().getPort();
    client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
  }

  /** GET a path; pass cookie="session" to send a freshly-established session cookie, or null for none. */
  private HttpResponse<String> get(final String path, final String cookieMode) throws Exception {
    String cookie = null;
    if ("session".equals(cookieMode)) {
      cookie = Cookies.SESSION + "=" + signIn();
    } else if (cookieMode != null) {
      cookie = cookieMode;
    }
    final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET();
    if (cookie != null) {
      builder.header("Cookie", cookie);
    }
    return client.send(builder.build(), BodyHandlers.ofString());
  }

  private String signIn() throws Exception {
    final HttpResponse<String> form = rawGet("/login");
    final String csrf = cookie(form, Cookies.CSRF);
    final HttpRequest login = HttpRequest.newBuilder(URI.create(baseUrl + "/login"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", Cookies.CSRF + "=" + csrf)
        .POST(HttpRequest.BodyPublishers.ofString("csrf=" + csrf + "&token=" + TOKEN))
        .build();
    final HttpResponse<String> response = client.send(login, BodyHandlers.ofString());
    final String sessionId = cookie(response, Cookies.SESSION);
    assertNotNull(sessionId);
    return sessionId;
  }

  private HttpResponse<String> rawGet(final String path) throws Exception {
    return client.send(HttpRequest.newBuilder(URI.create(baseUrl + path)).GET().build(),
        BodyHandlers.ofString());
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

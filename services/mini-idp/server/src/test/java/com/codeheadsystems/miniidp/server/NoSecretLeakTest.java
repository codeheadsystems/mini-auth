package com.codeheadsystems.miniidp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Guards the "no secret material in logs" invariant: after a registration + token issuance flow,
 * neither the client secret, the issued access token, nor any private-key marker appears in the
 * captured logs or stdout/stderr.
 *
 * <p>It captures both the JUL stream that {@link System.Logger} delegates to and stdout/stderr,
 * since those are the only sinks the service writes to.
 */
class NoSecretLeakTest {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private IdpServer server;
  private HttpClient client;
  private String baseUrl;

  private final ByteArrayOutputStream capturedLog = new ByteArrayOutputStream();
  private Handler logHandler;
  private Logger rootLogger;
  private Level previousLevel;
  private PrintStream originalOut;
  private PrintStream originalErr;
  private ByteArrayOutputStream capturedOut;
  private ByteArrayOutputStream capturedErr;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws IOException {
    rootLogger = Logger.getLogger("");
    previousLevel = rootLogger.getLevel();
    rootLogger.setLevel(Level.ALL);
    logHandler = new Handler() {
      @Override
      public void publish(final LogRecord record) {
        capturedLog.writeBytes((String.valueOf(record.getMessage()) + "\n").getBytes(StandardCharsets.UTF_8));
      }

      @Override
      public void flush() {
      }

      @Override
      public void close() {
      }
    };
    logHandler.setLevel(Level.ALL);
    rootLogger.addHandler(logHandler);

    originalOut = System.out;
    originalErr = System.err;
    capturedOut = new ByteArrayOutputStream();
    capturedErr = new ByteArrayOutputStream();
    System.setOut(new PrintStream(capturedOut, true, StandardCharsets.UTF_8));
    System.setErr(new PrintStream(capturedErr, true, StandardCharsets.UTF_8));

    final ServerConfig config = ServerConfig.resolve(
        new String[] {"--port", "0", "--data-dir", dir.toString(),
            "--argon-memory-kib", "1024", "--argon-iterations", "1", "--argon-parallelism", "1"},
        Map.of());
    server = IdpServer.create(config, "admin-token", Clock.systemUTC());
    server.start();
    baseUrl = "http://127.0.0.1:" + server.address().getPort();
    client = HttpClient.newHttpClient();
  }

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.stop();
    }
    System.setOut(originalOut);
    System.setErr(originalErr);
    if (rootLogger != null && logHandler != null) {
      rootLogger.removeHandler(logHandler);
      rootLogger.setLevel(previousLevel);
    }
  }

  @Test
  void secretsDoNotAppearInLogsOrConsole() throws Exception {
    final HttpResponse<String> registration = postJson("/admin/clients",
        "{\"authorization\":{\"control\":false,\"groups\":[]}}", "admin-token");
    assertEquals(201, registration.statusCode());
    final JsonNode registered = MAPPER.readTree(registration.body());
    final String clientId = registered.get("clientId").asText();
    final String secret = registered.get("secret").asText();

    final String form = "grant_type=client_credentials&client_id=" + clientId
        + "&client_secret=" + java.net.URLEncoder.encode(secret, StandardCharsets.UTF_8);
    final HttpResponse<String> tokenResponse = client.send(
        HttpRequest.newBuilder(URI.create(baseUrl + "/oauth/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(BodyPublishers.ofString(form)).build(),
        BodyHandlers.ofString());
    assertEquals(200, tokenResponse.statusCode());
    final String accessToken = MAPPER.readTree(tokenResponse.body()).get("access_token").asText();

    final String allOutput = capturedLog.toString(StandardCharsets.UTF_8)
        + capturedOut.toString(StandardCharsets.UTF_8)
        + capturedErr.toString(StandardCharsets.UTF_8);

    assertFalse(allOutput.contains(secret), "client secret must never be logged");
    assertFalse(allOutput.contains(accessToken), "issued access token must never be logged");
    assertFalse(allOutput.contains("PRIVATE"), "no private-key material should be logged");
  }

  private HttpResponse<String> postJson(final String path, final String json, final String adminToken)
      throws Exception {
    return client.send(HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer " + adminToken)
        .POST(BodyPublishers.ofString(json)).build(), BodyHandlers.ofString());
  }
}

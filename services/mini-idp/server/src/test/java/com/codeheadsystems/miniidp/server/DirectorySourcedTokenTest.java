package com.codeheadsystems.miniidp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniidp.directory.HttpServiceAccountDirectory;
import com.codeheadsystems.minidirectory.server.DirectoryServer;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.service.TokenVerifier;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The capstone: a real mini-directory holds the service account, and mini-idp sources the client's
 * credentials and grants from it (over HTTP) at token issuance. Proves the token mini-idp produces
 * is identical in shape to the old local-registry path — same subject, same {@code grants} — and
 * that a bad/unknown credential still collapses to {@code invalid_client}.
 */
class DirectorySourcedTokenTest {

  private static final String ISSUER = "http://idp.test";
  private static final String AUDIENCE = "mini-kms";
  private static final String DIR_ADMIN = "dir-admin";
  private static final String IDP_ADMIN = "idp-admin";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private DirectoryServer directoryServer;
  private IdpServer idp;
  private HttpClient client;
  private String idpUrl;
  private String clientId;
  private String clientSecret;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws Exception {
    // 1. A real mini-directory.
    final com.codeheadsystems.minidirectory.server.ServerConfig dirConfig =
        com.codeheadsystems.minidirectory.server.ServerConfig.resolve(new String[] {
            "--port", "0", "--data-dir", dir.resolve("directory").toString(),
            "--argon-memory-kib", "1024", "--argon-iterations", "1", "--argon-parallelism", "1"}, Map.of());
    directoryServer = DirectoryServer.create(dirConfig, DIR_ADMIN);
    directoryServer.start();
    final String dirUrl = "http://127.0.0.1:" + directoryServer.address().getPort();
    client = HttpClient.newHttpClient();

    // 2. Create a service account in mini-directory, granted ENCRYPT/DECRYPT on key group "billing".
    final HttpResponse<String> created = client.send(HttpRequest.newBuilder(
            URI.create(dirUrl + "/admin/service-accounts"))
        .header("Content-Type", "application/json").header("Authorization", "Bearer " + DIR_ADMIN)
        .POST(BodyPublishers.ofString("{\"displayName\":\"svc\",\"grants\":["
            + "{\"action\":\"ENCRYPT\",\"resource\":\"billing\"},"
            + "{\"action\":\"DECRYPT\",\"resource\":\"billing\"}]}")).build(), BodyHandlers.ofString());
    assertEquals(201, created.statusCode(), created.body());
    final JsonNode body = MAPPER.readTree(created.body());
    clientId = body.get("id").asString();
    clientSecret = body.get("secret").asString();

    // 3. mini-idp, sourcing service accounts from that mini-directory over HTTP.
    final ServerConfig idpConfig = ServerConfig.resolve(new String[] {
        "--port", "0", "--data-dir", dir.resolve("idp").toString(),
        "--issuer", ISSUER, "--audience", AUDIENCE, "--directory-url", dirUrl}, Map.of());
    idp = IdpServer.create(idpConfig, IDP_ADMIN, new HttpServiceAccountDirectory(dirUrl, DIR_ADMIN),
        Clock.systemUTC());
    idp.start();
    idpUrl = "http://127.0.0.1:" + idp.address().getPort();
  }

  @AfterEach
  void tearDown() {
    if (idp != null) {
      idp.stop();
    }
    if (directoryServer != null) {
      directoryServer.stop();
    }
  }

  @Test
  void mniIdpIssuesAVerifiableTokenSourcedFromMiniDirectory() throws Exception {
    final HttpResponse<String> tokenResponse = requestToken(clientId, clientSecret);
    assertEquals(200, tokenResponse.statusCode(), tokenResponse.body());
    final String accessToken = MAPPER.readTree(tokenResponse.body()).get("access_token").asString();

    final JwkSet jwks = MAPPER.readValue(get(idpUrl + "/.well-known/jwks.json"), JwkSet.class);
    final TokenVerifier.Result result =
        new TokenVerifier(ISSUER, AUDIENCE, Clock.systemUTC(), 5).verify(accessToken, jwks, jti -> false);
    assertTrue(result.valid(), "the directory-sourced token must verify against the published JWKS");
    assertEquals(clientId, result.claims().subject(), "sub is the directory account id");
    // The grants resolved from mini-directory are reassembled into the same per-key-group claim shape.
    final var groups = result.claims().grants().groups();
    assertEquals("billing", groups.get(0).keyGroup());
    assertTrue(groups.get(0).operations().contains("ENCRYPT"));
    assertTrue(groups.get(0).operations().contains("DECRYPT"));
  }

  @Test
  void wrongSecretSourcedFromDirectoryStillCollapsesToInvalidClient() throws Exception {
    final HttpResponse<String> response = requestToken(clientId, "not-the-secret");
    assertEquals(401, response.statusCode());
    assertEquals("invalid_client", MAPPER.readTree(response.body()).get("error").asString());
  }

  private HttpResponse<String> requestToken(final String id, final String secret) throws Exception {
    final String form = "grant_type=client_credentials&client_id=" + enc(id) + "&client_secret=" + enc(secret);
    return client.send(HttpRequest.newBuilder(URI.create(idpUrl + "/oauth/token"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(BodyPublishers.ofString(form)).build(), BodyHandlers.ofString());
  }

  private String get(final String url) throws Exception {
    return client.send(HttpRequest.newBuilder(URI.create(url)).GET().build(), BodyHandlers.ofString()).body();
  }

  private static String enc(final String value) {
    return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}

package com.codeheadsystems.miniidp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minikms.auth.ApiTokenAuthenticator;
import com.codeheadsystems.minikms.client.KmsClient;
import com.codeheadsystems.minikms.client.KmsSigningKeyStore;
import com.codeheadsystems.minikms.keyring.LocalKeyring;
import com.codeheadsystems.minikms.kms.KmsRequestHandler;
import com.codeheadsystems.minikms.kms.KmsService;
import com.codeheadsystems.minikms.master.Argon2Settings;
import com.codeheadsystems.minikms.server.KmsServer;
import com.codeheadsystems.minipolicy.AllowAllPolicyEngine;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.service.TokenVerifier;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The recursive integration, end to end through mini-idp: with {@code --kms-*} configured, the IDP's
 * signing keys are wrapped under a mini-kms key group (no plaintext on disk), yet token issuance and
 * offline JWKS verification still work.
 */
class KmsBackedSigningTest {

  private static final String ISSUER = "http://idp.test";
  private static final String AUDIENCE = "mini-kms";
  private static final String ADMIN_TOKEN = "idp-admin";
  private static final String KMS_API_TOKEN = "kms-data";
  private static final String KMS_ADMIN_TOKEN = "kms-admin";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private LocalKeyring keyring;
  private KmsServer kms;
  private IdpServer idp;
  private HttpClient client;
  private String baseUrl;
  private Path dataDir;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws Exception {
    dataDir = dir.resolve("idp");
    keyring = LocalKeyring.bootstrap(dir.resolve("keystore.json"),
        "passphrase".toCharArray(), new Argon2Settings(2048, 1, 1));
    kms = new KmsServer(
        com.codeheadsystems.minikms.server.ServerConfig.resolve(new String[] {"--tcp-port", "0"}, Map.of()),
        new KmsRequestHandler(new KmsService(keyring), keyring,
            new ApiTokenAuthenticator(KMS_API_TOKEN), new ApiTokenAuthenticator(KMS_ADMIN_TOKEN),
            new AllowAllPolicyEngine()));
    kms.start();
    try (KmsClient admin = KmsClient.connectTcp("127.0.0.1", kms.boundTcpPort(), KMS_ADMIN_TOKEN)) {
      admin.createKeyGroup("idp-signing");
    }

    final ServerConfig config = ServerConfig.resolve(new String[] {
        "--port", "0", "--data-dir", dataDir.toString(), "--issuer", ISSUER, "--audience", AUDIENCE,
        "--kms-tcp", "127.0.0.1:" + kms.boundTcpPort(), "--kms-key-group", "idp-signing",
        "--argon-memory-kib", "1024", "--argon-iterations", "1", "--argon-parallelism", "1"}, Map.of());
    assertTrue(config.kmsEnabled(), "KMS wrapping should be enabled by --kms-* flags");
    idp = IdpServer.create(config, ADMIN_TOKEN, KMS_API_TOKEN, Clock.systemUTC());
    idp.start();
    baseUrl = "http://127.0.0.1:" + idp.address().getPort();
    client = HttpClient.newHttpClient();
  }

  @AfterEach
  void tearDown() {
    if (idp != null) {
      idp.stop();
    }
    if (kms != null) {
      kms.close();
    }
    if (keyring != null) {
      keyring.close();
    }
  }

  @Test
  void signingKeysAreKmsWrappedYetTokensVerify() throws Exception {
    // No plaintext signing key on disk: every stored private key is a mini-kms envelope.
    final SigningKeys onDisk = MAPPER.readValue(
        Files.readAllBytes(dataDir.resolve("signing-keys.json")), SigningKeys.class);
    assertFalse(onDisk.keys().isEmpty());
    assertTrue(onDisk.keys().stream()
            .allMatch(k -> k.privatePkcs8Base64().startsWith(KmsSigningKeyStore.WRAPPED_PREFIX)),
        "every signing key must be wrapped under mini-kms on disk");

    // Issue a token (the key is unwrapped in memory via mini-kms) and verify it offline via JWKS.
    final Client registered = registerClient();
    final String accessToken = MAPPER.readTree(
        requestToken(registered.clientId, registered.secret).body()).get("access_token").asString();

    final JwkSet jwks = MAPPER.readValue(get("/.well-known/jwks.json").body(), JwkSet.class);
    final TokenVerifier verifier = new TokenVerifier(ISSUER, AUDIENCE, Clock.systemUTC(), 5);
    assertTrue(verifier.verify(accessToken, jwks, jti -> false).valid(),
        "a token signed with a KMS-wrapped key verifies against the published JWKS");

    // Rotation still works through the KMS store.
    assertEquals(200, postJson("/admin/keys/rotate", "", ADMIN_TOKEN).statusCode());
    final String afterRotation = MAPPER.readTree(
        requestToken(registered.clientId, registered.secret).body()).get("access_token").asString();
    final JwkSet rotatedJwks = MAPPER.readValue(get("/.well-known/jwks.json").body(), JwkSet.class);
    assertTrue(verifier.verify(afterRotation, rotatedJwks, jti -> false).valid());
    assertTrue(verifier.verify(accessToken, rotatedJwks, jti -> false).valid(), "old token still verifies");
  }

  private record Client(String clientId, String secret) {
  }

  private Client registerClient() throws Exception {
    final HttpResponse<String> response = postJson("/admin/clients",
        "{\"authorization\":{\"control\":false,\"groups\":[]}}", ADMIN_TOKEN);
    assertEquals(201, response.statusCode(), response.body());
    final JsonNode body = MAPPER.readTree(response.body());
    return new Client(body.get("clientId").asString(), body.get("secret").asString());
  }

  private HttpResponse<String> requestToken(final String clientId, final String secret) throws Exception {
    final String form = "grant_type=client_credentials&client_id="
        + java.net.URLEncoder.encode(clientId, StandardCharsets.UTF_8)
        + "&client_secret=" + java.net.URLEncoder.encode(secret, StandardCharsets.UTF_8);
    return client.send(HttpRequest.newBuilder(URI.create(baseUrl + "/oauth/token"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(BodyPublishers.ofString(form)).build(), BodyHandlers.ofString());
  }

  private HttpResponse<String> get(final String path) throws Exception {
    return client.send(HttpRequest.newBuilder(URI.create(baseUrl + path)).GET().build(),
        BodyHandlers.ofString());
  }

  private HttpResponse<String> postJson(final String path, final String body, final String token)
      throws Exception {
    return client.send(HttpRequest.newBuilder(URI.create(baseUrl + path))
        .header("Content-Type", "application/json").header("Authorization", "Bearer " + token)
        .POST(BodyPublishers.ofString(body)).build(), BodyHandlers.ofString());
  }
}

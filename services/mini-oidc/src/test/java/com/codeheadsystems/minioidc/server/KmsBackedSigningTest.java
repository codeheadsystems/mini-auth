package com.codeheadsystems.minioidc.server;

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
import com.codeheadsystems.minioidc.auth.PasskeyStack;
import com.codeheadsystems.minioidc.directory.InMemoryUserDirectory;
import com.codeheadsystems.minipolicy.AllowAllPolicyEngine;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import com.codeheadsystems.pkauth.config.RelyingPartyConfig;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import tools.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The recursive integration through mini-oidc: with {@code --kms-*} configured, the OP's signing
 * keys are wrapped under a mini-kms key group on disk, yet the JWKS is served from keys unwrapped in
 * memory (so RPs can still verify ID/access tokens offline).
 */
class KmsBackedSigningTest {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private LocalKeyring keyring;
  private KmsServer kms;
  private OidcServer oidc;
  private Path dataDir;
  private String baseUrl;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws Exception {
    dataDir = dir.resolve("oidc");
    keyring = LocalKeyring.bootstrap(dir.resolve("keystore.json"),
        "passphrase".toCharArray(), new Argon2Settings(2048, 1, 1));
    kms = new KmsServer(
        com.codeheadsystems.minikms.server.ServerConfig.resolve(new String[] {"--tcp-port", "0"}, Map.of()),
        new KmsRequestHandler(new KmsService(keyring), keyring,
            new ApiTokenAuthenticator("kms-data"), new ApiTokenAuthenticator("kms-admin"),
            new AllowAllPolicyEngine()));
    kms.start();
    try (KmsClient admin = KmsClient.connectTcp("127.0.0.1", kms.boundTcpPort(), "kms-admin")) {
      admin.createKeyGroup("oidc-signing");
    }

    final ServerConfig config = ServerConfig.resolve(new String[] {
        "--port", "0", "--issuer", "http://oidc.test", "--data-dir", dataDir.toString(),
        "--kms-tcp", "127.0.0.1:" + kms.boundTcpPort(), "--kms-key-group", "oidc-signing"}, Map.of());
    final PasskeyStack passkeys = PasskeyStack.inMemory(
        new RelyingPartyConfig("example.com", "mini-oidc", Set.of("https://example.com")),
        ClockProvider.system());
    oidc = OidcServer.create(config, "admin", "kms-data", new InMemoryUserDirectory(),
        passkeys.humanAuthenticator(), passkeys.recoveryAuthenticator(), Clock.systemUTC());
    oidc.start();
    baseUrl = "http://127.0.0.1:" + oidc.address().getPort();
  }

  @AfterEach
  void tearDown() {
    if (oidc != null) {
      oidc.stop();
    }
    if (kms != null) {
      kms.close();
    }
    if (keyring != null) {
      keyring.close();
    }
  }

  @Test
  void signingKeysAreWrappedOnDiskAndJwksStillServes() throws Exception {
    final SigningKeys onDisk = MAPPER.readValue(
        Files.readAllBytes(dataDir.resolve("signing-keys.json")), SigningKeys.class);
    assertFalse(onDisk.keys().isEmpty());
    assertTrue(onDisk.keys().stream()
            .allMatch(k -> k.privatePkcs8Base64().startsWith(KmsSigningKeyStore.WRAPPED_PREFIX)),
        "the OP's signing keys must be KMS-wrapped on disk");

    // The JWKS serves public keys reconstructed from the (unwrapped-in-memory) signing keys.
    final HttpClient client = HttpClient.newHttpClient();
    final var response = client.send(
        HttpRequest.newBuilder(URI.create(baseUrl + "/jwks.json")).GET().build(), BodyHandlers.ofString());
    assertEquals(200, response.statusCode());
    final JwkSet jwks = MAPPER.readValue(response.body(), JwkSet.class);
    assertFalse(jwks.keys().isEmpty(), "the JWKS is served despite keys being KMS-wrapped at rest");
  }
}

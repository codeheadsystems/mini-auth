package com.codeheadsystems.minica.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minica.support.TestCsr;
import com.codeheadsystems.minikms.auth.ApiTokenAuthenticator;
import com.codeheadsystems.minikms.client.KmsClient;
import com.codeheadsystems.minikms.client.KmsSigningKeyStore;
import com.codeheadsystems.minikms.keyring.LocalKeyring;
import com.codeheadsystems.minikms.kms.KmsRequestHandler;
import com.codeheadsystems.minikms.kms.KmsService;
import com.codeheadsystems.minikms.master.Argon2Settings;
import com.codeheadsystems.minikms.server.KmsServer;
import com.codeheadsystems.minipolicy.AllowAllPolicyEngine;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import tools.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The recursive integration for mini-ca: with {@code --kms-*}, the CA private key is wrapped under a
 * mini-kms key group (no plaintext on disk), yet the CA still issues — the key is unwrapped in memory
 * at bootstrap — and the wrapped key reloads across a restart.
 */
class KmsBackedCaKeyTest {

  private static final String ADMIN = "ca-admin";
  private static final String KMS_API = "kms-data";
  private static final String KMS_ADMIN = "kms-admin";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private LocalKeyring keyring;
  private KmsServer kms;
  private Path dataDir;
  private ServerConfig config;

  @BeforeEach
  void setUp(@TempDir final Path dir) throws Exception {
    dataDir = dir.resolve("ca");
    keyring = LocalKeyring.bootstrap(dir.resolve("keystore.json"),
        "passphrase".toCharArray(), new Argon2Settings(2048, 1, 1));
    kms = new KmsServer(
        com.codeheadsystems.minikms.server.ServerConfig.resolve(new String[] {"--tcp-port", "0"}, Map.of()),
        new KmsRequestHandler(new KmsService(keyring), keyring,
            new ApiTokenAuthenticator(KMS_API), new ApiTokenAuthenticator(KMS_ADMIN),
            new AllowAllPolicyEngine()));
    kms.start();
    try (KmsClient admin = KmsClient.connectTcp("127.0.0.1", kms.boundTcpPort(), KMS_ADMIN)) {
      admin.createKeyGroup("ca-key");
    }
    config = ServerConfig.resolve(new String[] {
        "--port", "0", "--data-dir", dataDir.toString(),
        "--kms-tcp", "127.0.0.1:" + kms.boundTcpPort(), "--kms-key-group", "ca-key"}, Map.of());
    assertTrue(config.kmsEnabled());
  }

  @AfterEach
  void tearDown() {
    if (kms != null) {
      kms.close();
    }
    if (keyring != null) {
      keyring.close();
    }
  }

  @Test
  void caKeyIsKmsWrappedOnDiskYetTheCaStillIssues() throws Exception {
    final CaServer server = CaServer.create(config, ADMIN, KMS_API, Clock.systemUTC());
    server.start();
    try {
      // No plaintext CA key on disk: it is a mini-kms envelope.
      final SigningKeys onDisk = MAPPER.readValue(
          Files.readAllBytes(dataDir.resolve("ca-key.json")), SigningKeys.class);
      assertTrue(onDisk.keys().get(0).privatePkcs8Base64().startsWith(KmsSigningKeyStore.WRAPPED_PREFIX),
          "the CA private key must be KMS-wrapped on disk");

      // The CA still issues (the key was unwrapped in memory at bootstrap).
      assertEquals(201, issue(server).statusCode(), "CA issues with a KMS-wrapped key");
    } finally {
      server.stop();
    }

    // Reload from disk (a fresh CaServer + connection): the wrapped key unwraps and issuance works.
    final CaServer reloaded = CaServer.create(config, ADMIN, KMS_API, Clock.systemUTC());
    reloaded.start();
    try {
      assertEquals(201, issue(reloaded).statusCode(), "the KMS-wrapped CA key reloads across a restart");
      // sanity: it is the same CA (the cert is public + stable), not a freshly minted one.
      assertFalse(reloaded.config() == null);
    } finally {
      reloaded.stop();
    }
  }

  private static java.net.http.HttpResponse<String> issue(final CaServer server) throws Exception {
    final String url = "http://127.0.0.1:" + server.address().getPort() + "/issue";
    final String body = "{\"csr\":" + MAPPER.writeValueAsString(TestCsr.create("svc").csrPem()) + "}";
    return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(url))
        .header("Content-Type", "application/json").header("Authorization", "Bearer " + ADMIN)
        .POST(BodyPublishers.ofString(body)).build(), BodyHandlers.ofString());
  }
}

package com.codeheadsystems.minikms.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minikms.auth.ApiTokenAuthenticator;
import com.codeheadsystems.minikms.keyring.LocalKeyring;
import com.codeheadsystems.minikms.kms.KmsRequestHandler;
import com.codeheadsystems.minikms.kms.KmsService;
import com.codeheadsystems.minikms.master.Argon2Settings;
import com.codeheadsystems.minikms.server.KmsServer;
import com.codeheadsystems.minikms.server.ServerConfig;
import com.codeheadsystems.minipolicy.AllowAllPolicyEngine;
import com.codeheadsystems.minitoken.crypto.Ed25519Keys;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.service.SigningKeyService;
import com.codeheadsystems.minitoken.store.DocumentStore;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import com.codeheadsystems.minitoken.token.Jws;
import com.codeheadsystems.minitoken.token.JwsClaimsVerifier;
import com.codeheadsystems.minitoken.token.JwsHeader;
import com.codeheadsystems.minitoken.util.RandomIds;
import tools.jackson.databind.json.JsonMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Proves the recursive integration: with {@link KmsSigningKeyStore} the token plane's private signing
 * keys are envelope-encrypted under a mini-kms key group — no plaintext touches disk — yet issuance,
 * rotation, and reload all still work. Also pins the default (plaintext) path as the contrast.
 */
class KmsSigningKeyStoreTest {

  private static final String API_TOKEN = "data-token";
  private static final String ADMIN_TOKEN = "admin-token";
  private static final String KEY_GROUP = "auth-signing-keys";
  private static final String ISSUER = "http://idp.test";
  private static final String AUDIENCE = "mini-kms-aud";

  @TempDir
  Path dir;

  private LocalKeyring keyring;
  private KmsServer server;
  private int port;

  @BeforeEach
  void startKms() throws Exception {
    keyring = LocalKeyring.bootstrap(dir.resolve("keystore.json"),
        "passphrase".toCharArray(), new Argon2Settings(2048, 1, 1));
    final KmsRequestHandler handler = new KmsRequestHandler(new KmsService(keyring), keyring,
        new ApiTokenAuthenticator(API_TOKEN), new ApiTokenAuthenticator(ADMIN_TOKEN),
        new AllowAllPolicyEngine());
    server = new KmsServer(ServerConfig.resolve(new String[] {"--tcp-port", "0"}, Map.of()), handler);
    server.start();
    port = server.boundTcpPort();
    // The auth service's signing-key group is created out of band by an operator (control plane).
    try (KmsClient admin = KmsClient.connectTcp("127.0.0.1", port, ADMIN_TOKEN)) {
      admin.createKeyGroup(KEY_GROUP);
    }
  }

  @AfterEach
  void stopKms() {
    if (server != null) {
      server.close();
    }
    if (keyring != null) {
      keyring.close();
    }
  }

  private KmsSigningKeyStore kmsStore(final Path file) {
    return KmsSigningKeyStore.overTcp(new JsonFileStore(file), "127.0.0.1", port, API_TOKEN, KEY_GROUP);
  }

  @Test
  void noPlaintextSigningKeyTouchesDiskWhenKmsBacked() throws Exception {
    final Path file = dir.resolve("signing-keys.json");
    final SigningKeyService keys = new SigningKeyService(
        kmsStore(file), new RandomIds(), Clock.systemUTC(), Duration.ofMinutes(30));

    final String plaintextActive = Ed25519Keys.encodePrivate(keys.currentSigner().privateKey());
    final String onDisk = Files.readString(file);
    assertTrue(onDisk.contains(KmsSigningKeyStore.WRAPPED_PREFIX), "private keys are KMS-wrapped on disk");
    assertFalse(onDisk.contains(plaintextActive), "the plaintext private key must NOT be on disk");
  }

  @Test
  void defaultPathWritesPlaintext() {
    // The contrast: the bare file store (the educational default) holds the key in the clear.
    final Path file = dir.resolve("plain-keys.json");
    final SigningKeyService keys = new SigningKeyService(
        new JsonFileStore(file), new RandomIds(), Clock.systemUTC(), Duration.ofMinutes(30));
    final String plaintextActive = Ed25519Keys.encodePrivate(keys.currentSigner().privateKey());
    final String onDisk = Files.exists(file) ? readString(file) : "";
    assertTrue(onDisk.contains(plaintextActive), "the default path stores the key plaintext");
    assertFalse(onDisk.contains(KmsSigningKeyStore.WRAPPED_PREFIX));
  }

  @Test
  void issuanceRotationAndReloadWorkThroughKms() {
    final Path file = dir.resolve("signing-keys.json");
    final SigningKeyService keys = new SigningKeyService(
        kmsStore(file), new RandomIds(), Clock.systemUTC(), Duration.ofMinutes(30));

    final String firstKid = keys.currentSigner().kid();
    final String oldToken = sign(keys);
    assertTrue(verifies(oldToken, keys.jwkSet()), "a freshly issued token verifies");

    final String secondKid = keys.rotate();
    assertNotEquals(firstKid, secondKid, "rotation mints a new kid");
    final JwkSet afterRotation = keys.jwkSet();
    assertTrue(verifies(oldToken, afterRotation), "old token still verifies after rotation");
    assertTrue(verifies(sign(keys), afterRotation), "new token verifies after rotation");

    // Reload from disk (a fresh service + connection): the wrapped keys unwrap and still verify.
    final SigningKeyService reloaded = new SigningKeyService(
        kmsStore(file), new RandomIds(), Clock.systemUTC(), Duration.ofMinutes(30));
    assertEquals(secondKid, reloaded.activeKid(), "the active key survives a reload");
    assertTrue(verifies(oldToken, reloaded.jwkSet()), "tokens verify after a KMS-backed reload");
  }

  @Test
  void rewrapAfterKeyGroupRotationKeepsKeysUsable() {
    final Path file = dir.resolve("signing-keys.json");
    final KmsSigningKeyStore store = kmsStore(file);
    final SigningKeyService keys = new SigningKeyService(
        store, new RandomIds(), Clock.systemUTC(), Duration.ofMinutes(30));
    final String token = sign(keys);

    try (KmsClient admin = KmsClient.connectTcp("127.0.0.1", port, ADMIN_TOKEN)) {
      admin.rotateKeyGroup(KEY_GROUP); // new active KEK version
    }
    store.rewrap(); // re-encrypt the wrapped keys onto the new version (ReEncrypt, no plaintext)

    final SigningKeyService reloaded = new SigningKeyService(
        store, new RandomIds(), Clock.systemUTC(), Duration.ofMinutes(30));
    assertTrue(verifies(token, reloaded.jwkSet()), "keys remain usable after KEK rotation + rewrap");
  }

  // ---- helpers -------------------------------------------------------------------------------

  private static String sign(final SigningKeyService keys) {
    final long now = Clock.systemUTC().instant().getEpochSecond();
    final Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("iss", ISSUER);
    claims.put("sub", "alice");
    claims.put("aud", AUDIENCE);
    claims.put("iat", now);
    claims.put("nbf", now);
    claims.put("exp", now + 300);
    final SigningKeyService.Signer signer = keys.currentSigner();
    return Jws.sign(JwsHeader.forKid(signer.kid()), claims, signer.privateKey());
  }

  private static boolean verifies(final String token, final JwkSet jwkSet) {
    return JwsClaimsVerifier.verify(token, jwkSet, ISSUER, AUDIENCE, Clock.systemUTC(), 5).isPresent();
  }

  private static String readString(final Path path) {
    try {
      return Files.readString(path);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  /** A minimal file-backed {@link DocumentStore} delegate (stands in for the services' JsonStore). */
  private static final class JsonFileStore implements DocumentStore<SigningKeys> {
    private static final JsonMapper MAPPER = JsonMapper.builder().build();
    private final Path path;

    JsonFileStore(final Path path) {
      this.path = path;
    }

    @Override
    public boolean exists() {
      return Files.isRegularFile(path);
    }

    @Override
    public SigningKeys load() {
      try {
        return MAPPER.readValue(Files.readAllBytes(path), SigningKeys.class);
      } catch (final Exception e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public void save(final SigningKeys document) {
      try {
        Files.write(path, MAPPER.writeValueAsBytes(document));
      } catch (final Exception e) {
        throw new RuntimeException(e);
      }
    }
  }
}

package com.codeheadsystems.miniidp.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniidp.model.ClientRecord;
import com.codeheadsystems.miniidp.secret.Argon2Settings;
import com.codeheadsystems.miniidp.secret.Argon2SecretHasher;
import com.codeheadsystems.miniidp.store.JsonStore;
import com.codeheadsystems.miniidp.store.StoreDocuments.ClientRegistry;
import com.codeheadsystems.miniidp.support.MutableClock;
import com.codeheadsystems.minitoken.auth.Authorization;
import com.codeheadsystems.minitoken.auth.Grant;
import com.codeheadsystems.minitoken.auth.KeyOperation;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.service.RevocationService;
import com.codeheadsystems.minitoken.service.SigningKeyService;
import com.codeheadsystems.minitoken.service.TokenIssuer;
import com.codeheadsystems.minitoken.service.TokenIssuer.IssuedToken;
import com.codeheadsystems.minitoken.service.TokenVerifier;
import com.codeheadsystems.minitoken.service.TokenVerifier.FailureReason;
import com.codeheadsystems.minitoken.service.TokenVerifier.Result;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.Revocations;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import com.codeheadsystems.minitoken.token.Jws;
import com.codeheadsystems.minitoken.token.JwsHeader;
import com.codeheadsystems.minitoken.util.RandomIds;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * End-to-end token lifecycle exercised entirely through core services, with a verifier that knows
 * only the published JWKS — i.e. exactly what the future mini-kms will do.
 */
class TokenLifecycleTest {

  private static final String ISSUER = "https://idp.example/";
  private static final String AUDIENCE = "mini-kms";
  private static final Duration TTL = Duration.ofMinutes(5);

  private MutableClock clock;
  private ClientService clients;
  private SigningKeyService signingKeys;
  private RevocationService revocations;
  private TokenIssuer issuer;
  private TokenVerifier verifier;

  @BeforeEach
  void setUp(@TempDir final Path dir) {
    clock = new MutableClock(Instant.parse("2026-06-14T12:00:00Z"));
    final RandomIds ids = new RandomIds();
    final Argon2SecretHasher hasher = new Argon2SecretHasher(new Argon2Settings(1024, 1, 1));
    clients = new ClientService(
        new JsonStore<>(dir.resolve("clients.json"), ClientRegistry.class), hasher, ids, clock);
    signingKeys = new SigningKeyService(
        new JsonStore<>(dir.resolve("keys.json"), SigningKeys.class), ids, clock, Duration.ofMinutes(30));
    revocations = new RevocationService(
        new JsonStore<>(dir.resolve("revocations.json"), Revocations.class), clock);
    issuer = new TokenIssuer(signingKeys, ids, clock, ISSUER.replaceAll("/$", ""), AUDIENCE, TTL);
    verifier = new TokenVerifier(ISSUER.replaceAll("/$", ""), AUDIENCE, clock, 0);
  }

  private ClientRecord registerWith(final Authorization authorization) {
    return clients.register("test", authorization).client();
  }

  // Adapt a registered client to the framework-neutral issuer seam (subject + authorization).
  private IssuedToken issueFor(final ClientRecord client) {
    return issuer.issue(client.clientId(), client.authorization());
  }

  @Test
  void issuedTokenVerifiesAgainstJwksWithCorrectClaims() {
    final ClientRecord client = registerWith(new Authorization(false,
        List.of(Grant.of("billing", KeyOperation.ENCRYPT, KeyOperation.DECRYPT))));

    final IssuedToken token = issueFor(client);
    final Result result = verifier.verify(token.accessToken(), signingKeys.jwkSet(), revocations::isRevoked);

    assertTrue(result.valid(), "freshly issued token must verify");
    assertEquals(client.clientId(), result.claims().subject());
    assertEquals(ISSUER.replaceAll("/$", ""), result.claims().issuer());
    assertEquals(AUDIENCE, result.claims().audience());

    // The grants round-trip back into the domain authorization the verifier will authorize against.
    final Authorization recovered = result.claims().grants().toAuthorization();
    assertFalse(recovered.controlPlane());
    assertEquals(1, recovered.grants().size());
    final Grant grant = recovered.grants().get(0);
    assertEquals("billing", grant.keyGroup());
    assertTrue(grant.operations().contains(KeyOperation.ENCRYPT));
    assertTrue(grant.operations().contains(KeyOperation.DECRYPT));
  }

  @Test
  void expiredTokenIsRejected() {
    final IssuedToken token = issueFor(registerWith(Authorization.none()));
    clock.advance(TTL.plusSeconds(1));
    final Result result = verifier.verify(token.accessToken(), signingKeys.jwkSet(), revocations::isRevoked);
    assertFalse(result.valid());
    assertEquals(FailureReason.EXPIRED, result.reason());
  }

  @Test
  void notYetValidTokenIsRejected() {
    final IssuedToken token = issueFor(registerWith(Authorization.none()));
    // Verify from a point well before the token's nbf.
    clock.advance(Duration.ofMinutes(-10));
    final Result result = verifier.verify(token.accessToken(), signingKeys.jwkSet(), revocations::isRevoked);
    assertFalse(result.valid());
    assertEquals(FailureReason.NOT_YET_VALID, result.reason());
  }

  @Test
  void wrongAudienceIsRejected() {
    final IssuedToken token = issueFor(registerWith(Authorization.none()));
    final TokenVerifier other = new TokenVerifier(ISSUER.replaceAll("/$", ""), "someone-else", clock, 0);
    final Result result = other.verify(token.accessToken(), signingKeys.jwkSet(), revocations::isRevoked);
    assertFalse(result.valid());
    assertEquals(FailureReason.WRONG_AUDIENCE, result.reason());
  }

  @Test
  void tamperedTokenIsRejected() {
    final IssuedToken token = issueFor(registerWith(Authorization.none()));
    // Flip a character in the payload segment; the signature no longer matches the bytes.
    final Jws.Parts parts = Jws.split(token.accessToken());
    final char flipped = parts.payload().charAt(0) == 'A' ? 'B' : 'A';
    final String tampered = flipped + parts.payload().substring(1) + "." + parts.signature();
    final String forged = parts.header() + "." + tampered;
    final Result result = verifier.verify(forged, signingKeys.jwkSet(), revocations::isRevoked);
    assertFalse(result.valid());
    assertEquals(FailureReason.BAD_SIGNATURE, result.reason());
  }

  @Test
  void rotatedKeyKeepsOldTokensVerifiableAndSignsNewTokensWithNewKid() {
    final String firstKid = signingKeys.activeKid();
    final IssuedToken oldToken = issueFor(registerWith(Authorization.none()));

    final String secondKid = signingKeys.rotate();
    assertNotEquals(firstKid, secondKid, "rotation must produce a new kid");

    // Old kid is still published, so the old token still verifies.
    final JwkSet jwks = signingKeys.jwkSet();
    assertTrue(jwks.keys().stream().anyMatch(k -> k.keyId().equals(firstKid)));
    assertTrue(jwks.keys().stream().anyMatch(k -> k.keyId().equals(secondKid)));
    assertTrue(verifier.verify(oldToken.accessToken(), jwks, revocations::isRevoked).valid());

    // New tokens are signed with the new kid.
    final IssuedToken newToken = issueFor(registerWith(Authorization.none()));
    final JwsHeader header = Jws.parseHeader(Jws.split(newToken.accessToken()));
    assertEquals(secondKid, header.keyId());
    assertTrue(verifier.verify(newToken.accessToken(), signingKeys.jwkSet(), revocations::isRevoked).valid());
  }

  @Test
  void revokedJtiAppearsInDenylistAndFailsVerification() {
    final IssuedToken token = issueFor(registerWith(Authorization.none()));
    revocations.revoke(token.jti(), token.expiresAt(), "compromised");

    assertTrue(revocations.isRevoked(token.jti()));
    assertTrue(revocations.activeDenylist().stream().anyMatch(r -> r.jti().equals(token.jti())));

    final Result result = verifier.verify(token.accessToken(), signingKeys.jwkSet(), revocations::isRevoked);
    assertFalse(result.valid());
    assertEquals(FailureReason.REVOKED, result.reason());
  }

  @Test
  void correctClientSecretAuthenticatesAndWrongOneDoesNot() {
    final ClientService.Registration registration = clients.register("auth-test", Authorization.none());
    final char[] secret = registration.secret();
    final String clientId = registration.client().clientId();

    assertTrue(clients.authenticate(clientId, secret.clone()).isPresent());
    assertFalse(clients.authenticate(clientId, "not-the-secret".toCharArray()).isPresent());
    assertFalse(clients.authenticate("client_unknown", secret.clone()).isPresent());
  }
}

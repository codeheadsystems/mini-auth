package com.codeheadsystems.miniidp.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniidp.store.JsonStore;
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
 * End-to-end token lifecycle exercised through the token plane, with a verifier that knows only the
 * published JWKS — exactly what the future mini-kms (or any verifier) does. The subject + grants now
 * come from the caller (mini-idp resolves them from mini-directory); this test feeds them directly.
 */
class TokenLifecycleTest {

  private static final String ISSUER = "https://idp.example";
  private static final String AUDIENCE = "mini-kms";
  private static final Duration TTL = Duration.ofMinutes(5);
  private static final String SUBJECT = "client_demo";

  private MutableClock clock;
  private SigningKeyService signingKeys;
  private RevocationService revocations;
  private TokenIssuer issuer;
  private TokenVerifier verifier;

  @BeforeEach
  void setUp(@TempDir final Path dir) {
    clock = new MutableClock(Instant.parse("2026-06-14T12:00:00Z"));
    final RandomIds ids = new RandomIds();
    signingKeys = new SigningKeyService(
        new JsonStore<>(dir.resolve("keys.json"), SigningKeys.class), ids, clock, Duration.ofMinutes(30));
    revocations = new RevocationService(
        new JsonStore<>(dir.resolve("revocations.json"), Revocations.class), clock);
    issuer = new TokenIssuer(signingKeys, ids, clock, ISSUER, AUDIENCE, TTL);
    verifier = new TokenVerifier(ISSUER, AUDIENCE, clock, 0);
  }

  @Test
  void issuedTokenVerifiesAgainstJwksWithCorrectClaims() {
    final Authorization authorization = new Authorization(false,
        List.of(Grant.of("billing", KeyOperation.ENCRYPT, KeyOperation.DECRYPT)));
    final IssuedToken token = issuer.issue(SUBJECT, authorization);
    final Result result = verifier.verify(token.accessToken(), signingKeys.jwkSet(), revocations::isRevoked);

    assertTrue(result.valid(), "freshly issued token must verify");
    assertEquals(SUBJECT, result.claims().subject());
    assertEquals(ISSUER, result.claims().issuer());
    assertEquals(AUDIENCE, result.claims().audience());

    final Authorization recovered = result.claims().grants().toAuthorization();
    assertFalse(recovered.controlPlane());
    final Grant grant = recovered.grants().get(0);
    assertEquals("billing", grant.keyGroup());
    assertTrue(grant.operations().contains(KeyOperation.ENCRYPT));
    assertTrue(grant.operations().contains(KeyOperation.DECRYPT));
  }

  @Test
  void expiredTokenIsRejected() {
    final IssuedToken token = issuer.issue(SUBJECT, Authorization.none());
    clock.advance(TTL.plusSeconds(1));
    final Result result = verifier.verify(token.accessToken(), signingKeys.jwkSet(), revocations::isRevoked);
    assertFalse(result.valid());
    assertEquals(FailureReason.EXPIRED, result.reason());
  }

  @Test
  void notYetValidTokenIsRejected() {
    final IssuedToken token = issuer.issue(SUBJECT, Authorization.none());
    clock.advance(Duration.ofMinutes(-10));
    final Result result = verifier.verify(token.accessToken(), signingKeys.jwkSet(), revocations::isRevoked);
    assertFalse(result.valid());
    assertEquals(FailureReason.NOT_YET_VALID, result.reason());
  }

  @Test
  void wrongAudienceIsRejected() {
    final IssuedToken token = issuer.issue(SUBJECT, Authorization.none());
    final TokenVerifier other = new TokenVerifier(ISSUER, "someone-else", clock, 0);
    final Result result = other.verify(token.accessToken(), signingKeys.jwkSet(), revocations::isRevoked);
    assertFalse(result.valid());
    assertEquals(FailureReason.WRONG_AUDIENCE, result.reason());
  }

  @Test
  void tamperedTokenIsRejected() {
    final IssuedToken token = issuer.issue(SUBJECT, Authorization.none());
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
    final IssuedToken oldToken = issuer.issue(SUBJECT, Authorization.none());

    final String secondKid = signingKeys.rotate();
    assertNotEquals(firstKid, secondKid, "rotation must produce a new kid");

    final JwkSet jwks = signingKeys.jwkSet();
    assertTrue(jwks.keys().stream().anyMatch(k -> k.keyId().equals(firstKid)));
    assertTrue(jwks.keys().stream().anyMatch(k -> k.keyId().equals(secondKid)));
    assertTrue(verifier.verify(oldToken.accessToken(), jwks, revocations::isRevoked).valid());

    final IssuedToken newToken = issuer.issue(SUBJECT, Authorization.none());
    final JwsHeader header = Jws.parseHeader(Jws.split(newToken.accessToken()));
    assertEquals(secondKid, header.keyId());
    assertTrue(verifier.verify(newToken.accessToken(), signingKeys.jwkSet(), revocations::isRevoked).valid());
  }

  @Test
  void revokedJtiAppearsInDenylistAndFailsVerification() {
    final IssuedToken token = issuer.issue(SUBJECT, Authorization.none());
    revocations.revoke(token.jti(), token.expiresAt(), "compromised");

    assertTrue(revocations.isRevoked(token.jti()));
    assertTrue(revocations.activeDenylist().stream().anyMatch(r -> r.jti().equals(token.jti())));

    final Result result = verifier.verify(token.accessToken(), signingKeys.jwkSet(), revocations::isRevoked);
    assertFalse(result.valid());
    assertEquals(FailureReason.REVOKED, result.reason());
  }
}

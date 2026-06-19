package com.codeheadsystems.miniconsole.harness.flows;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Status;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Step;
import com.codeheadsystems.miniidp.client.MiniIdpClient;
import com.codeheadsystems.miniidp.client.model.DiscoveryDocument;
import com.codeheadsystems.miniidp.client.model.HealthStatus;
import com.codeheadsystems.miniidp.client.model.TokenResponse;
import com.codeheadsystems.minitoken.auth.Authorization;
import com.codeheadsystems.minitoken.crypto.Ed25519Keys;
import com.codeheadsystems.minitoken.jwks.Jwk;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.model.AuditEntry;
import com.codeheadsystems.minitoken.token.GrantsClaim;
import com.codeheadsystems.minitoken.token.Jws;
import com.codeheadsystems.minitoken.token.JwsHeader;
import com.codeheadsystems.minitoken.token.JwtClaims;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link M2mTokenFlow}, the heart of the exercise harness — its offline verification
 * logic — exercised against a fake {@link MiniIdpClient} with REAL mini-token-signed tokens and a
 * matching JWKS. No IDP is booted: this isolates the flow's assertions (signature, issuer, expiry)
 * and its redaction contract.
 */
class M2mTokenFlowTest {

  private static final String ISSUER = "http://idp.test";
  private static final String CLIENT = "svc_demo";
  private static final String SECRET = "super-secret-value";

  private final M2mTokenFlow flow = new M2mTokenFlow(Clock.systemUTC());

  @Test
  void validToken_verifiesOffline_andPasses() {
    final KeyPair kp = Ed25519Keys.generate();
    final String token = sign(kp, "kid-1", Instant.now().getEpochSecond() + 3600);
    final FakeIdp idp = new FakeIdp(ok(token), new JwkSet(List.of(Jwk.forEd25519("kid-1", kp.getPublic()))));

    final ExerciseResult result = flow.run(idp, CLIENT, SECRET);

    assertEquals(Status.PASS, result.status());
    assertTrue(result.steps().stream().allMatch(s -> s.status() == Status.PASS));
    // The verify step reports the non-secret facts.
    final Step verify = lastStep(result);
    assertTrue(verify.detail().contains("sub=" + CLIENT));
    assertTrue(verify.detail().contains("kid=kid-1"));
  }

  @Test
  void tokenSignedByAnotherKey_failsVerification() {
    final KeyPair signer = Ed25519Keys.generate();
    final KeyPair impostor = Ed25519Keys.generate();
    final String token = sign(signer, "kid-1", Instant.now().getEpochSecond() + 3600);
    // The JWKS publishes a DIFFERENT key under the same kid — the signature cannot verify.
    final FakeIdp idp = new FakeIdp(ok(token),
        new JwkSet(List.of(Jwk.forEd25519("kid-1", impostor.getPublic()))));

    final ExerciseResult result = flow.run(idp, CLIENT, SECRET);

    assertEquals(Status.FAIL, result.status());
    assertTrue(lastStep(result).detail().contains("BAD_SIGNATURE"));
  }

  @Test
  void expiredToken_fails() {
    final KeyPair kp = Ed25519Keys.generate();
    final String token = sign(kp, "kid-1", Instant.now().getEpochSecond() - 60);
    final FakeIdp idp = new FakeIdp(ok(token), new JwkSet(List.of(Jwk.forEd25519("kid-1", kp.getPublic()))));

    final ExerciseResult result = flow.run(idp, CLIENT, SECRET);

    assertEquals(Status.FAIL, result.status());
    assertTrue(lastStep(result).detail().contains("EXPIRED"));
  }

  @Test
  void tokenRequestRefused_failsAtFirstStep_noOracle() {
    final FakeIdp idp = new FakeIdp(null, null); // token() throws
    final ExerciseResult result = flow.run(idp, CLIENT, SECRET);
    assertEquals(Status.FAIL, result.status());
    assertEquals(1, result.steps().size());
    assertEquals("Request token", result.steps().get(0).label());
  }

  @Test
  void resultNeverContainsTheSecretOrTheRawToken() {
    final KeyPair kp = Ed25519Keys.generate();
    final String token = sign(kp, "kid-1", Instant.now().getEpochSecond() + 3600);
    final FakeIdp idp = new FakeIdp(ok(token), new JwkSet(List.of(Jwk.forEd25519("kid-1", kp.getPublic()))));

    final ExerciseResult result = flow.run(idp, CLIENT, SECRET);

    final String rendered = result.summary() + result.steps().stream()
        .map(s -> s.label() + s.detail()).reduce("", String::concat);
    assertTrue(!rendered.contains(SECRET), "the client secret must never appear in the result");
    assertTrue(!rendered.contains(token), "the raw access token must never appear in the result");
  }

  // ---- helpers -------------------------------------------------------------------------------

  private static TokenResponse ok(final String accessToken) {
    return new TokenResponse(accessToken, "Bearer", 3600, "billing");
  }

  private static String sign(final KeyPair kp, final String kid, final long exp) {
    final long now = Instant.now().getEpochSecond();
    final JwtClaims claims = new JwtClaims(ISSUER, CLIENT, "mini-kms", now, now, exp, "jti-1",
        GrantsClaim.from(Authorization.none()), null);
    return Jws.sign(JwsHeader.forKid(kid), claims, kp.getPrivate());
  }

  private static Step lastStep(final ExerciseResult result) {
    return result.steps().get(result.steps().size() - 1);
  }

  /** A fake idp: returns the canned token + JWKS; {@code token()} throws when the token is null. */
  private static final class FakeIdp implements MiniIdpClient {
    private final TokenResponse token;
    private final JwkSet jwks;

    FakeIdp(final TokenResponse token, final JwkSet jwks) {
      this.token = token;
      this.jwks = jwks;
    }

    @Override
    public TokenResponse token(final String clientId, final String clientSecret) {
      if (token == null) {
        throw new ClientException("refused");
      }
      return token;
    }

    @Override
    public JwkSet jwks() {
      return jwks;
    }

    @Override
    public DiscoveryDocument discovery() {
      return new DiscoveryDocument(ISSUER, null, null);
    }

    @Override
    public List<AuditEntry> audit() {
      return List.of();
    }

    @Override
    public HealthStatus health() {
      return new HealthStatus("ok");
    }
  }
}

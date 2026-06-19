package com.codeheadsystems.miniconsole.harness.flows;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Status;
import com.codeheadsystems.miniidp.client.MiniIdpClient;
import com.codeheadsystems.miniidp.client.model.DiscoveryDocument;
import com.codeheadsystems.miniidp.client.model.HealthStatus;
import com.codeheadsystems.miniidp.client.model.RotationResult;
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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link KeyRotationFlow}, against a fake mini-idp that mints REAL Ed25519-signed
 * tokens and rotates its signing key in memory. No real IDP is booted; the flow's logic — that a
 * token minted before rotation still verifies afterward because the retired key is retained — is
 * exercised directly. The secret/token are never asserted by value.
 */
class KeyRotationFlowTest {

  private static final String ISSUER = "http://idp.test";

  @Test
  void passesWhenRotationRetainsTheRetiredKey() {
    final RotatingFakeIdp idp = new RotatingFakeIdp(true);
    final ExerciseResult result = new KeyRotationFlow(Clock.systemUTC()).run(idp, "svc", "secret");
    assertEquals(Status.PASS, result.status(), result.summary());
    assertTrue(result.steps().stream().anyMatch(
        step -> step.label().contains("still verifies") && step.status() == Status.PASS));
    // The supplied secret never appears in any rendered step/summary.
    assertFalse(result.summary().contains("secret"));
  }

  @Test
  void failsWhenRotationDropsTheRetiredKey() {
    final RotatingFakeIdp idp = new RotatingFakeIdp(false);
    final ExerciseResult result = new KeyRotationFlow(Clock.systemUTC()).run(idp, "svc", "secret");
    assertEquals(Status.FAIL, result.status());
    assertTrue(result.steps().stream().anyMatch(
        step -> step.label().contains("Retired key retained") && step.status() == Status.FAIL));
  }

  /**
   * A fake IDP that signs tokens with its current active key and publishes its keys. On rotation it
   * mints a new active key; {@code retainOldKeys} decides whether the retired key stays in the JWKS
   * (the safe, correct behavior) or is dropped (the bug the flow must catch).
   */
  private static final class RotatingFakeIdp implements MiniIdpClient {

    private final boolean retainOldKeys;
    private final Map<String, KeyPair> keys = new LinkedHashMap<>();
    private String activeKid = "kid-0";
    private int counter;

    RotatingFakeIdp(final boolean retainOldKeys) {
      this.retainOldKeys = retainOldKeys;
      keys.put(activeKid, Ed25519Keys.generate());
    }

    @Override
    public TokenResponse token(final String clientId, final String clientSecret) {
      final long now = Instant.now().getEpochSecond();
      final JwtClaims claims = new JwtClaims(ISSUER, clientId, "mini-kms", now, now, now + 3600,
          "jti-" + counter, GrantsClaim.from(Authorization.none()), null);
      final String jws = Jws.sign(JwsHeader.forKid(activeKid), claims, keys.get(activeKid).getPrivate());
      return new TokenResponse(jws, "Bearer", 3600, "billing");
    }

    @Override
    public JwkSet jwks() {
      final List<Jwk> published = new ArrayList<>();
      keys.forEach((kid, pair) -> published.add(Jwk.forEd25519(kid, pair.getPublic())));
      return new JwkSet(published);
    }

    @Override
    public RotationResult rotateSigningKey() {
      final String newKid = "kid-" + (++counter);
      final KeyPair fresh = Ed25519Keys.generate();
      if (!retainOldKeys) {
        keys.clear();
      }
      keys.put(newKid, fresh);
      activeKid = newKid;
      return new RotationResult(newKid);
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

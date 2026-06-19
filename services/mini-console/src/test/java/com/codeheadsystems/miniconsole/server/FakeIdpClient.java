package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniclient.common.ClientException;
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
import java.time.Instant;
import java.util.List;

/**
 * A canned, in-memory {@link MiniIdpClient} for console tests — no real IDP is booted. It mints a
 * REAL mini-token-signed token under a key it also publishes in its JWKS, so the machine-to-machine
 * harness flow genuinely verifies offline and PASSes. The {@code audit()} list carries one
 * non-secret entry. Set {@link #failAudit} to make the audit call throw (the no-oracle path).
 */
final class FakeIdpClient implements MiniIdpClient {

  static final String ISSUER = "http://idp.test";
  static final String KID = "fake-kid";

  /** When true, {@link #audit()} throws — used to prove the Audit page degrades without an oracle. */
  boolean failAudit;
  /** When true, {@link #rotateSigningKey()} throws — used to prove the Keys page has no oracle. */
  boolean failRotate;
  /** Counts rotation calls so a test can assert the route reached the client. */
  int rotateCalls;

  private final KeyPair keyPair = Ed25519Keys.generate();

  @Override
  public TokenResponse token(final String clientId, final String clientSecret) {
    final long now = Instant.now().getEpochSecond();
    final JwtClaims claims = new JwtClaims(ISSUER, clientId, "mini-kms", now, now, now + 3600,
        "jti-fake", GrantsClaim.from(Authorization.none()), null);
    return new TokenResponse(Jws.sign(JwsHeader.forKid(KID), claims, keyPair.getPrivate()),
        "Bearer", 3600, "billing");
  }

  @Override
  public JwkSet jwks() {
    return new JwkSet(List.of(Jwk.forEd25519(KID, keyPair.getPublic())));
  }

  @Override
  public DiscoveryDocument discovery() {
    return new DiscoveryDocument(ISSUER, null, null);
  }

  @Override
  public List<AuditEntry> audit() {
    if (failAudit) {
      throw new ClientException("audit unavailable");
    }
    return List.of(new AuditEntry(Instant.now().getEpochSecond(), "token.issued", "svc_demo",
        "jti=jti-fake"));
  }

  @Override
  public RotationResult rotateSigningKey() {
    rotateCalls++;
    if (failRotate) {
      throw new ClientException("rotation unavailable");
    }
    return new RotationResult("rotated-kid");
  }

  @Override
  public HealthStatus health() {
    return new HealthStatus("ok");
  }
}

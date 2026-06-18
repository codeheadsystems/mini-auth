package com.codeheadsystems.minitoken.token;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minitoken.crypto.Ed25519Keys;
import com.codeheadsystems.minitoken.jwks.Jwk;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Guards the offline verifier against JOSE algorithm-confusion: a token whose {@code alg} header is
 * not {@code EdDSA} must be rejected even when its signature is, in fact, a valid Ed25519 signature
 * over the signing input. We pin the algorithm by checking the header — never letting the token's
 * own {@code alg} choose the verification path.
 */
class JwsClaimsVerifierTest {

  private static final String KID = "k1";
  private static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(1_000_000), ZoneOffset.UTC);

  @Test
  void rejectsTokenWhoseAlgIsNotEddsa() throws Exception {
    final KeyPair kp = Ed25519Keys.generate();
    final JwkSet jwks = new JwkSet(List.of(Jwk.forEd25519(KID, kp.getPublic())));
    final long now = CLOCK.instant().getEpochSecond();
    final String payload = "{\"iss\":\"https://op\",\"aud\":\"acc\",\"sub\":\"u\",\"nbf\":"
        + (now - 10) + ",\"exp\":" + (now + 300) + "}";

    // Positive control: a genuine EdDSA token verifies.
    assertTrue(JwsClaimsVerifier.verify(
        mint("EdDSA", payload, kp.getPrivate()), jwks, "https://op", "acc", CLOCK, 5).isPresent());

    // Forged alg headers — each validly Ed25519-signed — must NOT verify (no alg confusion).
    assertTrue(JwsClaimsVerifier.verify(
        mint("HS256", payload, kp.getPrivate()), jwks, "https://op", "acc", CLOCK, 5).isEmpty(),
        "alg=HS256 must be rejected");
    assertTrue(JwsClaimsVerifier.verify(
        mint("none", payload, kp.getPrivate()), jwks, "https://op", "acc", CLOCK, 5).isEmpty(),
        "alg=none must be rejected");
  }

  /** Mint a compact JWS with an arbitrary {@code alg} header, validly Ed25519-signed. */
  private static String mint(final String alg, final String payloadJson, final PrivateKey key)
      throws Exception {
    final String header = "{\"alg\":\"" + alg + "\",\"typ\":\"JWT\",\"kid\":\"" + KID + "\"}";
    final String signingInput = Base64Url.encode(header.getBytes(StandardCharsets.UTF_8))
        + "." + Base64Url.encode(payloadJson.getBytes(StandardCharsets.UTF_8));
    final Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(key);
    signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
    return signingInput + "." + Base64Url.encode(signer.sign());
  }
}

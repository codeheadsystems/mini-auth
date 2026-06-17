package com.codeheadsystems.minioidc.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PkceTest {

  // RFC 7636 Appendix B worked example.
  private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

  @Test
  void s256ChallengeVerifies() {
    assertTrue(Pkce.verify(Pkce.METHOD_S256, CHALLENGE, VERIFIER));
  }

  @Test
  void wrongVerifierIsRejected() {
    assertFalse(Pkce.verify(Pkce.METHOD_S256, CHALLENGE, "not-the-verifier"));
    assertFalse(Pkce.verify(Pkce.METHOD_S256, CHALLENGE, null));
  }

  @Test
  void plainMethodComparesVerbatim() {
    assertTrue(Pkce.verify(Pkce.METHOD_PLAIN, "abc", "abc"));
    assertFalse(Pkce.verify(Pkce.METHOD_PLAIN, "abc", "abd"));
  }
}

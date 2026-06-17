package com.codeheadsystems.minioidc.service;

import com.codeheadsystems.minitoken.jwks.Jwk;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.token.Base64Url;
import com.codeheadsystems.minitoken.token.Jws;
import com.codeheadsystems.minitoken.token.JwsHeader;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import java.security.PublicKey;
import java.time.Clock;
import java.util.Optional;

/**
 * Offline verification of a mini-oidc-minted ID or access token against a published {@link JwkSet}.
 *
 * <p>This is exactly what any relying party (or {@code /userinfo}, or a resource server) does with
 * one of our tokens and the JWKS — it needs no call back to the OP. It reuses the token plane's
 * primitives: select the key by the JWS {@code kid}, check the Ed25519 signature with mini-token's
 * {@link Jws#verifySignature}, then validate {@code iss} / {@code aud} / the {@code nbf}/{@code exp}
 * window. Signature first, so unsigned claim data is never trusted; on any failure it returns empty
 * — never an oracle for which check failed.
 */
public final class OidcTokenVerifier {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private OidcTokenVerifier() {
  }

  /**
   * Verify a compact JWS and return its claims.
   *
   * @param token            the compact JWS.
   * @param jwkSet           the published public keys.
   * @param expectedIssuer   the {@code iss} the token must carry.
   * @param expectedAudience the {@code aud} the token must carry (string, or an array containing it).
   * @param clock            the clock for the time-window check.
   * @param leewaySeconds    permitted clock skew on {@code nbf}/{@code exp}.
   * @return the verified claims as a JSON object, or empty if anything failed.
   */
  public static Optional<JsonNode> verify(final String token, final JwkSet jwkSet,
                                          final String expectedIssuer, final String expectedAudience,
                                          final Clock clock, final long leewaySeconds) {
    final Jws.Parts parts;
    final JwsHeader header;
    try {
      parts = Jws.split(token);
      header = Jws.parseHeader(parts);
    } catch (final RuntimeException e) {
      return Optional.empty();
    }
    final PublicKey key = publicKeyFor(jwkSet, header.keyId());
    if (key == null || !Jws.verifySignature(parts, key)) {
      return Optional.empty();
    }
    final JsonNode claims;
    try {
      claims = MAPPER.readTree(Base64Url.decode(parts.payload()));
    } catch (final RuntimeException e) {
      return Optional.empty();
    }
    if (expectedIssuer != null && !expectedIssuer.equals(text(claims, "iss"))) {
      return Optional.empty();
    }
    if (expectedAudience != null && !audienceMatches(claims.get("aud"), expectedAudience)) {
      return Optional.empty();
    }
    final long now = clock.instant().getEpochSecond();
    if (claims.has("nbf") && now + leewaySeconds < claims.get("nbf").asLong()) {
      return Optional.empty();
    }
    if (!claims.has("exp") || now - leewaySeconds >= claims.get("exp").asLong()) {
      return Optional.empty();
    }
    return Optional.of(claims);
  }

  private static boolean audienceMatches(final JsonNode aud, final String expected) {
    if (aud == null) {
      return false;
    }
    if (aud.isArray()) {
      for (final JsonNode entry : aud) {
        if (expected.equals(entry.asString())) {
          return true;
        }
      }
      return false;
    }
    return expected.equals(aud.asString());
  }

  private static String text(final JsonNode node, final String field) {
    return node.has(field) ? node.get(field).asString() : null;
  }

  private static PublicKey publicKeyFor(final JwkSet jwkSet, final String kid) {
    if (kid == null) {
      return null;
    }
    for (final Jwk jwk : jwkSet.keys()) {
      if (kid.equals(jwk.keyId())) {
        return jwk.toPublicKey();
      }
    }
    return null;
  }
}

package com.codeheadsystems.minitoken.token;

import com.codeheadsystems.minitoken.jwks.Jwk;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import java.security.PublicKey;
import java.time.Clock;
import java.util.Optional;

/**
 * Offline verification of any compact JWS minted by this token plane, returning its claims as JSON.
 *
 * <p>This is the reference verifier a relying party, a {@code /userinfo} endpoint, or a forward-auth
 * gateway uses with a token and the published JWKS — no call back to the issuer. It is claim-shape
 * agnostic (it returns a {@link JsonNode}), so it serves both mini-idp's fixed claim set and
 * mini-oidc's OIDC ID/access tokens. The order is load-bearing: select the key by the JWS
 * {@code kid}, check the Ed25519 signature with {@link Jws#verifySignature}, and only then read and
 * validate {@code iss} / {@code aud} / the {@code nbf}/{@code exp} window. On any failure it returns
 * empty — never an oracle for which check failed.
 */
public final class JwsClaimsVerifier {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private JwsClaimsVerifier() {
  }

  /**
   * Verify a compact JWS and return its claims.
   *
   * @param token            the compact JWS.
   * @param jwkSet           the published public keys.
   * @param expectedIssuer   the {@code iss} the token must carry (null to skip).
   * @param expectedAudience the {@code aud} the token must carry — a string, or an array containing
   *                         it (null to skip).
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
    // Pin the algorithm two ways: we only ever verify with an Ed25519 key (selected by kid), AND we
    // reject any header that does not declare EdDSA. Never let the token's own `alg` choose the
    // verification algorithm — that is the classic JOSE alg-confusion footgun (e.g. `alg: none`).
    if (!JwsHeader.ALG_EDDSA.equals(header.algorithm())) {
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

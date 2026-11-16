package com.codeheadsystems.miniidp.testkit;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.URI;
import java.net.URL;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A token verifier built the way config-server builds one, so this test fails if mini-idp stops
 * being acceptable to it. It mirrors, deliberately line for line where it matters,
 * {@code config-server/.../auth/TrustedIssuer.java}, {@code DiscoveryJwkSource.java} and
 * {@code IssuerUrls.java} in the config project:
 *
 * <ul>
 *   <li>keys found through {@code <issuer>/.well-known/openid-configuration}, whose {@code issuer}
 *       must equal the configured issuer and whose {@code jwks_uri} must be https or loopback http;</li>
 *   <li>Nimbus's JWKS source with a 5-minute cache, refetch on an unknown {@code kid} rate-limited
 *       to a 30-second window, one retry, and a one-day outage tolerance;</li>
 *   <li>{@code typ} of {@code JWT}, {@code at+jwt} or absent; config-server's algorithm set
 *       (RS/PS/ES 256/384/512, <b>no EdDSA</b>); required {@code iss}/{@code sub}/{@code aud}/
 *       {@code exp}, exact {@code iss}, the configured audience, 60 s of clock skew, and a
 *       non-blank {@code sub}.</li>
 * </ul>
 *
 * <p>It also counts JWKS fetches, so the rotation test can prove a new {@code kid} was found by
 * refetching rather than by luck.
 */
final class ConfigServerStyleVerifier {

  /** config-server's accepted algorithms (TrustedIssuer.ALGORITHMS): asymmetric, no EdDSA. */
  static final Set<JWSAlgorithm> ALGORITHMS = Set.of(
      JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
      JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512,
      JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512);

  private static final long CACHE_TTL_MILLIS = 5 * 60 * 1000L;
  private static final long REFRESH_INTERVAL_MILLIS = 30 * 1000L;
  private static final long OUTAGE_TOLERANCE_MILLIS = 24 * 60 * 60 * 1000L;
  private static final int CLOCK_SKEW_SECONDS = 60;
  private static final Set<String> LOOPBACK = Set.of("localhost", "127.0.0.1", "[::1]", "::1");

  private final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
  private final AtomicInteger jwksFetches = new AtomicInteger();

  ConfigServerStyleVerifier(final String issuer, final String audience) throws Exception {
    final ResourceRetriever http = new DefaultResourceRetriever(2000, 2000);
    final ResourceRetriever counting = url -> {
      if (!url.getPath().endsWith("openid-configuration")) {
        jwksFetches.incrementAndGet();
      }
      return http.retrieveResource(url);
    };
    final JWKSource<SecurityContext> keys = JWKSourceBuilder
        .<SecurityContext>create(discover(issuer, counting), counting)
        .cache(CACHE_TTL_MILLIS, JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT)
        .rateLimited(REFRESH_INTERVAL_MILLIS)
        .retrying(true)
        .outageTolerant(OUTAGE_TOLERANCE_MILLIS)
        .build();
    processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(
        JOSEObjectType.JWT, new JOSEObjectType("at+jwt"), null));
    processor.setJWSKeySelector(new JWSVerificationKeySelector<>(ALGORITHMS, keys));
    final DefaultJWTClaimsVerifier<SecurityContext> claims = new DefaultJWTClaimsVerifier<>(
        Set.of(audience),
        new JWTClaimsSet.Builder().issuer(issuer).build(),
        Set.of("iss", "sub", "aud", "exp"),
        null);
    claims.setMaxClockSkew(CLOCK_SKEW_SECONDS);
    processor.setJWTClaimsSetVerifier(claims);
  }

  /**
   * @return the token's subject (config-server's caller identity).
   * @throws Exception if config-server would refuse the token.
   */
  String verify(final String token) throws Exception {
    final String subject = processor.process(SignedJWT.parse(token), null).getSubject();
    if (subject == null || subject.isBlank()) {
      throw new IllegalStateException("blank sub");
    }
    return subject;
  }

  /** @return how many times the JWKS has been fetched. */
  int jwksFetches() {
    return jwksFetches.get();
  }

  /** DiscoveryJwkSource.discover(): issuer must match exactly; jwks_uri must be secure. */
  private static URL discover(final String issuer, final ResourceRetriever retriever) throws Exception {
    final String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
    final URL discovery = URI.create(base + "/.well-known/openid-configuration").toURL();
    final Map<String, Object> document =
        JSONObjectUtils.parse(retriever.retrieveResource(discovery).getContent());
    final String named = JSONObjectUtils.getString(document, "issuer");
    if (!issuer.equals(named)) {
      throw new KeySourceException("Discovery for " + issuer + " names a different issuer: " + named);
    }
    final URI jwks = JSONObjectUtils.getURI(document, "jwks_uri");
    if (!isSecure(jwks)) {
      throw new KeySourceException("insecure jwks_uri: " + jwks);
    }
    return jwks.toURL();
  }

  /** IssuerUrls.isSecure(). */
  static boolean isSecure(final URI url) {
    if (url == null || !url.isAbsolute() || url.getHost() == null || url.getRawFragment() != null) {
      return false;
    }
    final String scheme = url.getScheme().toLowerCase(Locale.ROOT);
    return scheme.equals("https")
        || scheme.equals("http") && LOOPBACK.contains(url.getHost().toLowerCase(Locale.ROOT));
  }
}

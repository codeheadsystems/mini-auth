package com.codeheadsystems.miniidp.testkit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.token.JwsClaimsVerifier;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * mini-idp as a trusted token issuer for config-server: tokens are obtained through the real
 * client-credentials endpoint and verified the way config-server verifies them
 * ({@link ConfigServerStyleVerifier}: Nimbus, keys via {@code /.well-known/openid-configuration},
 * config-server's algorithm set, which has no EdDSA).
 *
 * <p>The issuer is configured as an operator would for config-server: audience {@code config-server}
 * mapped to ES256, and a service account allowlisted for that audience.
 */
class ConfigServerCompatibilityTest {

  private static final String AUDIENCE = "config-server";
  private static final String CLIENT = "billing";
  private static final String SECRET = "billing-secret";
  private static final JsonMapper JSON = JsonMapper.builder().build();

  private TestIdp idp;

  @BeforeEach
  void start() {
    idp = TestIdp.builder().audienceAlgorithm(AUDIENCE, "ES256").start();
    idp.addServiceAccount(CLIENT, SECRET, AUDIENCE);
    idp.addServiceAccount("reports", "reports-secret"); // default audience only
  }

  @AfterEach
  void stop() {
    idp.close();
  }

  @Test
  void openIdDiscoveryMatchesTheIdpDocumentAndListsBothAlgorithms() throws Exception {
    final JsonNode openId = getJson("/.well-known/openid-configuration");
    final JsonNode idpDoc = getJson("/.well-known/idp-configuration");
    final JsonNode rfc8414 = getJson("/.well-known/oauth-authorization-server");

    assertEquals(idp.issuer(), openId.get("issuer").asString());
    assertEquals(idpDoc.get("issuer").asString(), openId.get("issuer").asString());
    assertEquals(idpDoc.get("jwks_uri").asString(), openId.get("jwks_uri").asString());
    assertEquals(openId, rfc8414);
    assertEquals(idp.issuer() + "/oauth/token", openId.get("token_endpoint").asString());
    assertEquals(List.of("client_credentials"), strings(openId.get("grant_types_supported")));
    assertTrue(strings(openId.get("token_endpoint_auth_methods_supported")).contains("client_secret_basic"));
    assertEquals(List.of("EdDSA", "ES256"), strings(openId.get("id_token_signing_alg_values_supported")));
    assertTrue(ConfigServerStyleVerifier.isSecure(URI.create(openId.get("jwks_uri").asString())));
  }

  @Test
  void validEs256TokenIsAccepted() throws Exception {
    final String token = idp.token(CLIENT, SECRET, AUDIENCE);

    final SignedJWT jwt = SignedJWT.parse(token);
    assertEquals(JWSAlgorithm.ES256, jwt.getHeader().getAlgorithm());
    assertEquals("JWT", jwt.getHeader().getType().getType());
    assertTrue(jwt.getHeader().getKeyID() != null && !jwt.getHeader().getKeyID().isBlank());
    // JWS ES256 wants raw R||S (64 bytes), not DER.
    assertEquals(64, jwt.getSignature().decode().length);
    assertEquals(List.of(AUDIENCE), jwt.getJWTClaimsSet().getAudience());

    final ConfigServerStyleVerifier verifier = new ConfigServerStyleVerifier(idp.issuer(), AUDIENCE);
    assertEquals(CLIENT, verifier.verify(token));
  }

  @Test
  void theAudienceParameterWorksLikeResource() throws Exception {
    final String token = tokenWith(Map.of("audience", AUDIENCE));
    assertEquals(CLIENT, new ConfigServerStyleVerifier(idp.issuer(), AUDIENCE).verify(token));
  }

  @Test
  void tokenForAnotherAudienceIsRefused() throws Exception {
    final ConfigServerStyleVerifier verifier = new ConfigServerStyleVerifier(idp.issuer(), AUDIENCE);
    // The default-audience token (mini-kms, EdDSA) must not be usable at config-server.
    final String miniKmsToken = idp.token(CLIENT, SECRET);
    assertThrows(BadJOSEException.class, () -> verifier.verify(miniKmsToken));
    // Nor an ES256 token whose audience is something else.
    final ConfigServerStyleVerifier otherAudience = new ConfigServerStyleVerifier(idp.issuer(), "other-service");
    assertThrows(BadJOSEException.class, () -> otherAudience.verify(idp.token(CLIENT, SECRET, AUDIENCE)));
  }

  @Test
  void aClientCannotRequestAnAudienceOutsideItsAllowlist() {
    final IllegalStateException refused =
        assertThrows(IllegalStateException.class, () -> idp.token("reports", "reports-secret", AUDIENCE));
    assertTrue(refused.getMessage().contains("invalid_target"), refused.getMessage());
    // Bad credentials stay the single generic invalid_client, whatever the audience.
    final IllegalStateException badSecret =
        assertThrows(IllegalStateException.class, () -> idp.token(CLIENT, "wrong", AUDIENCE));
    assertTrue(badSecret.getMessage().contains("invalid_client"), badSecret.getMessage());
  }

  @Test
  void afterAnEs256RotationTheNewKidIsFoundByRefetchingTheJwks() throws Exception {
    final ConfigServerStyleVerifier verifier = new ConfigServerStyleVerifier(idp.issuer(), AUDIENCE);
    final String before = idp.token(CLIENT, SECRET, AUDIENCE);
    assertEquals(CLIENT, verifier.verify(before));
    final int fetchesBefore = verifier.jwksFetches();

    final Map<String, String> kids = idp.rotateKeys();
    final String after = idp.token(CLIENT, SECRET, AUDIENCE);
    final String newKid = SignedJWT.parse(after).getHeader().getKeyID();
    assertEquals(kids.get("ES256"), newKid);
    assertNotEquals(SignedJWT.parse(before).getHeader().getKeyID(), newKid);

    // The cached JWKS lacks the new kid, so the verifier must refetch to accept the token.
    assertEquals(CLIENT, verifier.verify(after));
    assertTrue(verifier.jwksFetches() > fetchesBefore, "the new kid was found by refetching the JWKS");
    // The retired key is still published, so the token issued before the rotation still verifies.
    assertEquals(CLIENT, verifier.verify(before));
  }

  @Test
  void defaultAudienceTokensAreStillEdDsaAndVerifyAsBefore() throws Exception {
    final String token = idp.token("reports", "reports-secret");
    final JsonNode header = JSON.readTree(Base64.getUrlDecoder().decode(token.split("\\.")[0]));
    assertEquals("EdDSA", header.get("alg").asString());

    final JwkSet jwks = JSON.readValue(get("/.well-known/jwks.json"), JwkSet.class);
    final Optional<JsonNode> claims = JwsClaimsVerifier.verify(
        token, jwks, idp.issuer(), idp.defaultAudience(), Clock.systemUTC(), 0);
    assertTrue(claims.isPresent(), "EdDSA token verifies with mini-token's verifier, as before");
    assertEquals("reports", claims.get().get("sub").asString());
    assertEquals("mini-kms", claims.get().get("aud").asString());

    // config-server's algorithm set has no EdDSA, so it refuses EdDSA tokens outright.
    final ConfigServerStyleVerifier verifier = new ConfigServerStyleVerifier(idp.issuer(), "mini-kms");
    assertThrows(BadJOSEException.class, () -> verifier.verify(token));
  }

  // ---- helpers ------------------------------------------------------------------------------

  private String tokenWith(final Map<String, String> extra) throws Exception {
    final StringBuilder body = new StringBuilder(
        "grant_type=client_credentials&client_id=" + CLIENT + "&client_secret=" + SECRET);
    extra.forEach((key, value) -> body.append('&').append(key).append('=').append(value));
    final var response = HttpClient.newHttpClient().send(
        HttpRequest.newBuilder(URI.create(idp.issuer() + "/oauth/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body.toString())).build(),
        BodyHandlers.ofString());
    assertEquals(200, response.statusCode(), response.body());
    return JSON.readTree(response.body()).get("access_token").asString();
  }

  private String get(final String path) throws Exception {
    final var response = HttpClient.newHttpClient().send(
        HttpRequest.newBuilder(URI.create(idp.issuer() + path)).GET().build(), BodyHandlers.ofString());
    assertEquals(200, response.statusCode());
    return response.body();
  }

  private JsonNode getJson(final String path) throws Exception {
    return JSON.readTree(get(path));
  }

  private static List<String> strings(final JsonNode array) {
    return array.valueStream().map(JsonNode::asString).toList();
  }
}

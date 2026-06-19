package com.codeheadsystems.miniconsole.harness.flows;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Status;
import com.codeheadsystems.minioidc.client.MiniOidcClient;
import com.codeheadsystems.minioidc.client.model.AuthorizeRequest;
import com.codeheadsystems.minioidc.client.model.ClientRegistration;
import com.codeheadsystems.minioidc.client.model.ClientSummary;
import com.codeheadsystems.minioidc.client.model.DiscoveryDocument;
import com.codeheadsystems.minioidc.client.model.HealthStatus;
import com.codeheadsystems.minioidc.client.model.RegisteredClient;
import com.codeheadsystems.minioidc.client.model.RotationResult;
import com.codeheadsystems.minioidc.client.model.TokenResponse;
import com.codeheadsystems.minioidc.client.model.UserInfo;
import com.codeheadsystems.minitoken.crypto.Ed25519Keys;
import com.codeheadsystems.minitoken.jwks.Jwk;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.token.Jws;
import com.codeheadsystems.minitoken.token.JwsHeader;
import java.net.URI;
import java.security.KeyPair;
import java.time.Clock;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link OidcCodePkceFlow}, exercised against a fake {@link MiniOidcClient} with REAL
 * mini-token-signed id_tokens. They prove: with no code the flow honestly SKIPs the interactive
 * passkey step (never PASS) while surfacing the authorize URL + verifier; and with a code it verifies
 * the id_token offline (PASS), failing when the id_token is signed by a key not in the JWKS.
 */
class OidcCodePkceFlowTest {

  private static final String ISSUER = "http://oidc.test";
  private static final String CLIENT = "client-1";
  private static final String KID = "oidc-kid";
  private static final String SECRET = "the-client-secret";

  private final OidcCodePkceFlow flow = new OidcCodePkceFlow(Clock.systemUTC());

  @Test
  void noCode_skipsTheInteractiveLogin_honestly() {
    final FakeOidc oidc = new FakeOidc();
    final ExerciseResult result = flow.run(oidc,
        new OidcCodePkceFlow.Inputs(CLIENT, "https://app/cb", "openid", "", "", ""));
    assertEquals(Status.SKIP, result.status(), "no PASS without a real login");
    final ExerciseResult.Step last = result.steps().get(result.steps().size() - 1);
    assertEquals(Status.SKIP, last.status());
    assertTrue(last.detail().contains("authorize_url="));
    assertTrue(last.detail().contains("code_verifier="));
  }

  @Test
  void withCode_verifiesIdTokenOffline_andPasses() {
    final FakeOidc oidc = new FakeOidc();
    final ExerciseResult result = flow.run(oidc, new OidcCodePkceFlow.Inputs(
        CLIENT, "https://app/cb", "openid profile", SECRET, "auth-code", "the-verifier"));
    assertEquals(Status.PASS, result.status(), result.summary());
    assertTrue(result.steps().stream().anyMatch(
        s -> s.label().equals("Verify id_token offline") && s.status() == Status.PASS));
    // The supplied secret and the tokens never appear in the rendered facts.
    assertFalse(result.toString().contains(SECRET));
  }

  @Test
  void withCode_tamperedIdToken_failsVerification() {
    final FakeOidc oidc = new FakeOidc();
    oidc.signIdTokenWithForeignKey = true;
    final ExerciseResult result = flow.run(oidc, new OidcCodePkceFlow.Inputs(
        CLIENT, "https://app/cb", "openid", "", "auth-code", "the-verifier"));
    assertEquals(Status.FAIL, result.status());
    assertTrue(result.steps().stream().anyMatch(
        s -> s.label().equals("Verify id_token offline") && s.status() == Status.FAIL));
  }

  /** A canned OIDC client minting a real mini-token-signed id_token under a key it publishes. */
  private static final class FakeOidc implements MiniOidcClient {
    private final KeyPair keyPair = Ed25519Keys.generate();
    private final KeyPair foreignKey = Ed25519Keys.generate();
    private final Set<String> usedRefresh = new HashSet<>();
    boolean signIdTokenWithForeignKey;

    @Override
    public DiscoveryDocument discovery() {
      return new DiscoveryDocument(ISSUER, ISSUER + "/authorize", ISSUER + "/token",
          ISSUER + "/userinfo", ISSUER + "/jwks.json");
    }

    @Override
    public JwkSet jwks() {
      return new JwkSet(List.of(Jwk.forEd25519(KID, keyPair.getPublic())));
    }

    @Override
    public RegisteredClient registerClient(final ClientRegistration registration) {
      return new RegisteredClient("c", registration.confidential() ? "s" : null,
          registration.name(), registration.redirectUris(), registration.scopes(),
          registration.confidential());
    }

    @Override
    public List<ClientSummary> listClients() {
      return List.of();
    }

    @Override
    public URI authorizeUrl(final AuthorizeRequest request) {
      return URI.create(ISSUER + "/authorize?response_type=code&code_challenge="
          + request.codeChallenge() + "&code_challenge_method=S256");
    }

    @Override
    public TokenResponse exchangeCode(final String code, final String codeVerifier,
                                      final String redirectUri, final String clientId,
                                      final String clientSecret) {
      final long now = Clock.systemUTC().instant().getEpochSecond();
      final Map<String, Object> claims = new LinkedHashMap<>();
      claims.put("iss", ISSUER);
      claims.put("sub", "user-1");
      claims.put("aud", clientId);
      claims.put("iat", now);
      claims.put("nbf", now);
      claims.put("exp", now + 3600);
      claims.put("nonce", "harness-nonce");
      claims.put("auth_time", now);
      final KeyPair signer = signIdTokenWithForeignKey ? foreignKey : keyPair;
      final String idToken = Jws.sign(JwsHeader.forKid(KID), claims, signer.getPrivate());
      return new TokenResponse("access-token", "Bearer", 3600, idToken, "refresh-1", "openid");
    }

    @Override
    public TokenResponse refresh(final String refreshToken, final String clientId,
                                 final String clientSecret) {
      if (!usedRefresh.add(refreshToken)) {
        throw new ClientException("invalid_grant");  // replay of a rotated token — no oracle
      }
      return new TokenResponse("access-2", "Bearer", 3600, null, "refresh-2", "openid");
    }

    @Override
    public UserInfo userInfo(final String accessToken) {
      return new UserInfo("user-1", "User One", null, null);
    }

    @Override
    public RotationResult rotateSigningKey() {
      return new RotationResult("rotated");
    }

    @Override
    public HealthStatus health() {
      return new HealthStatus("ok");
    }
  }
}

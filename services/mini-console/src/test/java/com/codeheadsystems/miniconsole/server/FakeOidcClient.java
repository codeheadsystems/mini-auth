package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniclient.common.ClientException;
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
import java.net.URI;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

/**
 * A canned, in-memory {@link MiniOidcClient} for console tests — no real OP is booted. It publishes a
 * JWKS, registers clients (returning a one-time secret only for a confidential client), lists them
 * without secrets, and counts rotations. The OIDC harness flow's automatable parts run against it
 * (the interactive exchange is SKIPped). Flags drive the no-oracle paths.
 */
final class FakeOidcClient implements MiniOidcClient {

  static final String ISSUER = "http://oidc.test";
  static final String SECRET = "one-time-client-secret";

  boolean failList;
  boolean failRotate;
  int rotateCalls;

  private final KeyPair keyPair = Ed25519Keys.generate();
  private final List<ClientSummary> registered = new ArrayList<>();

  @Override
  public DiscoveryDocument discovery() {
    return new DiscoveryDocument(ISSUER, ISSUER + "/authorize", ISSUER + "/token",
        ISSUER + "/userinfo", ISSUER + "/jwks.json");
  }

  @Override
  public JwkSet jwks() {
    return new JwkSet(List.of(Jwk.forEd25519("oidc-kid", keyPair.getPublic())));
  }

  @Override
  public RegisteredClient registerClient(final ClientRegistration registration) {
    registered.add(new ClientSummary("client-" + registered.size(), registration.name(),
        registration.redirectUris(), registration.scopes(), registration.confidential(), 0L));
    return new RegisteredClient("client-" + (registered.size() - 1),
        registration.confidential() ? SECRET : null, registration.name(),
        registration.redirectUris(), registration.scopes(), registration.confidential());
  }

  @Override
  public List<ClientSummary> listClients() {
    if (failList) {
      throw new ClientException("clients unavailable");
    }
    return List.copyOf(registered);
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
    throw new ClientException("not exercised in the console SKIP-path test");
  }

  @Override
  public TokenResponse refresh(final String refreshToken, final String clientId,
                               final String clientSecret) {
    throw new ClientException("not exercised");
  }

  @Override
  public UserInfo userInfo(final String accessToken) {
    throw new ClientException("not exercised");
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

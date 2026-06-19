package com.codeheadsystems.minioidc.client;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.minioidc.client.model.AuthorizeRequest;
import com.codeheadsystems.minioidc.client.model.ClientRegistration;
import com.codeheadsystems.minioidc.client.model.ClientSummary;
import com.codeheadsystems.minioidc.client.model.DiscoveryDocument;
import com.codeheadsystems.minioidc.client.model.HealthStatus;
import com.codeheadsystems.minioidc.client.model.RegisteredClient;
import com.codeheadsystems.minioidc.client.model.RotationResult;
import com.codeheadsystems.minioidc.client.model.TokenResponse;
import com.codeheadsystems.minioidc.client.model.UserInfo;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import java.net.URI;
import java.util.List;

/**
 * A client for mini-oidc — the human SSO / OpenID Provider.
 *
 * <p>It speaks two surfaces: the <b>public</b> OIDC endpoints (discovery, JWKS, token, userinfo) and
 * the <b>admin</b> endpoints (client registration, signing-key rotation) guarded by mini-oidc's admin
 * bearer token. The returned {@link JwkSet} is mini-token's own published type, so an id_token can be
 * verified offline by feeding this JWKS straight into mini-token's verifier.
 *
 * <p>Every method may throw {@link ClientException} (the no-oracle collapse): a refused token, an
 * unknown client, and an unreachable OP are indistinguishable to the caller, by design.
 *
 * <p><b>What this client cannot do:</b> obtain an authorization code. That requires a human passkey
 * (WebAuthn) login at {@code /authorize}, which cannot be driven headlessly. {@link #authorizeUrl}
 * builds the URL a human opens; {@link #exchangeCode} completes the flow once a code is in hand.
 */
public interface MiniOidcClient {

  /** @return the OP's discovery document (issuer, endpoints, jwks_uri). */
  DiscoveryDocument discovery();

  /** @return the OP's published signing keys (mini-token's {@link JwkSet}), for offline verification. */
  JwkSet jwks();

  /**
   * Register a relying-party client (admin).
   *
   * @param registration the client to create.
   * @return the registered client — carries the one-time secret for a confidential client.
   * @throws ClientException on any failure (including a refused admin token — no oracle).
   */
  RegisteredClient registerClient(ClientRegistration registration);

  /**
   * @return the registered clients (admin) — never any secret material.
   * @throws ClientException on any failure.
   */
  List<ClientSummary> listClients();

  /**
   * Build the {@code /authorize} URL for the authorization-code + PKCE flow (a pure client-side
   * helper; no HTTP). {@code response_type=code} and {@code code_challenge_method=S256} are set here.
   *
   * @param request the authorize inputs (incl. the S256 code challenge).
   * @return the URL a human opens in a browser to authenticate and consent.
   */
  URI authorizeUrl(AuthorizeRequest request);

  /**
   * Exchange an authorization code for tokens (the {@code authorization_code} grant). The code is only
   * obtainable after a human passkey login completes at {@code /authorize}.
   *
   * @param code         the authorization code from the redirect.
   * @param codeVerifier the PKCE verifier matching the challenge sent at {@code /authorize}.
   * @param redirectUri  the redirect URI used at {@code /authorize}.
   * @param clientId     the client id.
   * @param clientSecret the client secret for a confidential client, or null for a public client.
   * @return the token response (access + id + refresh).
   * @throws ClientException on any failure (one generic {@code invalid_grant} — no oracle).
   */
  TokenResponse exchangeCode(String code, String codeVerifier, String redirectUri, String clientId,
                             String clientSecret);

  /**
   * Exchange a refresh token for a fresh token set (the {@code refresh_token} grant; the refresh token
   * rotates).
   *
   * @param refreshToken the current refresh token.
   * @param clientId     the client id.
   * @param clientSecret the client secret for a confidential client, or null.
   * @return the new token response.
   * @throws ClientException on any failure (one generic {@code invalid_grant} — no oracle).
   */
  TokenResponse refresh(String refreshToken, String clientId, String clientSecret);

  /**
   * Fetch the userinfo for an access token.
   *
   * @param accessToken the access token (sent as the bearer; held only for this call, never logged).
   * @return the userinfo claims.
   * @throws ClientException on any failure (a bad/expired token → generic — no oracle).
   */
  UserInfo userInfo(String accessToken);

  /**
   * Rotate the OP's signing key (admin): activate a fresh key; the retired key stays published.
   *
   * @return the new active key id.
   * @throws ClientException on any failure (including a refused admin token — no oracle).
   */
  RotationResult rotateSigningKey();

  /** @return the OP's liveness status. */
  HealthStatus health();

  /**
   * Build an HTTP-backed client.
   *
   * @param baseUri    the OP origin (e.g. {@code http://127.0.0.1:8477}).
   * @param adminToken the OP admin bearer token, used only for the {@code /admin/*} calls (held in
   *                   memory only, never logged).
   * @return a client over loopback-friendly transports.
   */
  static MiniOidcClient http(final URI baseUri, final String adminToken) {
    return new HttpMiniOidcClient(baseUri, adminToken);
  }
}

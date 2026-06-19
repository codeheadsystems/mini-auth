package com.codeheadsystems.minioidc.client;

import com.codeheadsystems.miniclient.common.HttpTransport;
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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

/**
 * The HTTP implementation of {@link MiniOidcClient}. It holds two {@link HttpTransport}s:
 *
 * <ul>
 *   <li>{@code publicTransport} — no bearer; for discovery, JWKS, {@code POST /token} (form-encoded),
 *       and {@code GET /health}.</li>
 *   <li>{@code adminTransport} — the OP admin bearer; for {@code /admin/clients} and
 *       {@code /admin/keys/rotate}.</li>
 * </ul>
 *
 * <p>{@code /userinfo} needs the per-call <i>access token</i> as its bearer (not the admin token), so
 * it builds a throwaway transport bound to that token. Paths mirror mini-oidc's {@code OidcHandlers}.
 */
final class HttpMiniOidcClient implements MiniOidcClient {

  private final URI baseUri;
  private final HttpTransport publicTransport;
  private final HttpTransport adminTransport;

  HttpMiniOidcClient(final URI baseUri, final String adminToken) {
    this.baseUri = baseUri;
    this.publicTransport = new HttpTransport(baseUri, null);
    this.adminTransport = new HttpTransport(baseUri, adminToken);
  }

  @Override
  public DiscoveryDocument discovery() {
    return publicTransport.get("/.well-known/openid-configuration", DiscoveryDocument.class);
  }

  @Override
  public JwkSet jwks() {
    return publicTransport.get("/jwks.json", JwkSet.class);
  }

  @Override
  public RegisteredClient registerClient(final ClientRegistration registration) {
    return adminTransport.post("/admin/clients", registration, RegisteredClient.class);
  }

  @Override
  public List<ClientSummary> listClients() {
    return adminTransport.getList("/admin/clients", ClientSummary.class);
  }

  @Override
  public URI authorizeUrl(final AuthorizeRequest request) {
    final StringJoiner query = new StringJoiner("&");
    query.add("response_type=code");
    query.add("client_id=" + enc(request.clientId()));
    query.add("redirect_uri=" + enc(request.redirectUri()));
    query.add("scope=" + enc(request.scope()));
    if (request.state() != null) {
      query.add("state=" + enc(request.state()));
    }
    if (request.nonce() != null) {
      query.add("nonce=" + enc(request.nonce()));
    }
    query.add("code_challenge=" + enc(request.codeChallenge()));
    query.add("code_challenge_method=S256");
    return URI.create(baseUri + "/authorize?" + query);
  }

  @Override
  public TokenResponse exchangeCode(final String code, final String codeVerifier,
                                    final String redirectUri, final String clientId,
                                    final String clientSecret) {
    final Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "authorization_code");
    form.put("code", code);
    form.put("redirect_uri", redirectUri);
    form.put("code_verifier", codeVerifier);
    form.put("client_id", clientId);
    if (clientSecret != null) {
      // client_secret_post: a confidential client's secret travels in the body, never the URL.
      form.put("client_secret", clientSecret);
    }
    return publicTransport.postForm("/token", form, TokenResponse.class);
  }

  @Override
  public TokenResponse refresh(final String refreshToken, final String clientId,
                               final String clientSecret) {
    final Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "refresh_token");
    form.put("refresh_token", refreshToken);
    form.put("client_id", clientId);
    if (clientSecret != null) {
      form.put("client_secret", clientSecret);
    }
    return publicTransport.postForm("/token", form, TokenResponse.class);
  }

  @Override
  public UserInfo userInfo(final String accessToken) {
    // The access token is the bearer here — a throwaway transport bound to it (held only for this
    // call, never logged), so the no-oracle collapse still applies.
    return new HttpTransport(baseUri, accessToken).get("/userinfo", UserInfo.class);
  }

  @Override
  public RotationResult rotateSigningKey() {
    return adminTransport.post("/admin/keys/rotate", Map.of(), RotationResult.class);
  }

  @Override
  public HealthStatus health() {
    return publicTransport.get("/health", HealthStatus.class);
  }

  private static String enc(final String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}

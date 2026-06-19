package com.codeheadsystems.miniidp.client;

import com.codeheadsystems.miniclient.common.HttpTransport;
import com.codeheadsystems.miniidp.client.model.DiscoveryDocument;
import com.codeheadsystems.miniidp.client.model.HealthStatus;
import com.codeheadsystems.miniidp.client.model.TokenResponse;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.model.AuditEntry;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The HTTP implementation of {@link MiniIdpClient}. It holds two {@link HttpTransport}s:
 *
 * <ul>
 *   <li>{@code publicTransport} — no bearer; for {@code POST /oauth/token} (form-encoded),
 *       {@code GET /.well-known/jwks.json}, {@code GET /.well-known/idp-configuration},
 *       {@code GET /health}.</li>
 *   <li>{@code adminTransport} — the IDP admin bearer; for {@code GET /admin/audit}.</li>
 * </ul>
 *
 * <p>Paths mirror mini-idp's {@code ApiHandlers} exactly. The token endpoint is the one form-encoded
 * call ({@link HttpTransport#postForm}); everything else is JSON.
 */
final class HttpMiniIdpClient implements MiniIdpClient {

  private final HttpTransport publicTransport;
  private final HttpTransport adminTransport;

  HttpMiniIdpClient(final URI baseUri, final String adminToken) {
    this.publicTransport = new HttpTransport(baseUri, null);
    this.adminTransport = new HttpTransport(baseUri, adminToken);
  }

  @Override
  public TokenResponse token(final String clientId, final String clientSecret) {
    // client_secret_post: credentials travel in the form body, never the URL. The secret is held in
    // this map only for the duration of the call and never logged.
    final Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "client_credentials");
    form.put("client_id", clientId);
    form.put("client_secret", clientSecret);
    return publicTransport.postForm("/oauth/token", form, TokenResponse.class);
  }

  @Override
  public JwkSet jwks() {
    return publicTransport.get("/.well-known/jwks.json", JwkSet.class);
  }

  @Override
  public DiscoveryDocument discovery() {
    return publicTransport.get("/.well-known/idp-configuration", DiscoveryDocument.class);
  }

  @Override
  public List<AuditEntry> audit() {
    return adminTransport.getList("/admin/audit", AuditEntry.class);
  }

  @Override
  public HealthStatus health() {
    return publicTransport.get("/health", HealthStatus.class);
  }
}

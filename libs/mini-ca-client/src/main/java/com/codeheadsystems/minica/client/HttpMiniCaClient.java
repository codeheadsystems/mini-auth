package com.codeheadsystems.minica.client;

import com.codeheadsystems.miniclient.common.HttpTransport;
import com.codeheadsystems.minica.client.model.Certificate;
import com.codeheadsystems.minica.client.model.HealthStatus;
import com.codeheadsystems.minica.client.model.IssuanceLogEntry;
import com.codeheadsystems.minica.client.model.IssueRequest;
import com.codeheadsystems.minica.client.model.RenewRequest;
import com.codeheadsystems.minica.client.model.RevocationEntry;
import com.codeheadsystems.minica.client.model.RevokeRequest;
import com.codeheadsystems.minica.client.model.RevokeResult;
import java.net.URI;
import java.time.Duration;
import java.util.List;

/**
 * The HTTP implementation of {@link MiniCaClient}. It holds two {@link HttpTransport}s:
 *
 * <ul>
 *   <li>{@code publicTransport} — no bearer; for {@code GET /ca} (PEM text), {@code GET /revocations},
 *       {@code GET /health}.</li>
 *   <li>{@code adminTransport} — the CA admin bearer; for {@code POST /issue}, {@code POST /renew},
 *       {@code POST /revoke}, {@code GET /log}.</li>
 * </ul>
 *
 * <p>Paths mirror mini-ca's {@code ApiHandlers} exactly. The trust anchor ({@code /ca}) is the one
 * endpoint that returns PEM rather than JSON ({@link HttpTransport#getText}); everything else is JSON.
 */
final class HttpMiniCaClient implements MiniCaClient {

  private final HttpTransport publicTransport;
  private final HttpTransport adminTransport;

  HttpMiniCaClient(final URI baseUri, final String adminToken) {
    this.publicTransport = new HttpTransport(baseUri, null);
    this.adminTransport = new HttpTransport(baseUri, adminToken);
  }

  @Override
  public String caCertificatePem() {
    return publicTransport.getText("/ca");
  }

  @Override
  public List<RevocationEntry> revocations() {
    return publicTransport.getList("/revocations", RevocationEntry.class);
  }

  @Override
  public Certificate issue(final String csrPem, final Duration ttl) {
    return adminTransport.post("/issue", new IssueRequest(csrPem, ttlSeconds(ttl), null),
        Certificate.class);
  }

  @Override
  public Certificate renew(final String csrPem, final Duration ttl, final String previousSerial) {
    return adminTransport.post("/renew", new RenewRequest(csrPem, ttlSeconds(ttl), null, previousSerial),
        Certificate.class);
  }

  @Override
  public void revoke(final String serial, final String reason) {
    // The response ({"revoked":serial}) is parsed and discarded — this method's contract is void.
    adminTransport.post("/revoke", new RevokeRequest(serial, reason), RevokeResult.class);
  }

  @Override
  public List<IssuanceLogEntry> issuanceLog() {
    return adminTransport.getList("/log", IssuanceLogEntry.class);
  }

  @Override
  public HealthStatus health() {
    return publicTransport.get("/health", HealthStatus.class);
  }

  /** @return the TTL in seconds, or null to let the CA apply its default. */
  private static Long ttlSeconds(final Duration ttl) {
    return ttl == null ? null : ttl.toSeconds();
  }
}

package com.codeheadsystems.minigateway.client;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.minigateway.client.model.HealthStatus;
import java.net.URI;

/**
 * A client for mini-gateway — the forward-auth endpoint a reverse proxy calls before forwarding a
 * request. mini-console uses it to <b>exercise</b> the gateway the way a proxy would: send a
 * {@code /verify} for a target route with (or without) the caller's credentials and observe the
 * decision.
 *
 * <p>It holds <b>no operator token</b>. {@code /verify} authorizes the credentials carried in the
 * request itself (a bearer access token or the shared SSO session cookie), and {@code /health} is
 * public — so unlike the other family clients there is no admin bearer to supply.
 *
 * <p><b>The no-oracle exception.</b> {@link #verify} deliberately maps the gateway's status to a
 * {@link VerifyOutcome} (200/302/401/403) instead of collapsing failures — distinguishing those
 * statuses is the proxy's whole job, and is mini-gateway's published contract. No response body is
 * read, so there is still no body oracle. {@link #health} keeps the normal collapse to
 * {@link ClientException}.
 */
public interface MiniGatewayClient {

  /**
   * Call {@code /verify} as a reverse proxy would and return the gateway's decision.
   *
   * @param request the proxied request to test (method/URI + the caller's credentials).
   * @return the mapped decision (AUTHORIZED / REDIRECT_LOGIN / UNAUTHENTICATED / FORBIDDEN).
   * @throws ClientException only on a transport failure or an unexpected (non-200/302/401/403)
   *     status — never to distinguish the four contract statuses from one another.
   */
  VerifyOutcome verify(VerifyRequest request);

  /**
   * @return the gateway's liveness status.
   * @throws ClientException on any failure (the normal no-oracle collapse).
   */
  HealthStatus health();

  /**
   * Build an HTTP-backed client.
   *
   * @param baseUri the gateway origin (e.g. {@code http://127.0.0.1:8488}).
   * @return a client over a loopback-friendly transport (redirects are never followed, so a 302 is
   *     observed rather than chased).
   */
  static MiniGatewayClient http(final URI baseUri) {
    return new HttpMiniGatewayClient(baseUri);
  }
}

package com.codeheadsystems.miniidp.client;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniidp.client.model.DiscoveryDocument;
import com.codeheadsystems.miniidp.client.model.HealthStatus;
import com.codeheadsystems.miniidp.client.model.RotationResult;
import com.codeheadsystems.miniidp.client.model.TokenResponse;
import com.codeheadsystems.minitoken.jwks.JwkSet;
import com.codeheadsystems.minitoken.model.AuditEntry;
import java.net.URI;
import java.util.List;

/**
 * A client for mini-idp — the machine token issuer.
 *
 * <p>It speaks two surfaces: the <b>public</b> OAuth/discovery/JWKS endpoints (no credential beyond
 * the per-call client secret on {@code /oauth/token}), and the <b>admin</b> audit endpoint (guarded
 * by mini-idp's admin bearer token, supplied when the client is built). The returned {@link JwkSet}
 * and {@link AuditEntry} are mini-token's own published types — so a verifier can feed the JWKS
 * straight into mini-token's {@code TokenVerifier} with no conversion.
 *
 * <p>Every method may throw {@link ClientException} (the no-oracle collapse): a refused credential, an
 * unknown client, and an unreachable IDP are indistinguishable to the caller, by design.
 *
 * <p>Slice 3 exposes the token/JWKS/discovery/audit/health surface the exercise harness and the Audit
 * page need; key rotation and revocation are added in a later slice.
 */
public interface MiniIdpClient {

  /**
   * Exchange client credentials for an access token (the OAuth 2.0 client_credentials grant,
   * {@code client_secret_post}).
   *
   * @param clientId     the service-account id (the token {@code sub}).
   * @param clientSecret the service-account secret — held only for this call, never logged.
   * @return the token response (the access token is a compact JWS).
   * @throws ClientException on any failure (wrong secret, unknown client, unreachable — no oracle).
   */
  TokenResponse token(String clientId, String clientSecret);

  /**
   * @return the IDP's published signing keys (mini-token's {@link JwkSet}), for offline verification.
   * @throws ClientException on any failure.
   */
  JwkSet jwks();

  /**
   * @return the IDP's discovery document (used for its declared {@code issuer}).
   * @throws ClientException on any failure.
   */
  DiscoveryDocument discovery();

  /**
   * @return the IDP's audit log (token issuance, key rotation, revocation — never any secret).
   * @throws ClientException on any failure (including a refused admin token — no oracle).
   */
  List<AuditEntry> audit();

  /**
   * Rotate the IDP's signing key: mint a fresh key and make it active. The retired key remains in the
   * JWKS so in-flight tokens still verify until it ages out.
   *
   * @return the new active key id.
   * @throws ClientException on any failure (including a refused admin token — no oracle).
   */
  RotationResult rotateSigningKey();

  /**
   * @return the IDP's liveness status.
   * @throws ClientException on any failure.
   */
  HealthStatus health();

  /**
   * Build an HTTP-backed client.
   *
   * @param baseUri    the IDP origin (e.g. {@code http://127.0.0.1:8455}).
   * @param adminToken the IDP admin bearer token, used only for {@code /admin/audit} (held in memory
   *                   only, never logged).
   * @return a client over loopback-friendly transports.
   */
  static MiniIdpClient http(final URI baseUri, final String adminToken) {
    return new HttpMiniIdpClient(baseUri, adminToken);
  }
}

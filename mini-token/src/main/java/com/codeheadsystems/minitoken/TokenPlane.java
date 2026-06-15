package com.codeheadsystems.minitoken;

/**
 * The seam for the shared token plane: issuing signed tokens and publishing the verification
 * keys that let any party validate them offline.
 *
 * <p>This interface is the contract that both token issuers in the family — mini-idp (machine
 * client-credentials) and mini-oidc (human SSO) — are intended to share, so the JWS signing,
 * JWKS publication, signing-key rotation, revocation, and audit logic lives in ONE place
 * instead of being re-implemented per service.
 *
 * <p><b>Scaffold.</b> The methods below are intentionally minimal placeholders so the module
 * compiles and the architecture is legible; none of the real machinery is implemented yet.
 *
 * <p>TODO(mini-token): extract from mini-idp's {@code core} the following and express them here:
 * <ul>
 *   <li>{@code token/Jws}, {@code JwsHeader}, {@code JwtClaims} — compact JWS issuance/parse.</li>
 *   <li>{@code jwks/Jwk}, {@code JwkSet} — the published verification key set.</li>
 *   <li>{@code service/SigningKeyService} — signing-key lifecycle + rotation (retain retired
 *       {@code kid}s across one token TTL so in-flight tokens keep verifying).</li>
 *   <li>{@code service/RevocationService} — {@code jti} denylist.</li>
 *   <li>{@code service/AuditService} — issuance/rotation/revocation audit trail.</li>
 * </ul>
 *
 * <p>TODO(mini-kms integration): the signing private keys this plane manages should ultimately be
 * wrapped by mini-kms rather than stored locally (the recursive integration described in
 * {@code docs/DIRECTION.md}). The wrap/unwrap boundary belongs behind this seam.
 */
public interface TokenPlane {

  /**
   * @return the id of the signing key currently minting new tokens (the active {@code kid}).
   *     Verifiers select keys from the JWKS by the {@code kid} carried in each token's header.
   */
  SigningKeyId activeKeyId();

  // TODO(mini-token): String issue(JwtClaims claims);           — sign a compact JWS.
  // TODO(mini-token): JwkSet jwks();                            — publish current + retired keys.
  // TODO(mini-token): void rotate();                           — activate a fresh signing key.
  // TODO(mini-token): void revoke(String jti);                 — add to the revocation denylist.
}

/**
 * The token-plane services that compose the {@link com.codeheadsystems.minitoken.token} primitives
 * into an issuer/verifier lifecycle, over the {@link com.codeheadsystems.minitoken.store.DocumentStore}
 * SPI.
 *
 * <ul>
 *   <li>{@link com.codeheadsystems.minitoken.service.SigningKeyService} — owns the Ed25519 keys:
 *       one active signer, retired keys kept published until they outlive the token TTL (rotation).</li>
 *   <li>{@link com.codeheadsystems.minitoken.service.TokenIssuer} — mints a signed token for a
 *       (subject, authorization).</li>
 *   <li>{@link com.codeheadsystems.minitoken.service.TokenVerifier} — the reference offline verifier
 *       (signature first, then registered claims + revocation).</li>
 *   <li>{@link com.codeheadsystems.minitoken.service.RevocationService} /
 *       {@link com.codeheadsystems.minitoken.service.AuditService} — the {@code jti} denylist and the
 *       append-only audit log.</li>
 * </ul>
 */
package com.codeheadsystems.minitoken.service;

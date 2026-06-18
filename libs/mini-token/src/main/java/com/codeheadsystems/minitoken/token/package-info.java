/**
 * The hand-rolled JOSE layer: the compact-serialization JWS and its pieces.
 *
 * <p>Read in this order to learn how a token is built and verified end to end:
 * <ol>
 *   <li>{@link com.codeheadsystems.minitoken.token.Base64Url} — base64url, the encoding every
 *       segment uses.</li>
 *   <li>{@link com.codeheadsystems.minitoken.token.JwsHeader} / {@link
 *       com.codeheadsystems.minitoken.token.JwtClaims} — the header (alg/typ/kid) and the standard
 *       claim set.</li>
 *   <li>{@link com.codeheadsystems.minitoken.token.Jws} — signs/verifies {@code
 *       base64url(header).base64url(payload)} with Ed25519; the load-bearing comment explains why
 *       the base64url <em>text</em> (never re-serialized JSON) is what gets signed.</li>
 *   <li>{@link com.codeheadsystems.minitoken.token.JwsClaimsVerifier} — the offline reference
 *       verifier: pin the algorithm + select key by kid, check the signature, then validate
 *       iss/aud/time; any failure returns empty (no oracle).</li>
 *   <li>{@link com.codeheadsystems.minitoken.token.GrantsClaim} — the {@code grants} authorization
 *       claim, the stable JSON contract that maps onto mini-kms's model.</li>
 * </ol>
 */
package com.codeheadsystems.minitoken.token;

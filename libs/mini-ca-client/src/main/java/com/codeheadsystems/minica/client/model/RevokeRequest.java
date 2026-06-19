package com.codeheadsystems.minica.client.model;

/**
 * Body of {@code POST /revoke}.
 *
 * @param serial the certificate serial to revoke (lowercase hex).
 * @param reason an optional operator-supplied reason (may be null).
 */
public record RevokeRequest(String serial, String reason) {
}

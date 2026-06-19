package com.codeheadsystems.minioidc.client.model;

import java.util.List;

/**
 * A request to register a relying-party client (the body of {@code POST /admin/clients}).
 *
 * @param name         a human label for the consent screen.
 * @param redirectUris the exact redirect URIs the client may use (at least one).
 * @param scopes       the scopes the client may request (a subset of openid/profile/email).
 * @param confidential whether to mint a client secret (else a public, PKCE-only client).
 */
public record ClientRegistration(String name, List<String> redirectUris, List<String> scopes,
                                 boolean confidential) {
}

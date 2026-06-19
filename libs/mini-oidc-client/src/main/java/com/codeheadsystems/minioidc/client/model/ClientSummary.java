package com.codeheadsystems.minioidc.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * A registered client as returned by {@code GET /admin/clients} — never includes secret material.
 *
 * @param clientId     the client id.
 * @param name         the human label.
 * @param redirectUris the registered redirect URIs.
 * @param scopes       the allowed scopes.
 * @param confidential whether the client has a secret (the secret itself is never listed).
 * @param createdAt    creation time (epoch seconds).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientSummary(String clientId, String name, List<String> redirectUris,
                            List<String> scopes, boolean confidential, long createdAt) {
}

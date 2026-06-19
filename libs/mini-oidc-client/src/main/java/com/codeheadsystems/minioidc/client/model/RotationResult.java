package com.codeheadsystems.minioidc.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The result of {@code POST /admin/keys/rotate} — the new active signing-key id.
 *
 * @param activeKid the id of the freshly activated key.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RotationResult(String activeKid) {
}

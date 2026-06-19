package com.codeheadsystems.miniidp.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The response of {@code POST /admin/keys/rotate} — mini-idp mints a fresh signing key and makes it
 * active, returning the new active key id. The retired key stays in the JWKS (so in-flight tokens
 * still verify) until it ages out.
 *
 * @param activeKid the id of the newly-active signing key.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RotationResult(String activeKid) {
}

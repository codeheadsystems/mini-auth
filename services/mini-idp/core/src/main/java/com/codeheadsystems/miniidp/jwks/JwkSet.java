package com.codeheadsystems.miniidp.jwks;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * A JWK Set (RFC 7517): the {@code {"keys":[...]}} document served at
 * {@code /.well-known/jwks.json}.
 *
 * <p>During key rotation this set holds more than one key: the freshly-activated signing key plus
 * any recently-retired keys that may still appear in not-yet-expired tokens. A verifier selects
 * the matching key by the token's {@code kid}. Retired keys remain published until every token
 * they could have signed has expired.
 *
 * @param keys the published public keys.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record JwkSet(@JsonProperty("keys") List<Jwk> keys) {

  /** Defensively copy the list. */
  public JwkSet {
    keys = keys == null ? List.of() : List.copyOf(keys);
  }
}

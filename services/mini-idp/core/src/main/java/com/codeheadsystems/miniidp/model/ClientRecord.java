package com.codeheadsystems.miniidp.model;

import com.codeheadsystems.minitoken.auth.Authorization;
import com.codeheadsystems.miniidp.secret.SecretHash;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A registered client in the client registry.
 *
 * <p>Holds the client's identity, the Argon2id hash of its secret (never the secret itself), the
 * {@link Authorization} an issued token will carry, and an enabled flag (a disabled client cannot
 * obtain tokens but its record is retained for audit). This is persisted as-is in the registry
 * JSON file; {@code secretHash} contains no recoverable secret material.
 *
 * @param clientId    the stable client identifier (becomes a token's {@code sub}).
 * @param displayName a human-friendly label for operators (optional, may be null).
 * @param secretHash  the Argon2id hash of the client secret.
 * @param authorization the grants/control-plane authority issued tokens carry.
 * @param enabled     whether the client may currently obtain tokens.
 * @param createdAt   creation time (epoch seconds).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientRecord(
    String clientId,
    String displayName,
    SecretHash secretHash,
    Authorization authorization,
    boolean enabled,
    long createdAt) {

  /** @return a copy of this record with a replaced authorization (used by the grants admin op). */
  public ClientRecord withAuthorization(final Authorization newAuthorization) {
    return new ClientRecord(clientId, displayName, secretHash, newAuthorization, enabled, createdAt);
  }

  /** @return a copy of this record with a replaced enabled flag. */
  public ClientRecord withEnabled(final boolean newEnabled) {
    return new ClientRecord(clientId, displayName, secretHash, authorization, newEnabled, createdAt);
  }
}

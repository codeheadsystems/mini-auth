package com.codeheadsystems.minioidc.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * The response of {@code POST /admin/clients} — a newly registered client. For a confidential client
 * it carries the <b>one-time plaintext secret</b>; for a public (PKCE-only) client the secret is
 * null.
 *
 * <p><b>Secret hygiene:</b> {@link #toString()} redacts the secret, so the record can never leak it
 * into a log or exception. Only an explicit {@link #clientSecret()} call (the console's once-only
 * banner) reads it. The secret is returned only here, at registration, and is not recoverable later.
 *
 * @param clientId     the new client id.
 * @param clientSecret the one-time plaintext secret (null for a public client) — display once.
 * @param name         the human label.
 * @param redirectUris the registered redirect URIs.
 * @param scopes       the allowed scopes.
 * @param confidential whether the client has a secret.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RegisteredClient(String clientId, String clientSecret, String name,
                               List<String> redirectUris, List<String> scopes, boolean confidential) {

  /** Redacts the secret — the record must never print it. */
  @Override
  public String toString() {
    return "RegisteredClient[clientId=" + clientId + ", clientSecret=<redacted>, name=" + name
        + ", redirectUris=" + redirectUris + ", scopes=" + scopes + ", confidential=" + confidential
        + "]";
  }
}

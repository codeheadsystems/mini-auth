package com.codeheadsystems.minioidc.model;

import com.codeheadsystems.minioidc.secret.SecretHash;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * A registered OIDC relying party (client).
 *
 * <p>Holds the client's identity, the exact redirect URIs it may use (an authorization-code flow
 * must redirect only to a pre-registered URI — open redirects are how codes get stolen), the scopes
 * it may request, and, for a <b>confidential</b> client, the Argon2id hash of its secret (never the
 * secret itself). A <b>public</b> client has a null {@code secretHash} and authenticates solely by
 * PKCE. Persisted as-is in {@code clients.json}; {@code secretHash} carries no recoverable secret.
 *
 * @param clientId     the stable client identifier (a token {@code aud}/{@code azp}).
 * @param name         a human-friendly label shown on the consent screen.
 * @param secretHash   the Argon2id hash of the client secret, or null for a public (PKCE-only) client.
 * @param redirectUris the exact redirect URIs this client may use; never null, never empty.
 * @param scopes       the scopes this client may request; never null. {@code openid} is implied.
 * @param createdAt    creation time (epoch seconds).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OidcClient(
    String clientId,
    String name,
    SecretHash secretHash,
    List<String> redirectUris,
    List<String> scopes,
    long createdAt) {

  /** Validate identity and defensively copy the lists. */
  public OidcClient {
    if (clientId == null || clientId.isBlank()) {
      throw new IllegalArgumentException("clientId must not be blank");
    }
    redirectUris = redirectUris == null ? List.of() : List.copyOf(redirectUris);
    scopes = scopes == null ? List.of() : List.copyOf(scopes);
  }

  /** @return whether this client authenticates with a secret (vs. a public PKCE-only client). */
  public boolean isConfidential() {
    return secretHash != null;
  }

  /** @return whether {@code redirectUri} is one of this client's exact registered URIs. */
  public boolean allowsRedirect(final String redirectUri) {
    return redirectUri != null && redirectUris.contains(redirectUri);
  }
}

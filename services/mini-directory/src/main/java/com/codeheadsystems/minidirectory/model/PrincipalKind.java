package com.codeheadsystems.minidirectory.model;

/**
 * What kind of actor an {@link Account} represents — the two identity types the family
 * distinguishes (see {@code docs/DIRECTION.md}: mini-oidc resolves humans, mini-idp resolves
 * service accounts).
 *
 * <p>Both kinds resolve to a mini-policy {@code Principal} the same way; the kind governs how the
 * identity authenticates: a {@link #HUMAN} carries no stored secret here (humans authenticate
 * interactively through mini-oidc), whereas a {@link #SERVICE_ACCOUNT} has a directory-held
 * Argon2id secret hash for the machine client-credentials flow.
 */
public enum PrincipalKind {

  /** A person. No secret is stored in the directory; credentials live with the human-SSO front door. */
  HUMAN,

  /** A non-human workload. Carries an Argon2id-hashed secret for client-credentials authentication. */
  SERVICE_ACCOUNT
}

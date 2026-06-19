package com.codeheadsystems.minidirectory.client.model;

/**
 * Whether a directory account is a person or a machine — the client-side copy of mini-directory's
 * {@code PrincipalKind}. Bound by enum name, so the wire values {@code "HUMAN"} /
 * {@code "SERVICE_ACCOUNT"} must match the directory's.
 */
public enum PrincipalKind {

  /** A person; authenticates interactively through mini-oidc, carries no secret in the directory. */
  HUMAN,

  /** A machine client; the directory holds an Argon2id hash of its secret. */
  SERVICE_ACCOUNT
}

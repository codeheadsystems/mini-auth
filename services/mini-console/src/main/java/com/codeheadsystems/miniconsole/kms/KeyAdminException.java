package com.codeheadsystems.miniconsole.kms;

/**
 * The single, generic failure of a {@link KeyGroupAdmin} operation.
 *
 * <p>Like the rest of the console, KMS access is <b>no-oracle</b>: a refused admin token, an unknown
 * key group, a disabled/active-version conflict, and an unreachable KMS all collapse to this one
 * exception with no distinguishing detail. The handler catches it and renders a generic page; the
 * cause (a {@code KmsClientException}) is kept only as the chained cause for local debugging, never
 * surfaced to the operator and never logged.
 */
public final class KeyAdminException extends RuntimeException {

  /** @param cause the underlying transport/KMS failure (not surfaced to the caller). */
  public KeyAdminException(final Throwable cause) {
    super("key administration failed", cause);
  }
}

package com.codeheadsystems.minipolicy;

/**
 * The outcome of a {@link PolicyEngine} decision: the access is either permitted or refused.
 *
 * <p>Deliberately binary (allow / deny) to match mini-kms's {@code boolean} authorization seam.
 * Any richer outcome (obligations, reasons) can be layered later without changing callers that
 * only need the allow/deny bit.
 */
public enum Decision {

  /** The request is permitted. */
  ALLOW,

  /** The request is refused. This is the safe default whenever no rule grants access. */
  DENY;

  /** @return whether this decision permits the request. */
  public boolean isAllowed() {
    return this == ALLOW;
  }
}

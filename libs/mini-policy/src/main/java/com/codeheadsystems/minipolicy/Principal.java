package com.codeheadsystems.minipolicy;

/**
 * The authenticated identity a decision is made about.
 *
 * <p>Generalizes mini-kms's {@code auth/Principal}: a stable {@code id} plus an {@code admin}
 * flag. The semantics are deliberately preserved across the family — {@code id} maps to a token
 * {@code sub} / a mini-kms principal id, and {@code admin} is the "control" capability (a
 * mini-idp token's {@code grants.control}, mini-kms's control-plane principal). A
 * {@link GrantBasedPolicyEngine} treats an {@code admin} principal as permitted everything, the
 * same way mini-idp's {@code grants.control} implies full authority.
 *
 * @param id    a stable identifier for the caller; must be present.
 * @param admin whether the caller holds the control/admin capability.
 */
public record Principal(String id, boolean admin) {

  /** Validate: a principal must always be identifiable. */
  public Principal {
    if (id == null || id.isBlank()) {
      throw new IllegalArgumentException("principal id must not be blank");
    }
  }

  /**
   * @param id the caller's identifier.
   * @return a non-admin principal.
   */
  public static Principal of(final String id) {
    return new Principal(id, false);
  }

  /**
   * @param id the caller's identifier.
   * @return a principal holding the control/admin capability.
   */
  public static Principal admin(final String id) {
    return new Principal(id, true);
  }
}

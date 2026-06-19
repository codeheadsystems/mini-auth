package com.codeheadsystems.minitoken.auth;

import java.util.ArrayList;
import java.util.List;

/**
 * The complete authorization payload granted to a client, carried inside an issued token.
 *
 * <p>It is the union of the two planes mini-kms distinguishes:
 * <ul>
 *   <li>{@code controlPlane} — whether the client may perform key-management (admin) operations.
 *       This maps directly onto mini-kms's {@code Principal.admin} flag: a verified token with
 *       {@code controlPlane = true} becomes an admin principal there.</li>
 *   <li>{@code grants} — the per-key-group data-plane {@link KeyOperation}s the client may
 *       perform. mini-kms feeds these to a per-key-group {@code PolicyEngine} decision (mini-policy).</li>
 * </ul>
 *
 * <p>The clientId is NOT stored here; it is the token subject ({@code sub}) and becomes the
 * mini-kms {@code Principal.id}. This separation keeps the authorization payload purely about
 * "what may be done", with "who" supplied by the subject claim.
 *
 * @param controlPlane whether the client is authorized for control-plane (admin) operations.
 * @param grants       the per-key-group data-plane grants; may be empty (a control-only or
 *                     deliberately-unprivileged client).
 */
public record Authorization(boolean controlPlane, List<Grant> grants) {

  /** Defensively copy the grant list so the record is immutable. */
  public Authorization {
    grants = grants == null ? List.of() : List.copyOf(grants);
  }

  /** An authorization with no control-plane access and no data grants. */
  public static Authorization none() {
    return new Authorization(false, List.of());
  }

  /** @return data-plane grants only (control plane is a separate boolean). */
  public static Authorization ofGrants(final List<Grant> grants) {
    return new Authorization(false, grants);
  }

  /** @return a mutable copy of the grants (callers building tokens may need to iterate/transform). */
  public List<Grant> grantsCopy() {
    return new ArrayList<>(grants);
  }
}

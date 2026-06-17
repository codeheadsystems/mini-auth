package com.codeheadsystems.minitoken.auth;

import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A client's granted access to a single key group: the group id plus the set of
 * {@link KeyOperation}s the client may perform against it.
 *
 * <p>This is the atom of mini-idp's authorization model and the shape that travels inside the
 * token's authorization claim (see {@code com.codeheadsystems.minitoken.token}). A verifier
 * (mini-kms) turns a verified token's grants into per-group authorization decisions: "may this
 * principal {@code DECRYPT} under group {@code billing}?" becomes a lookup over these records.
 *
 * @param keyGroup   the key-group identifier this grant applies to (opaque to mini-idp).
 * @param operations the operations permitted on that group; never empty.
 */
public record Grant(String keyGroup, Set<KeyOperation> operations) {

  /** Validate and defensively copy into a stable, deduplicated set. */
  public Grant {
    if (keyGroup == null || keyGroup.isBlank()) {
      throw new IllegalArgumentException("grant keyGroup must not be blank");
    }
    if (operations == null || operations.isEmpty()) {
      throw new IllegalArgumentException("grant operations must not be empty");
    }
    // Copy so the record is immutable regardless of what the caller passed.
    operations = new LinkedHashSet<>(operations);
    if (operations.contains(null)) {
      throw new IllegalArgumentException("grant operations must not contain null");
    }
  }

  /** Convenience factory taking varargs operations. */
  public static Grant of(final String keyGroup, final KeyOperation... operations) {
    return new Grant(keyGroup, EnumSet.copyOf(Set.of(operations)));
  }
}

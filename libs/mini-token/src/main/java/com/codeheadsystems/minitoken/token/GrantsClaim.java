package com.codeheadsystems.minitoken.token;

import com.codeheadsystems.minitoken.auth.Authorization;
import com.codeheadsystems.minitoken.auth.Grant;
import com.codeheadsystems.minitoken.auth.KeyOperation;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The JSON wire shape of the {@code grants} authorization claim inside a mini-idp token.
 *
 * <p>This is the on-the-wire mirror of {@link Authorization}: a {@code control} boolean (maps to
 * mini-kms {@code Principal.admin}) and a list of per-group operation grants (each maps to a
 * {@code KeyAuthorizationPolicy} entry). It is intentionally a separate type from the domain
 * {@link Authorization}/{@link Grant} so the JSON contract is explicit and stable — the field
 * names here ARE the published contract the mini-kms team integrates against.
 *
 * @param control whether the client holds control-plane (admin) authority.
 * @param groups  per-key-group grants; never null (empty list when there are none).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record GrantsClaim(
    @JsonProperty("control") boolean control,
    @JsonProperty("groups") List<Group> groups) {

  /**
   * A single key-group grant in wire form.
   *
   * @param keyGroup   the key-group id.
   * @param operations the granted operations, as {@link KeyOperation} names.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Group(
      @JsonProperty("keyGroup") String keyGroup,
      @JsonProperty("operations") List<String> operations) {
  }

  /** Project a domain {@link Authorization} into its wire form. */
  public static GrantsClaim from(final Authorization authorization) {
    final List<Group> groups = new ArrayList<>();
    for (final Grant grant : authorization.grants()) {
      final List<String> ops = new ArrayList<>();
      for (final KeyOperation op : grant.operations()) {
        ops.add(op.name());
      }
      groups.add(new Group(grant.keyGroup(), ops));
    }
    return new GrantsClaim(authorization.controlPlane(), groups);
  }

  /**
   * Rebuild a domain {@link Authorization} from this claim, validating operation names.
   *
   * <p>This is the step a verifier (mini-kms) performs to turn a parsed token into something it
   * can authorize against. Unknown operation names are rejected loudly rather than silently
   * dropped, so a typo in a grant cannot quietly widen or narrow access.
   */
  public Authorization toAuthorization() {
    final List<Grant> grants = new ArrayList<>();
    if (groups != null) {
      for (final Group group : groups) {
        final Set<KeyOperation> ops = new LinkedHashSet<>();
        if (group.operations() != null) {
          for (final String op : group.operations()) {
            ops.add(KeyOperation.valueOf(op));
          }
        }
        grants.add(new Grant(group.keyGroup(), ops));
      }
    }
    return new Authorization(control, grants);
  }
}

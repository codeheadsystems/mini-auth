package com.codeheadsystems.miniidp.directory;

import com.codeheadsystems.minitoken.auth.Authorization;
import com.codeheadsystems.minitoken.auth.Grant;
import com.codeheadsystems.minitoken.auth.KeyOperation;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import tools.jackson.databind.JsonNode;

/**
 * Rebuilds a mini-token {@link Authorization} from mini-directory's resolution shape.
 *
 * <p>mini-directory expresses a principal's grants as flat {@code (action, resource)} pairs — the
 * generalized mini-policy form. A mini-idp client's authorization is the specialization where the
 * action is a {@link KeyOperation} name and the resource is a key group, plus a control-plane flag
 * (the directory's {@code admin}). This regroups the resolved grants back into the per-key-group
 * shape mini-idp's {@code grants} claim carries, so a token issued from mini-directory is identical
 * to one the old local registry would have produced.
 *
 * <p>Grants whose action is not a known {@link KeyOperation}, or whose resource is the wildcard
 * {@code "*"}, are ignored: they belong to other consumers (e.g. OIDC scopes) and are not part of
 * mini-idp's key-group authorization.
 *
 * <p><b>Audience allowlist.</b> The audiences a service account may request per token are stored in
 * mini-directory as ordinary grants with the action {@value #AUDIENCE_ACTION} and the audience as
 * the resource — e.g. {@code {"action":"token:audience","resource":"config-server"}}. That keeps the
 * allowlist in the identity source of truth with no new directory schema; {@link #audiences} reads
 * it back. A wildcard resource is <em>not</em> honored: the allowlist is always explicit.
 */
public final class Authorizations {

  private Authorizations() {
  }

  /**
   * @param admin  the directory principal's control/admin flag.
   * @param grants the resolved grants, each a JSON object with {@code action} + {@code resource}.
   * @return the reconstructed {@link Authorization}.
   */
  public static Authorization fromResolution(final boolean admin, final JsonNode grants) {
    final Map<String, List<KeyOperation>> byKeyGroup = new LinkedHashMap<>();
    if (grants != null) {
      for (final JsonNode grant : grants) {
        final String resource = text(grant, "resource");
        final KeyOperation op = keyOperation(text(grant, "action"));
        if (op == null || resource == null || "*".equals(resource)) {
          continue;
        }
        byKeyGroup.computeIfAbsent(resource, key -> new ArrayList<>()).add(op);
      }
    }
    final List<Grant> result = new ArrayList<>();
    byKeyGroup.forEach((keyGroup, ops) ->
        result.add(new Grant(keyGroup, new java.util.LinkedHashSet<>(ops))));
    return new Authorization(admin, result);
  }

  /** The directory grant action that allowlists an audience for a service account. */
  public static final String AUDIENCE_ACTION = "token:audience";

  /**
   * @param grants the resolved grants, each a JSON object with {@code action} + {@code resource}.
   * @return the audiences the account may request (the resources of its {@value #AUDIENCE_ACTION}
   *     grants, excluding the wildcard).
   */
  public static Set<String> audiences(final JsonNode grants) {
    final Set<String> result = new LinkedHashSet<>();
    if (grants != null) {
      for (final JsonNode grant : grants) {
        final String resource = text(grant, "resource");
        if (AUDIENCE_ACTION.equals(text(grant, "action")) && resource != null
            && !resource.isBlank() && !"*".equals(resource)) {
          result.add(resource);
        }
      }
    }
    return result;
  }

  private static KeyOperation keyOperation(final String action) {
    if (action == null) {
      return null;
    }
    try {
      return KeyOperation.valueOf(action);
    } catch (final IllegalArgumentException e) {
      return null;
    }
  }

  private static String text(final JsonNode node, final String field) {
    return node.has(field) && !node.get(field).isNull() ? node.get(field).asString() : null;
  }
}

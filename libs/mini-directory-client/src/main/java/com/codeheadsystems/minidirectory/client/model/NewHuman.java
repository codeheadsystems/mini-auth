package com.codeheadsystems.minidirectory.client.model;

import java.util.List;

/**
 * The body of {@code POST /admin/humans} — the client-side copy of mini-directory's
 * {@code CreateHumanRequest}. A human carries no secret; only an id, an optional label, and its
 * authorization (admin flag + memberships + roles + direct grants).
 *
 * @param id          the operator-chosen id (e.g. a username); required.
 * @param displayName optional human label (may be null).
 * @param admin       whether the human holds the control/admin capability.
 * @param memberOf    group ids the human joins (may be empty).
 * @param roles       role ids assigned directly (may be empty).
 * @param grants      direct grants (may be empty).
 */
public record NewHuman(String id, String displayName, boolean admin, List<String> memberOf,
                       List<String> roles, List<GrantSpec> grants) {
}

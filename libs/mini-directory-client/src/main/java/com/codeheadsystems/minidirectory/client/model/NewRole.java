package com.codeheadsystems.minidirectory.client.model;

import java.util.List;

/**
 * The body of {@code POST /admin/roles} — the client-side copy of mini-directory's
 * {@code RoleRequest}. A role is a reusable, named bundle of grants.
 *
 * @param id          the role id; required.
 * @param description an optional human label (may be null).
 * @param grants      the grants this role confers (may be empty).
 */
public record NewRole(String id, String description, List<GrantSpec> grants) {
}

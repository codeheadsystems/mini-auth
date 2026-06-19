package com.codeheadsystems.minidirectory.client.model;

import java.util.List;

/**
 * The body of {@code POST /admin/groups} — the client-side copy of mini-directory's
 * {@code GroupRequest}. A group is a reusable bundle of roles + direct grants its members inherit.
 *
 * @param id          the group id; required.
 * @param description an optional human label (may be null).
 * @param roles       role ids this group confers (may be empty).
 * @param grants      direct grants members inherit (may be empty).
 */
public record NewGroup(String id, String description, List<String> roles, List<GrantSpec> grants) {
}

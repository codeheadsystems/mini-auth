package com.codeheadsystems.minidirectory.client.model;

import java.util.List;

/**
 * The body of {@code PUT /admin/principals/{id}/assignment} — the client-side copy of
 * mini-directory's {@code AssignmentRequest}. It <b>replaces</b> an account's authorization wholesale
 * (enabled flag + admin flag + memberships + roles + direct grants), so a caller sends the complete
 * desired state, not a delta.
 *
 * @param enabled  whether the account remains active.
 * @param admin    whether it holds the control/admin capability.
 * @param memberOf group ids it belongs to (may be empty).
 * @param roles    role ids assigned directly (may be empty).
 * @param grants   direct grants (may be empty).
 */
public record Assignment(boolean enabled, boolean admin, List<String> memberOf, List<String> roles,
                         List<GrantSpec> grants) {
}

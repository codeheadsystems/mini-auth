package com.codeheadsystems.minidirectory.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * The result of resolving a principal — the client-side copy of mini-directory's {@code
 * ResolutionView}. The {@code grants} here are the <b>fully expanded, de-duplicated</b> set (roles
 * and group memberships already flattened), i.e. exactly what a policy engine decides over.
 *
 * @param id     the principal id.
 * @param admin  whether the principal holds the control/admin capability.
 * @param grants the effective, flattened grants.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Resolution(String id, boolean admin, List<GrantSpec> grants) {
}

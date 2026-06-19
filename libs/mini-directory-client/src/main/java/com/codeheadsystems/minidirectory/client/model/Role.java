package com.codeheadsystems.minidirectory.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * A role as the directory returns it — a reusable, named bundle of grants. Client-side copy of
 * mini-directory's {@code Role}.
 *
 * @param id          the role id.
 * @param description an optional human label.
 * @param grants      the grants this role confers.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Role(String id, String description, List<GrantSpec> grants) {
}

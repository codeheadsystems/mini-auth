package com.codeheadsystems.minidirectory.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * A group as the directory returns it — a reusable bundle of roles + direct grants that members
 * inherit. Client-side copy of mini-directory's {@code Group}.
 *
 * @param id          the group id.
 * @param description an optional human label.
 * @param roles       role ids this group confers.
 * @param grants      direct grants members inherit.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Group(String id, String description, List<String> roles, List<GrantSpec> grants) {
}

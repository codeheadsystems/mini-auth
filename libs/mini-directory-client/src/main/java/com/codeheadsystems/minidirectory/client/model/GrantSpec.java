package com.codeheadsystems.minidirectory.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * One permission as the directory speaks it: a flat {@code (action, resource)} pair — the client-side
 * copy of mini-directory's {@code GrantSpec}. {@code "*"} is the wildcard for either coordinate.
 *
 * @param action   the permitted action (a mini-kms key operation today, or {@code "*"}).
 * @param resource the permitted resource (a key-group id today, or {@code "*"}).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GrantSpec(String action, String resource) {
}

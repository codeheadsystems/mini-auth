package com.codeheadsystems.minioidc.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The {@code /userinfo} response for the authenticated subject. {@code name}/{@code email} appear
 * only when the matching scope was granted; unknown claims are ignored.
 *
 * @param subject       the subject identifier (always present).
 * @param name          the display name (scope {@code profile}), or null.
 * @param email         the email (scope {@code email}), or null.
 * @param emailVerified whether the email is verified (scope {@code email}), or null.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserInfo(
    @JsonProperty("sub") String subject,
    @JsonProperty("name") String name,
    @JsonProperty("email") String email,
    @JsonProperty("email_verified") Boolean emailVerified) {
}

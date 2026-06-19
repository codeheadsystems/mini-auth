package com.codeheadsystems.minica.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Response of {@code POST /revoke} ({@code {"revoked":"<serial>"}}). Parsed and discarded by the
 * client's {@code revoke} (which returns void) — present only so the JSON response has a target type.
 *
 * @param revoked the serial that was revoked.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RevokeResult(String revoked) {
}

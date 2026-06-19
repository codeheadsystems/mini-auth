package com.codeheadsystems.miniidp.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The body of mini-idp's {@code GET /health} — a single status string (e.g. {@code "ok"}).
 *
 * @param status the liveness status.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record HealthStatus(String status) {
}

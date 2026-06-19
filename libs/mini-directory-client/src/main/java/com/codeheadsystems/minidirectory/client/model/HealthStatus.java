package com.codeheadsystems.minidirectory.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The body of {@code GET /health} — {@code {"status":"ok"}} when the directory is up.
 *
 * @param status the liveness status (e.g. {@code "ok"}).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record HealthStatus(String status) {
}

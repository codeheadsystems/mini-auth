package com.codeheadsystems.minioidc.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The {@code /health} response.
 *
 * @param status the liveness status (e.g. {@code ok}).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record HealthStatus(String status) {
}

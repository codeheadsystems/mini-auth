package com.codeheadsystems.minica.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The CA's liveness response ({@code {"status":"ok"}}).
 *
 * @param status the reported status (e.g. {@code "ok"}).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record HealthStatus(String status) {
}

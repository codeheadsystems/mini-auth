package com.codeheadsystems.miniidp.server.http;

import java.nio.charset.StandardCharsets;

/**
 * A fully-formed HTTP response: status, content type, and the raw body bytes.
 *
 * <p>Handlers return one of these and the {@link Router} writes it to the exchange. Keeping it a
 * small immutable value (rather than writing to the exchange inside each handler) keeps handlers
 * pure and easy to test.
 *
 * @param status      the HTTP status code.
 * @param contentType the {@code Content-Type} header value.
 * @param body        the response body bytes (never null; empty for no-content).
 */
public record HttpResponse(int status, String contentType, byte[] body) {

  /** A JSON response from an already-serialized value. */
  public static HttpResponse json(final int status, final Object value) {
    return new HttpResponse(status, "application/json", Json.toBytes(value));
  }

  /** A 204 No Content response. */
  public static HttpResponse noContent() {
    return new HttpResponse(204, "application/json", new byte[0]);
  }

  /** A response with an explicit content type and raw bytes (e.g. YAML, JS, CSS, HTML). */
  public static HttpResponse raw(final int status, final String contentType, final byte[] body) {
    return new HttpResponse(status, contentType, body);
  }

  /** A text response. */
  public static HttpResponse text(final int status, final String contentType, final String body) {
    return new HttpResponse(status, contentType, body.getBytes(StandardCharsets.UTF_8));
  }
}

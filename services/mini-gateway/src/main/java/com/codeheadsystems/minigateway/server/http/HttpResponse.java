package com.codeheadsystems.minigateway.server.http;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * A fully-formed HTTP response: status, content type, body bytes, and any extra headers (e.g.
 * {@code Location} for a redirect and one or more {@code Set-Cookie}s).
 *
 * <p>Handlers return one of these and the {@link Router} writes it to the exchange. Keeping it an
 * immutable value (rather than writing to the exchange inside each handler) keeps handlers pure and
 * testable. {@link #header} returns a copy with the header appended, so {@code Set-Cookie} can
 * appear more than once.
 *
 * @param status      the HTTP status code.
 * @param contentType the {@code Content-Type} header value.
 * @param body        the response body bytes (never null; empty for no-content / redirects).
 * @param headers     extra response headers, in order (name/value pairs; repeats allowed).
 */
public record HttpResponse(int status, String contentType, byte[] body, List<Header> headers) {

  /** A single response header (name + value). */
  public record Header(String name, String value) {
  }

  public HttpResponse {
    headers = headers == null ? List.of() : List.copyOf(headers);
  }

  /** A JSON response from an already-serialized value. */
  public static HttpResponse json(final int status, final Object value) {
    return new HttpResponse(status, "application/json", Json.toBytes(value), List.of());
  }

  /** A 204 No Content response. */
  public static HttpResponse noContent() {
    return new HttpResponse(204, "application/json", new byte[0], List.of());
  }

  /** A response with an explicit content type and raw bytes (e.g. YAML, JS, CSS, HTML). */
  public static HttpResponse raw(final int status, final String contentType, final byte[] body) {
    return new HttpResponse(status, contentType, body, List.of());
  }

  /** A text response. */
  public static HttpResponse text(final int status, final String contentType, final String body) {
    return new HttpResponse(status, contentType, body.getBytes(StandardCharsets.UTF_8), List.of());
  }

  /** An HTML response (200). */
  public static HttpResponse html(final String body) {
    return text(200, "text/html; charset=utf-8", body);
  }

  /** A 302 redirect to {@code location} (the browser-flow workhorse). */
  public static HttpResponse redirect(final String location) {
    return new HttpResponse(302, "text/plain", new byte[0], List.of(new Header("Location", location)));
  }

  /** @return a copy of this response with an extra header appended (e.g. {@code Set-Cookie}). */
  public HttpResponse header(final String name, final String value) {
    final List<Header> next = new ArrayList<>(headers);
    next.add(new Header(name, value));
    return new HttpResponse(status, contentType, body, next);
  }
}

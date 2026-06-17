package com.codeheadsystems.minioidc.server.http;

import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Per-request view handed to a handler: the underlying exchange plus the matched path parameters
 * and convenience accessors for the body, headers, and form fields.
 *
 * <p>This keeps {@link com.sun.net.httpserver.HttpExchange} at arm's length so handlers deal in
 * small, testable accessors rather than the raw servlet-like API.
 */
public final class RequestContext {

  private final HttpExchange exchange;
  private final Map<String, String> pathParams;
  private byte[] cachedBody;

  RequestContext(final HttpExchange exchange, final Map<String, String> pathParams) {
    this.exchange = exchange;
    this.pathParams = pathParams;
  }

  /** @return the matched path parameter, or null if absent. */
  public String pathParam(final String name) {
    return pathParams.get(name);
  }

  /** @return a request header value, or null if absent. */
  public String header(final String name) {
    return exchange.getRequestHeaders().getFirst(name);
  }

  /** @return the decoded query-string parameters (for GET endpoints like {@code /authorize}). */
  public Map<String, String> queryParams() {
    return parseUrlEncoded(exchange.getRequestURI().getRawQuery());
  }

  /** @return a single query parameter, or null if absent. */
  public String queryParam(final String name) {
    return queryParams().get(name);
  }

  /** @return the value of a request cookie, or null if absent. */
  public String cookie(final String name) {
    final String header = header("Cookie");
    if (header == null) {
      return null;
    }
    for (final String part : header.split(";")) {
      final String pair = part.trim();
      final int eq = pair.indexOf('=');
      if (eq > 0 && pair.substring(0, eq).equals(name)) {
        return pair.substring(eq + 1);
      }
    }
    return null;
  }

  /** @return the full request body bytes (read once, then cached). */
  public byte[] body() {
    if (cachedBody == null) {
      try {
        cachedBody = exchange.getRequestBody().readAllBytes();
      } catch (final IOException e) {
        throw new UncheckedIOException(e);
      }
    }
    return cachedBody;
  }

  /**
   * Parse an {@code application/x-www-form-urlencoded} body into a map.
   *
   * <p>Used by the token endpoint, whose client-credentials parameters arrive as a form per OAuth
   * 2.0. Percent-decoding is applied to both names and values.
   */
  public Map<String, String> formParams() {
    return parseUrlEncoded(new String(body(), StandardCharsets.UTF_8));
  }

  private static Map<String, String> parseUrlEncoded(final String raw) {
    final Map<String, String> params = new HashMap<>();
    if (raw == null || raw.isBlank()) {
      return params;
    }
    for (final String pair : raw.split("&")) {
      final int eq = pair.indexOf('=');
      if (eq < 0) {
        params.put(decode(pair), "");
      } else {
        params.put(decode(pair.substring(0, eq)), decode(pair.substring(eq + 1)));
      }
    }
    return params;
  }

  private static String decode(final String value) {
    return URLDecoder.decode(value, StandardCharsets.UTF_8);
  }
}

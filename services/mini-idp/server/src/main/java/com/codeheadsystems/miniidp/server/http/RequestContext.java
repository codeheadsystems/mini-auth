package com.codeheadsystems.miniidp.server.http;

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

  /** Hard cap on a request body we will buffer (1 MiB) — bounds memory per request. */
  private static final int MAX_BODY_BYTES = 1 << 20;

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

  /** @return the full request body bytes (read once, then cached). */
  public byte[] body() {
    if (cachedBody == null) {
      try {
        // Bounded read: never buffer more than the cap, so an oversized (or slow-trickled) body
        // cannot exhaust the heap. readNBytes(cap + 1) stops at cap + 1 bytes; if we got that
        // many, the body is over the limit and we reject it before parsing.
        final byte[] read = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
        if (read.length > MAX_BODY_BYTES) {
          throw new ApiException(413, "payload_too_large",
              "request body exceeds the " + MAX_BODY_BYTES + "-byte limit");
        }
        cachedBody = read;
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
    final Map<String, String> params = new HashMap<>();
    final String raw = new String(body(), StandardCharsets.UTF_8);
    if (raw.isBlank()) {
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

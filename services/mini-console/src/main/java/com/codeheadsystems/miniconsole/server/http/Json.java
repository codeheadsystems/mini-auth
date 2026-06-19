package com.codeheadsystems.miniconsole.server.http;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Shared Jackson {@link ObjectMapper} plus tiny (de)serialization helpers for the HTTP layer.
 *
 * <p>One mapper is reused for every JSON response body. It pretty-prints so responses are readable
 * when poked at with {@code curl}. A verbatim copy of mini-oidc's {@code server/http/Json}; in
 * Slice 0 only the {@code /health} liveness body and router error bodies are JSON (the pages are
 * HTML).
 */
public final class Json {

  /** The shared mapper (thread-safe once configured). Jackson 3: built via the immutable builder. */
  public static final ObjectMapper MAPPER = JsonMapper.builder()
      .enable(SerializationFeature.INDENT_OUTPUT)
      .build();

  private Json() {
  }

  /** Serialize a value to JSON bytes. */
  public static byte[] toBytes(final Object value) {
    try {
      return MAPPER.writeValueAsBytes(value);
    } catch (final JacksonException e) {
      throw new IllegalStateException("failed to serialize response", e);
    }
  }

  /**
   * Parse JSON bytes into the given type, mapping any parse failure to a 400.
   *
   * @throws ApiException (400 {@code invalid_request}) if the body is missing or malformed.
   */
  public static <T> T parse(final byte[] body, final Class<T> type) {
    if (body == null || body.length == 0) {
      throw ApiException.badRequest("request body is required");
    }
    try {
      return MAPPER.readValue(body, type);
    } catch (final JacksonException e) {
      // Jackson 3: parse failures are unchecked JacksonException (no longer checked IOException).
      throw ApiException.badRequest("malformed JSON request body");
    }
  }
}

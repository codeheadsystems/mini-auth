package com.codeheadsystems.miniclient.common;

import tools.jackson.databind.json.JsonMapper;

/**
 * The one shared, immutable Jackson mapper for the family's HTTP clients.
 *
 * <p>Jackson 3.x mappers are immutable — built once with {@link JsonMapper#builder()} and reused.
 * Records bind by constructor parameter name (the family compiles with {@code -parameters}), and
 * each wire DTO opts into {@code @JsonIgnoreProperties(ignoreUnknown = true)} so a client tolerates
 * fields a newer server adds. This holder keeps the single instance out of every transport.
 */
public final class Json {

  private static final JsonMapper MAPPER = JsonMapper.builder().build();

  private Json() {
  }

  /** @return the shared, thread-safe mapper. */
  public static JsonMapper mapper() {
    return MAPPER;
  }
}

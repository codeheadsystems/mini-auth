package com.codeheadsystems.minikms.protocol;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * Serializes and parses the newline-delimited JSON wire protocol.
 *
 * <p>Each request/response is one JSON object encoded on a single line; the
 * newline framing is the transport's concern, not this codec's. This class
 * produces compact single-line JSON (no embedded newlines) and parses one object
 * from a string.
 *
 * <p>Thread-safe: the underlying {@link ObjectMapper} is configured once and only
 * read afterwards.
 */
public final class ProtocolCodec {

  private final ObjectMapper mapper;

  /** Create a codec with a strict-but-tolerant mapper. */
  public ProtocolCodec() {
    // Jackson 3: mappers are immutable and built via the builder (the instance configure/enable
    // mutators were removed). JsonMapper extends ObjectMapper, so the field type is unchanged.
    this.mapper = JsonMapper.builder()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
        .build();
  }

  /**
   * @param request the request to serialize.
   * @return single-line JSON (no trailing newline).
   */
  public String encodeRequest(final KmsRequest request) {
    return write(request);
  }

  /**
   * @param response the response to serialize.
   * @return single-line JSON (no trailing newline).
   */
  public String encodeResponse(final KmsResponse response) {
    return write(response);
  }

  /**
   * @param line one JSON object line.
   * @return the parsed request.
   * @throws ProtocolException if the line is not a valid request object.
   */
  public KmsRequest decodeRequest(final String line) {
    try {
      return mapper.readValue(line, KmsRequest.class);
    } catch (final JacksonException e) {
      throw new ProtocolException("malformed request JSON");
    } catch (final IllegalArgumentException e) {
      throw new ProtocolException(e.getMessage());
    }
  }

  /**
   * @param line one JSON object line.
   * @return the parsed response.
   * @throws ProtocolException if the line is not a valid response object.
   */
  public KmsResponse decodeResponse(final String line) {
    try {
      return mapper.readValue(line, KmsResponse.class);
    } catch (final JacksonException e) {
      throw new ProtocolException("malformed response JSON");
    }
  }

  private String write(final Object value) {
    try {
      return mapper.writeValueAsString(value);
    } catch (final JacksonException e) {
      throw new ProtocolException("failed to serialize protocol object");
    }
  }
}

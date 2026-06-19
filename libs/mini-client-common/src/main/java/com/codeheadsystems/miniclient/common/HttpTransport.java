package com.codeheadsystems.miniclient.common;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.List;
import tools.jackson.databind.JavaType;

/**
 * A thin JSON-over-HTTP transport for the family's client libraries.
 *
 * <p>Built from a base URI (a loopback service in normal use) and an optional bearer token, it issues
 * read requests and parses the JSON body through the shared {@link Json} mapper. Its defining
 * property is the <b>no-oracle error collapse</b>: any failure — a non-2xx status, a transport
 * {@link IOException}, an interruption, or an unparseable body — surfaces as one generic
 * {@link ClientException} with no status code or response body leaked. A caller therefore cannot
 * tell "404 unknown" from "401 refused" from "connection refused", which is exactly the property the
 * family's no-oracle rule requires.
 *
 * <p>Slice 1 needs only {@code GET}; mutating verbs are deliberately omitted until a real consumer
 * (Slice 2) needs them.
 */
public final class HttpTransport {

  private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

  private final HttpClient http;
  private final String base;
  private final String bearerToken;

  /**
   * @param baseUri     the service origin (e.g. {@code http://127.0.0.1:8466}); a trailing slash is
   *                    tolerated.
   * @param bearerToken the token sent as {@code Authorization: Bearer …} on every request, or null
   *                    for unauthenticated calls. Held in memory only; never logged.
   */
  public HttpTransport(final URI baseUri, final String bearerToken) {
    final String raw = baseUri.toString();
    this.base = raw.endsWith("/") ? raw.substring(0, raw.length() - 1) : raw;
    this.bearerToken = bearerToken;
    this.http = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
  }

  /**
   * GET a path and deserialize the JSON body into {@code type}.
   *
   * @throws ClientException on any failure (no status/body detail leaked).
   */
  public <T> T get(final String path, final Class<T> type) {
    return read(send(path), Json.mapper().constructType(type));
  }

  /**
   * GET a path whose body is a JSON array, deserialized into a {@code List<element>}.
   *
   * @throws ClientException on any failure (no status/body detail leaked).
   */
  public <T> List<T> getList(final String path, final Class<T> element) {
    final JavaType listType =
        Json.mapper().getTypeFactory().constructCollectionType(List.class, element);
    return read(send(path), listType);
  }

  private byte[] send(final String path) {
    try {
      final HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
          .timeout(REQUEST_TIMEOUT)
          .header("Accept", "application/json")
          .GET();
      if (bearerToken != null) {
        request.header("Authorization", "Bearer " + bearerToken);
      }
      final var response = http.send(request.build(), BodyHandlers.ofByteArray());
      if (response.statusCode() / 100 != 2) {
        // No status/body in the message — collapsing every non-2xx avoids an oracle.
        throw new ClientException("request failed");
      }
      return response.body();
    } catch (final IOException e) {
      throw new ClientException("transport failure", e);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new ClientException("transport interrupted", e);
    }
  }

  private <T> T read(final byte[] body, final JavaType type) {
    try {
      return Json.mapper().readValue(body, type);
    } catch (final RuntimeException e) {
      // Jackson 3 throws the unchecked JacksonException; collapse it like any other failure.
      throw new ClientException("malformed response", e);
    }
  }
}

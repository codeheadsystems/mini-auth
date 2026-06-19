package com.codeheadsystems.miniclient.common;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import tools.jackson.databind.JavaType;

/**
 * A thin JSON-over-HTTP transport for the family's client libraries.
 *
 * <p>Built from a base URI (a loopback service in normal use) and an optional bearer token, it issues
 * requests and (de)serializes JSON through the shared {@link Json} mapper. Its defining property is
 * the <b>no-oracle error collapse</b>: any failure — a non-2xx status, a transport
 * {@link IOException}, an interruption, or an un(de)serializable body — surfaces as one generic
 * {@link ClientException} with no status code or response body leaked. A caller therefore cannot tell
 * "404 unknown" from "401 refused" from "connection refused", which is exactly the property the
 * family's no-oracle rule requires.
 *
 * <p>Slice 1 added {@code GET}; Slice 2 adds the mutating verbs ({@code POST}/{@code PUT}/
 * {@code DELETE}) the directory client's create/assign/delete needs; Slice 3 adds
 * {@link #postForm} for the one endpoint that speaks {@code application/x-www-form-urlencoded}
 * rather than JSON — mini-idp's OAuth {@code /oauth/token} — no speculative surface beyond that.
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
    return read(exchange("GET", path, null, "application/json"), Json.mapper().constructType(type));
  }

  /**
   * GET a path whose body is a JSON array, deserialized into a {@code List<element>}.
   *
   * @throws ClientException on any failure (no status/body detail leaked).
   */
  public <T> List<T> getList(final String path, final Class<T> element) {
    final JavaType listType =
        Json.mapper().getTypeFactory().constructCollectionType(List.class, element);
    return read(exchange("GET", path, null, "application/json"), listType);
  }

  /**
   * POST a JSON {@code body} and deserialize the response into {@code type}.
   *
   * @throws ClientException on any failure (no status/body detail leaked).
   */
  public <T> T post(final String path, final Object body, final Class<T> type) {
    return read(exchange("POST", path, serialize(body), "application/json"),
        Json.mapper().constructType(type));
  }

  /**
   * PUT a JSON {@code body} and deserialize the response into {@code type}.
   *
   * @throws ClientException on any failure (no status/body detail leaked).
   */
  public <T> T put(final String path, final Object body, final Class<T> type) {
    return read(exchange("PUT", path, serialize(body), "application/json"),
        Json.mapper().constructType(type));
  }

  /**
   * DELETE a path. The response body (a {@code 204} carries none) is ignored.
   *
   * @throws ClientException on any failure (no status/body detail leaked).
   */
  public void delete(final String path) {
    exchange("DELETE", path, null, "application/json");
  }

  /**
   * POST an {@code application/x-www-form-urlencoded} body and deserialize the JSON response into
   * {@code type}. This is the OAuth content type — mini-idp's {@code /oauth/token} expects form
   * fields, not JSON — so it is its own method rather than overloading {@link #post}.
   *
   * @throws ClientException on any failure (no status/body detail leaked).
   */
  public <T> T postForm(final String path, final Map<String, String> form, final Class<T> type) {
    return read(exchange("POST", path, encodeForm(form), "application/x-www-form-urlencoded"),
        Json.mapper().constructType(type));
  }

  /** URL-encode a form map into a {@code k=v&k=v} body. */
  private static byte[] encodeForm(final Map<String, String> form) {
    final StringJoiner joiner = new StringJoiner("&");
    for (final Map.Entry<String, String> field : form.entrySet()) {
      joiner.add(URLEncoder.encode(field.getKey(), StandardCharsets.UTF_8)
          + "=" + URLEncoder.encode(field.getValue(), StandardCharsets.UTF_8));
    }
    return joiner.toString().getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Issue one request and return its body bytes, collapsing every failure to {@link ClientException}.
   *
   * @param method      the HTTP method.
   * @param path        the path appended to the base URI.
   * @param body        the request body bytes, or null for a body-less request (GET/DELETE).
   * @param contentType the {@code Content-Type} for a body (JSON or form-urlencoded); ignored when
   *                    {@code body} is null.
   * @return the response body bytes (possibly empty, e.g. a 204).
   */
  private byte[] exchange(final String method, final String path, final byte[] body,
                          final String contentType) {
    try {
      final HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
          .timeout(REQUEST_TIMEOUT)
          .header("Accept", "application/json");
      if (bearerToken != null) {
        request.header("Authorization", "Bearer " + bearerToken);
      }
      if (body != null) {
        request.header("Content-Type", contentType);
        request.method(method, BodyPublishers.ofByteArray(body));
      } else {
        request.method(method, BodyPublishers.noBody());
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

  private byte[] serialize(final Object body) {
    try {
      return Json.mapper().writeValueAsBytes(body);
    } catch (final RuntimeException e) {
      // Jackson 3 throws the unchecked JacksonException; collapse it like any other failure.
      throw new ClientException("could not serialize request", e);
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

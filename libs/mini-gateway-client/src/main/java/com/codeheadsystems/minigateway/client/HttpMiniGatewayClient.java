package com.codeheadsystems.minigateway.client;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniclient.common.HttpTransport;
import com.codeheadsystems.minigateway.client.model.HealthStatus;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;

/**
 * The HTTP implementation of {@link MiniGatewayClient}.
 *
 * <p>{@link #health} goes through the shared {@link HttpTransport} (the normal no-oracle collapse).
 * {@link #verify} cannot: the gateway answers a reverse proxy with distinct statuses, and mapping
 * them is the point — so it uses its own {@link HttpClient} configured to <b>never follow
 * redirects</b> (otherwise a 302-to-login would be chased and lost) and reads only the status code,
 * never the body. The headers mirror exactly what a proxy forwards (see
 * mini-gateway's {@code GatewayHandlers}): {@code X-Forwarded-Method} / {@code X-Forwarded-Uri}, the
 * caller's {@code Authorization} / {@code Cookie}, and an {@code Accept} that marks browser vs API.
 */
final class HttpMiniGatewayClient implements MiniGatewayClient {

  private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

  private final String base;
  private final HttpClient http;
  private final HttpTransport publicTransport;

  HttpMiniGatewayClient(final URI baseUri) {
    final String raw = baseUri.toString();
    this.base = raw.endsWith("/") ? raw.substring(0, raw.length() - 1) : raw;
    // NEVER follow redirects: a 302-to-login is a meaningful outcome here, not a hop to chase.
    this.http = HttpClient.newBuilder()
        .connectTimeout(CONNECT_TIMEOUT)
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
    this.publicTransport = new HttpTransport(baseUri, null);
  }

  @Override
  public VerifyOutcome verify(final VerifyRequest request) {
    try {
      final HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(base + "/verify"))
          .timeout(REQUEST_TIMEOUT)
          // /verify is registered for all methods; GET keeps the probe body-less. The ORIGINAL
          // method/URI travel in the forwarded headers, exactly as a reverse proxy sends them.
          .method("GET", BodyPublishers.noBody())
          .header("X-Forwarded-Method", blankTo(request.method(), "GET"))
          .header("X-Forwarded-Uri", blankTo(request.uri(), "/"))
          // A browser navigation accepts HTML (so the gateway may 302); an API client accepts JSON.
          .header("Accept", request.browser() ? "text/html" : "application/json");
      if (request.bearerToken() != null && !request.bearerToken().isBlank()) {
        builder.header("Authorization", "Bearer " + request.bearerToken());
      }
      if (request.cookie() != null && !request.cookie().isBlank()) {
        builder.header("Cookie", request.cookie());
      }
      final int status = http.send(builder.build(), BodyHandlers.discarding()).statusCode();
      return map(status);
    } catch (final IOException e) {
      throw new ClientException("transport failure", e);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new ClientException("transport interrupted", e);
    }
  }

  @Override
  public HealthStatus health() {
    return publicTransport.get("/health", HealthStatus.class);
  }

  /** Map the gateway's contract status to an outcome; anything else is an unexpected failure. */
  private static VerifyOutcome map(final int status) {
    return switch (status) {
      case 200 -> VerifyOutcome.AUTHORIZED;
      case 302, 303 -> VerifyOutcome.REDIRECT_LOGIN;
      case 401 -> VerifyOutcome.UNAUTHENTICATED;
      case 403 -> VerifyOutcome.FORBIDDEN;
      // A 404/405/500 is not part of the contract — surface it as a generic failure (no leak).
      default -> throw new ClientException("unexpected verify status");
    };
  }

  private static String blankTo(final String value, final String fallback) {
    return value == null || value.isBlank() ? fallback : value;
  }
}

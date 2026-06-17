package com.codeheadsystems.minigateway.auth;

import com.codeheadsystems.minitoken.jwks.JwkSet;
import tools.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Clock;
import java.time.Duration;

/**
 * Fetches the OP's JWKS from its {@code jwks_uri} (mini-oidc's {@code /jwks.json}) and caches it for
 * a short window, so bearer verification does not hit the network on every request but still picks
 * up key rotation within the cache TTL. A fetch failure reuses the last good set if there is one,
 * else yields an empty set (which fails verification closed).
 */
public final class HttpJwksProvider implements JwksProvider {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
  private final String jwksUrl;
  private final Clock clock;
  private final Duration cacheTtl;
  private volatile JwkSet cached;
  private volatile long fetchedAtEpochSecond;

  public HttpJwksProvider(final String jwksUrl, final Clock clock, final Duration cacheTtl) {
    this.jwksUrl = jwksUrl;
    this.clock = clock;
    this.cacheTtl = cacheTtl;
  }

  @Override
  public JwkSet get() {
    final long now = clock.instant().getEpochSecond();
    if (cached != null && now - fetchedAtEpochSecond < cacheTtl.toSeconds()) {
      return cached;
    }
    try {
      final var response = http.send(
          HttpRequest.newBuilder(URI.create(jwksUrl)).timeout(Duration.ofSeconds(5)).GET().build(),
          BodyHandlers.ofString());
      if (response.statusCode() == 200) {
        cached = MAPPER.readValue(response.body(), JwkSet.class);
        fetchedAtEpochSecond = now;
      }
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (final java.io.IOException | RuntimeException e) {
      // Reuse the last good set on a transient failure; never an oracle.
    }
    return cached != null ? cached : new JwkSet(java.util.List.of());
  }
}

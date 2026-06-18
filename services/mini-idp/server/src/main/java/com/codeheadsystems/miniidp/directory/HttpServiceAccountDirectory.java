package com.codeheadsystems.miniidp.directory;

import com.codeheadsystems.minitoken.auth.Authorization;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.Optional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The production {@link ServiceAccountDirectory}: authenticates a client <b>via mini-directory</b>
 * over HTTP. It POSTs the presented {@code (clientId, secret)} to mini-directory's
 * {@code /admin/service-accounts/authenticate} endpoint (with the directory admin bearer proving
 * mini-idp is an authorized issuer); mini-directory verifies the Argon2id secret in constant time —
 * the secret hash never leaves the directory — and returns the resolved principal + grants, which
 * are reassembled into a mini-token {@link Authorization}.
 *
 * <p>Any non-200 (unknown client, wrong/disabled, directory unreachable) maps to {@link
 * Optional#empty()} — the token endpoint then surfaces one generic {@code invalid_client}. The admin
 * token and the client secret are never logged.
 */
public final class HttpServiceAccountDirectory implements ServiceAccountDirectory {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
  private final String baseUrl;
  private final String adminToken;

  /**
   * @param baseUrl    the mini-directory base URL (e.g. {@code http://127.0.0.1:8466}).
   * @param adminToken the mini-directory bootstrap admin token (sent as a bearer; never logged).
   */
  public HttpServiceAccountDirectory(final String baseUrl, final String adminToken) {
    this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    this.adminToken = adminToken;
  }

  @Override
  public Optional<ResolvedClient> authenticate(final String clientId, final char[] secret) {
    if (clientId == null || secret == null) {
      return Optional.empty();
    }
    final ObjectNode body = MAPPER.createObjectNode();
    body.put("id", clientId);
    body.put("secret", new String(secret));
    try {
      final HttpRequest request = HttpRequest.newBuilder(
              URI.create(baseUrl + "/admin/service-accounts/authenticate"))
          .header("Authorization", "Bearer " + adminToken)
          .header("Content-Type", "application/json")
          .timeout(Duration.ofSeconds(5))
          .POST(BodyPublishers.ofString(MAPPER.writeValueAsString(body))).build();
      final var response = http.send(request, BodyHandlers.ofString());
      if (response.statusCode() != 200) {
        return Optional.empty();
      }
      final JsonNode resolution = MAPPER.readTree(response.body());
      final boolean admin = resolution.has("admin") && resolution.get("admin").asBoolean();
      final Authorization authorization = Authorizations.fromResolution(admin, resolution.get("grants"));
      return Optional.of(new ResolvedClient(resolution.get("id").asString(), authorization));
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      return Optional.empty();
    } catch (final java.io.IOException | RuntimeException e) {
      // A directory outage must never be an oracle; authentication simply fails closed.
      return Optional.empty();
    }
  }
}

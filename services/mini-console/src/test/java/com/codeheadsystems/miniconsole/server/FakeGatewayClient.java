package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.minigateway.client.MiniGatewayClient;
import com.codeheadsystems.minigateway.client.VerifyOutcome;
import com.codeheadsystems.minigateway.client.VerifyRequest;
import com.codeheadsystems.minigateway.client.model.HealthStatus;

/**
 * A canned, in-memory {@link MiniGatewayClient} for console tests — no real gateway is booted. It maps
 * a verify call the way a configured gateway would: no credentials → redirect-to-login, a bearer on a
 * path whose name contains {@code "forbidden"} → 403, any other bearer → 200. It records the last
 * bearer it saw so a test can prove the console never leaks the operator-supplied token to the page.
 */
final class FakeGatewayClient implements MiniGatewayClient {

  boolean failHealth;
  String lastBearer;

  @Override
  public VerifyOutcome verify(final VerifyRequest request) {
    if (request.bearerToken() == null || request.bearerToken().isBlank()) {
      return VerifyOutcome.REDIRECT_LOGIN;
    }
    lastBearer = request.bearerToken();
    final String uri = request.uri();
    return uri != null && uri.contains("forbidden") ? VerifyOutcome.FORBIDDEN : VerifyOutcome.AUTHORIZED;
  }

  @Override
  public HealthStatus health() {
    if (failHealth) {
      throw new ClientException("gateway unavailable");
    }
    return new HealthStatus("ok");
  }
}

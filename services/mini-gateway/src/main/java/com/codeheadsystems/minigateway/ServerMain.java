package com.codeheadsystems.minigateway;

import com.codeheadsystems.minigateway.server.GatewayServer;
import com.codeheadsystems.minigateway.server.ServerConfig;
import java.io.IOException;
import java.time.Clock;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * mini-gateway entry point — the forward-auth endpoint for a reverse proxy.
 *
 * <p>Resolve {@link ServerConfig}, build the {@link GatewayServer} (shared session store + route
 * policy + authenticators), bind loopback, and serve {@code /verify} until interrupted. No admin
 * token: the gateway holds no secrets of its own — it validates the family's sessions/tokens.
 *
 * <p><b>Loopback / TLS.</b> Binds {@code 127.0.0.1} by default; the reverse proxy reaches it over the
 * loopback/Docker network. Any real deployment terminates TLS at the proxy and never exposes the
 * verify endpoint to clients directly.
 */
public final class ServerMain {

  private ServerMain() {
  }

  /** @param args CLI arguments (see {@link ServerConfig}). */
  public static void main(final String[] args) {
    try {
      run(args, System.getenv());
    } catch (final IllegalArgumentException | IllegalStateException e) {
      System.err.println("Configuration error: " + e.getMessage());
      System.exit(64);
    } catch (final IOException e) {
      System.err.println("I/O error: " + e.getMessage());
      System.exit(74);
    }
  }

  private static void run(final String[] args, final Map<String, String> env) throws IOException {
    final ServerConfig config = ServerConfig.resolve(args, env);
    final GatewayServer server = GatewayServer.create(config, Clock.systemUTC(), null);

    final CountDownLatch shutdown = new CountDownLatch(1);
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      server.stop();
      shutdown.countDown();
    }, "minigateway-shutdown"));

    server.start();
    System.out.println("mini-gateway is running on http://" + server.address().getHostString()
        + ":" + server.address().getPort());
    System.out.println("forward-auth endpoint: /verify   (point your reverse proxy here)");
    System.out.println("sessions: " + config.sessionsFile()
        + "   bearer: " + (config.bearerEnabled() ? config.jwksUrl() : "disabled"));
    System.out.println("Press Ctrl-C to stop.");
    awaitShutdown(shutdown);
  }

  private static void awaitShutdown(final CountDownLatch shutdown) {
    try {
      shutdown.await();
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }
}

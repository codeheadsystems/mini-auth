package com.codeheadsystems.minidirectory.server.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A tiny method + path router over the JDK's {@link HttpExchange}.
 *
 * <p>The built-in {@code HttpServer} only matches longest-prefix contexts and has no notion of
 * methods or path variables, so we register a single root context and let this router dispatch.
 * Patterns use {@code {name}} segments (e.g. {@code /admin/clients/{id}/grants}); a matched
 * variable is exposed via {@link RequestContext#pathParam}. First registered match wins; a path
 * that matches but with the wrong method yields 405, an unmatched path yields 404.
 *
 * <p>Errors are funnelled here: an {@link ApiException} becomes its declared status + JSON error
 * body, and any other exception becomes a generic 500 — never a stack trace to the client. Access
 * logging records method, path, and status only; request/response bodies (which may carry
 * secrets) are never logged.
 */
public final class Router implements HttpHandler {

  private static final Logger LOGGER = System.getLogger(Router.class.getName());

  /** A request handler: receives the matched request, returns a response (may throw ApiException). */
  @FunctionalInterface
  public interface Handler {
    HttpResponse handle(RequestContext context);
  }

  private record Route(String method, String[] segments, Handler handler) {
  }

  private final List<Route> routes = new ArrayList<>();

  /** Register a route. {@code pattern} segments wrapped in {@code {}} are path variables. */
  public Router route(final String method, final String pattern, final Handler handler) {
    routes.add(new Route(method, split(pattern), handler));
    return this;
  }

  @Override
  public void handle(final HttpExchange exchange) throws IOException {
    final String method = exchange.getRequestMethod();
    final String path = exchange.getRequestURI().getPath();
    HttpResponse response;
    try {
      response = dispatch(method, path, exchange);
    } catch (final ApiException e) {
      response = errorResponse(e.status(), e.error(), e.getMessage());
    } catch (final RuntimeException e) {
      // Never leak internals to the caller; log server-side without any request body.
      LOGGER.log(Level.ERROR, "unhandled error for " + method + " " + path, e);
      response = errorResponse(500, "internal_error", "an unexpected error occurred");
    }
    write(exchange, response);
    final int status = response.status();
    LOGGER.log(Level.INFO, () -> method + " " + path + " -> " + status);
  }

  private HttpResponse dispatch(final String method, final String path, final HttpExchange exchange) {
    final String[] segments = split(path);
    boolean pathMatchedWrongMethod = false;
    for (final Route route : routes) {
      final Map<String, String> params = match(route.segments(), segments);
      if (params == null) {
        continue;
      }
      if (!route.method().equals(method)) {
        pathMatchedWrongMethod = true;
        continue;
      }
      return route.handler().handle(new RequestContext(exchange, params));
    }
    if (pathMatchedWrongMethod) {
      throw new ApiException(405, "method_not_allowed", "method not allowed for this resource");
    }
    throw ApiException.notFound("no such resource: " + path);
  }

  /** @return path variable bindings if the pattern matches, else null. */
  private static Map<String, String> match(final String[] pattern, final String[] actual) {
    if (pattern.length != actual.length) {
      return null;
    }
    final Map<String, String> params = new HashMap<>();
    for (int i = 0; i < pattern.length; i++) {
      final String p = pattern[i];
      if (p.length() > 1 && p.charAt(0) == '{' && p.charAt(p.length() - 1) == '}') {
        params.put(p.substring(1, p.length() - 1), actual[i]);
      } else if (!p.equals(actual[i])) {
        return null;
      }
    }
    return params;
  }

  private static String[] split(final String path) {
    final String trimmed = path.startsWith("/") ? path.substring(1) : path;
    if (trimmed.isEmpty()) {
      return new String[] {""};
    }
    return trimmed.split("/", -1);
  }

  private static HttpResponse errorResponse(final int status, final String error, final String description) {
    final Map<String, String> body = new LinkedHashMap<>();
    body.put("error", error);
    body.put("error_description", description);
    return HttpResponse.json(status, body);
  }

  private static void write(final HttpExchange exchange, final HttpResponse response) throws IOException {
    final byte[] body = response.body();
    exchange.getResponseHeaders().set("Content-Type", response.contentType());
    // 204 must not declare a body length; everything else sends its byte count.
    if (response.status() == 204 || body.length == 0) {
      exchange.sendResponseHeaders(response.status(), -1);
    } else {
      exchange.sendResponseHeaders(response.status(), body.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    }
    exchange.close();
  }
}

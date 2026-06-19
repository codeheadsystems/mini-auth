package com.codeheadsystems.miniconsole.server.http;

/**
 * An exception carrying an HTTP status and a machine-readable error code, rendered as a JSON
 * error body by the router.
 *
 * <p>The {@code error}/{@code error_description} shape mirrors the family's other services. Auth and
 * CSRF failures collapse to a single generic outcome with no distinguishing detail (no oracle). A
 * verbatim copy of mini-oidc's {@code server/http/ApiException}, trimmed to the statics Slice 0 uses.
 */
public final class ApiException extends RuntimeException {

  private final int status;
  private final String error;

  /**
   * @param status      the HTTP status code.
   * @param error       the short machine-readable error code.
   * @param description a human-readable description (must not leak secrets or auth-failure detail).
   */
  public ApiException(final int status, final String error, final String description) {
    super(description);
    this.status = status;
    this.error = error;
  }

  /** @return the HTTP status code. */
  public int status() {
    return status;
  }

  /** @return the machine-readable error code. */
  public String error() {
    return error;
  }

  /** 400 with {@code invalid_request}. */
  public static ApiException badRequest(final String description) {
    return new ApiException(400, "invalid_request", description);
  }

  /** 401 with {@code unauthorized} for a missing/invalid credential. */
  public static ApiException unauthorized() {
    return new ApiException(401, "unauthorized", "authentication required");
  }

  /** 404 with {@code not_found}. */
  public static ApiException notFound(final String description) {
    return new ApiException(404, "not_found", description);
  }

  /** 409 with {@code conflict} (e.g. an id that already exists). */
  public static ApiException conflict(final String description) {
    return new ApiException(409, "conflict", description);
  }
}

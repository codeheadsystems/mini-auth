package com.codeheadsystems.miniidp.server.http;

/**
 * An exception carrying an HTTP status and a machine-readable error code, rendered as a JSON
 * error body by the router.
 *
 * <p>The {@code error}/{@code error_description} shape mirrors OAuth 2.0 error responses (RFC
 * 6749). Importantly, the messages here are deliberately generic for authentication failures: the
 * token endpoint must not reveal <em>why</em> a credential was rejected (unknown client vs. wrong
 * secret), so {@link #invalidClient()} carries no distinguishing detail.
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

  /** 401 with {@code invalid_client} and no distinguishing detail (no credential oracle). */
  public static ApiException invalidClient() {
    return new ApiException(401, "invalid_client", "client authentication failed");
  }

  /** 401 with {@code unauthorized} for a missing/invalid admin credential. */
  public static ApiException unauthorized() {
    return new ApiException(401, "unauthorized", "admin authentication required");
  }

  /** 404 with {@code not_found}. */
  public static ApiException notFound(final String description) {
    return new ApiException(404, "not_found", description);
  }
}

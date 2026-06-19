package com.codeheadsystems.minigateway.client;

/**
 * The decision mini-gateway returned for a {@code /verify} call, mapped from the HTTP status a reverse
 * proxy would act on.
 *
 * <p>mini-gateway is a forward-auth endpoint: a reverse proxy calls {@code /verify} before forwarding
 * a request and acts on the <b>status code</b> — 200 to forward, 302 to bounce a browser to login,
 * 401 to refuse an API client, 403 to forbid an authenticated-but-unauthorized caller. So, uniquely
 * in the family, this client deliberately <i>distinguishes</i> those statuses (it is the proxy's job)
 * rather than collapsing them to one generic error. No response body is read, so there is still no
 * body oracle — only the status, which is the gateway's public contract.
 */
public enum VerifyOutcome {

  /** 200 — the request is allowed (the proxy would forward it, copying the {@code X-Auth-*} headers). */
  AUTHORIZED,

  /** 302 — an unauthenticated browser is redirected to the configured login URL. */
  REDIRECT_LOGIN,

  /** 401 — an unauthenticated API client (no browser redirect) is refused. */
  UNAUTHENTICATED,

  /** 403 — a valid caller the route's policy forbids. */
  FORBIDDEN
}

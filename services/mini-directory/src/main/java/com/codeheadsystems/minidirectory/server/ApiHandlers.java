package com.codeheadsystems.minidirectory.server;

import com.codeheadsystems.minidirectory.model.Account;
import com.codeheadsystems.minidirectory.model.Group;
import com.codeheadsystems.minidirectory.model.Role;
import com.codeheadsystems.minidirectory.server.dto.Dtos.AccountView;
import com.codeheadsystems.minidirectory.server.dto.Dtos.AssignmentRequest;
import com.codeheadsystems.minidirectory.server.dto.Dtos.CreateHumanRequest;
import com.codeheadsystems.minidirectory.server.dto.Dtos.CreateServiceAccountRequest;
import com.codeheadsystems.minidirectory.server.dto.Dtos.GroupRequest;
import com.codeheadsystems.minidirectory.server.dto.Dtos.GroupUpdateRequest;
import com.codeheadsystems.minidirectory.server.dto.Dtos.ResolutionView;
import com.codeheadsystems.minidirectory.server.dto.Dtos.RoleRequest;
import com.codeheadsystems.minidirectory.server.dto.Dtos.RoleUpdateRequest;
import com.codeheadsystems.minidirectory.server.dto.Dtos.ServiceAccountCreated;
import com.codeheadsystems.minidirectory.server.http.ApiException;
import com.codeheadsystems.minidirectory.server.http.HttpResponse;
import com.codeheadsystems.minidirectory.server.http.Json;
import com.codeheadsystems.minidirectory.server.http.RequestContext;
import com.codeheadsystems.minidirectory.server.http.Router;
import com.codeheadsystems.minidirectory.server.http.StaticResource;
import com.codeheadsystems.minidirectory.service.DirectoryService;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * Builds the {@link Router} wiring every documented endpoint to a handler.
 *
 * <p>The meta endpoints (health, spec, docs) are public; every {@code /admin} endpoint first calls
 * {@link AdminAuthenticator#requireAdmin} on the request's {@code Authorization} header. Handlers
 * stay thin: validate input, call {@link DirectoryService}, and map the result to an
 * {@link HttpResponse}. All directory logic (validation, role/grant resolution, secret hashing)
 * lives in the service.
 *
 * <p>No secret material is ever logged or echoed except the one-time service-account secret in the
 * creation response (by design). Service-layer validation exceptions are mapped to HTTP here:
 * {@link IllegalStateException} (id collision) → 409, {@link IllegalArgumentException} (bad input /
 * dangling reference) → 400.
 */
public final class ApiHandlers {

  private final DirectoryService directory;
  private final AdminAuthenticator adminAuth;
  private final OpenApiDocument openApi;

  /** Wire the handlers with their collaborators. */
  public ApiHandlers(final DirectoryService directory, final AdminAuthenticator adminAuth,
                     final OpenApiDocument openApi) {
    this.directory = directory;
    this.adminAuth = adminAuth;
    this.openApi = openApi;
  }

  /** @return a router with every route registered. */
  public Router router() {
    final Router router = new Router();
    // Public meta endpoints.
    router.route("GET", "/health", this::health);
    router.route("GET", "/openapi.yaml", this::openApiYaml);
    router.route("GET", "/openapi.json", this::openApiJson);
    router.route("GET", "/docs", this::docs);
    router.route("GET", "/docs/swagger-ui.css", ctx -> asset("swagger-ui.css", "text/css"));
    router.route("GET", "/docs/swagger-ui-bundle.js",
        ctx -> asset("swagger-ui-bundle.js", "application/javascript"));

    // Roles (admin).
    router.route("POST", "/admin/roles", this::createRole);
    router.route("GET", "/admin/roles", this::listRoles);
    router.route("GET", "/admin/roles/{id}", this::getRole);
    router.route("PUT", "/admin/roles/{id}", this::updateRole);
    router.route("DELETE", "/admin/roles/{id}", this::deleteRole);

    // Groups (admin).
    router.route("POST", "/admin/groups", this::createGroup);
    router.route("GET", "/admin/groups", this::listGroups);
    router.route("GET", "/admin/groups/{id}", this::getGroup);
    router.route("PUT", "/admin/groups/{id}", this::updateGroup);
    router.route("DELETE", "/admin/groups/{id}", this::deleteGroup);

    // Principals — humans + service accounts (admin).
    router.route("POST", "/admin/humans", this::createHuman);
    router.route("POST", "/admin/service-accounts", this::createServiceAccount);
    router.route("GET", "/admin/principals", this::listPrincipals);
    router.route("GET", "/admin/principals/{id}", this::getPrincipal);
    router.route("PUT", "/admin/principals/{id}/assignment", this::assign);
    router.route("DELETE", "/admin/principals/{id}", this::deletePrincipal);
    router.route("GET", "/admin/principals/{id}/resolution", this::resolve);
    return router;
  }

  // ---- Meta ----------------------------------------------------------------------------------

  private HttpResponse health(final RequestContext ctx) {
    return HttpResponse.json(200, java.util.Map.of("status", "ok"));
  }

  private HttpResponse openApiYaml(final RequestContext ctx) {
    return HttpResponse.raw(200, "application/yaml", openApi.yaml());
  }

  private HttpResponse openApiJson(final RequestContext ctx) {
    return HttpResponse.raw(200, "application/json", openApi.json());
  }

  private HttpResponse docs(final RequestContext ctx) {
    return HttpResponse.text(200, "text/html; charset=utf-8", SwaggerUiPage.HTML);
  }

  private HttpResponse asset(final String file, final String contentType) {
    return HttpResponse.raw(200, contentType, StaticResource.bytes("/swagger-ui/" + file));
  }

  // ---- Roles ---------------------------------------------------------------------------------

  private HttpResponse createRole(final RequestContext ctx) {
    requireAdmin(ctx);
    final RoleRequest request = Json.parse(ctx.body(), RoleRequest.class);
    final Role role = guard(() -> directory.createRole(request.id(), request.description(), request.grants()));
    return HttpResponse.json(201, role);
  }

  private HttpResponse listRoles(final RequestContext ctx) {
    requireAdmin(ctx);
    return HttpResponse.json(200, directory.listRoles());
  }

  private HttpResponse getRole(final RequestContext ctx) {
    requireAdmin(ctx);
    final String id = ctx.pathParam("id");
    return HttpResponse.json(200, directory.getRole(id)
        .orElseThrow(() -> ApiException.notFound("no such role: " + id)));
  }

  private HttpResponse updateRole(final RequestContext ctx) {
    requireAdmin(ctx);
    final String id = ctx.pathParam("id");
    final RoleUpdateRequest request = Json.parse(ctx.body(), RoleUpdateRequest.class);
    final Role updated = guard(() -> directory.updateRole(id, request.description(), request.grants()))
        .orElseThrow(() -> ApiException.notFound("no such role: " + id));
    return HttpResponse.json(200, updated);
  }

  private HttpResponse deleteRole(final RequestContext ctx) {
    requireAdmin(ctx);
    final String id = ctx.pathParam("id");
    if (!directory.deleteRole(id)) {
      throw ApiException.notFound("no such role: " + id);
    }
    return HttpResponse.noContent();
  }

  // ---- Groups --------------------------------------------------------------------------------

  private HttpResponse createGroup(final RequestContext ctx) {
    requireAdmin(ctx);
    final GroupRequest request = Json.parse(ctx.body(), GroupRequest.class);
    final Group group = guard(() ->
        directory.createGroup(request.id(), request.description(), request.roles(), request.grants()));
    return HttpResponse.json(201, group);
  }

  private HttpResponse listGroups(final RequestContext ctx) {
    requireAdmin(ctx);
    return HttpResponse.json(200, directory.listGroups());
  }

  private HttpResponse getGroup(final RequestContext ctx) {
    requireAdmin(ctx);
    final String id = ctx.pathParam("id");
    return HttpResponse.json(200, directory.getGroup(id)
        .orElseThrow(() -> ApiException.notFound("no such group: " + id)));
  }

  private HttpResponse updateGroup(final RequestContext ctx) {
    requireAdmin(ctx);
    final String id = ctx.pathParam("id");
    final GroupUpdateRequest request = Json.parse(ctx.body(), GroupUpdateRequest.class);
    final Group updated = guard(() ->
        directory.updateGroup(id, request.description(), request.roles(), request.grants()))
        .orElseThrow(() -> ApiException.notFound("no such group: " + id));
    return HttpResponse.json(200, updated);
  }

  private HttpResponse deleteGroup(final RequestContext ctx) {
    requireAdmin(ctx);
    final String id = ctx.pathParam("id");
    if (!directory.deleteGroup(id)) {
      throw ApiException.notFound("no such group: " + id);
    }
    return HttpResponse.noContent();
  }

  // ---- Principals ----------------------------------------------------------------------------

  private HttpResponse createHuman(final RequestContext ctx) {
    requireAdmin(ctx);
    final CreateHumanRequest request = Json.parse(ctx.body(), CreateHumanRequest.class);
    final Account account = guard(() -> directory.createHuman(request.id(), request.displayName(),
        request.admin(), request.memberOf(), request.roles(), request.grants()));
    return HttpResponse.json(201, AccountView.from(account));
  }

  private HttpResponse createServiceAccount(final RequestContext ctx) {
    requireAdmin(ctx);
    final CreateServiceAccountRequest request = Json.parse(ctx.body(), CreateServiceAccountRequest.class);
    final DirectoryService.Registration registration = guard(() -> directory.createServiceAccount(
        request.displayName(), request.admin(), request.memberOf(), request.roles(), request.grants()));
    final Account account = registration.account();

    // The one place a plaintext secret leaves the service. Converting char[] -> String for JSON
    // means the String lingers until GC; a stricter build would stream it. We zero our char[].
    final String secret = new String(registration.secret());
    java.util.Arrays.fill(registration.secret(), '\0');
    final ServiceAccountCreated response = new ServiceAccountCreated(
        account.id(), secret, account.displayName(), AccountView.from(account));
    return HttpResponse.json(201, response);
  }

  private HttpResponse listPrincipals(final RequestContext ctx) {
    requireAdmin(ctx);
    final List<AccountView> views = new ArrayList<>();
    for (final Account account : directory.listAccounts()) {
      views.add(AccountView.from(account));
    }
    return HttpResponse.json(200, views);
  }

  private HttpResponse getPrincipal(final RequestContext ctx) {
    requireAdmin(ctx);
    final String id = ctx.pathParam("id");
    final Account account = directory.getAccount(id)
        .orElseThrow(() -> ApiException.notFound("no such principal: " + id));
    return HttpResponse.json(200, AccountView.from(account));
  }

  private HttpResponse assign(final RequestContext ctx) {
    requireAdmin(ctx);
    final String id = ctx.pathParam("id");
    final AssignmentRequest request = Json.parse(ctx.body(), AssignmentRequest.class);
    final Account updated = guard(() -> directory.assign(id, request.enabled(), request.admin(),
        request.memberOf(), request.roles(), request.grants()))
        .orElseThrow(() -> ApiException.notFound("no such principal: " + id));
    return HttpResponse.json(200, AccountView.from(updated));
  }

  private HttpResponse deletePrincipal(final RequestContext ctx) {
    requireAdmin(ctx);
    final String id = ctx.pathParam("id");
    if (!directory.deleteAccount(id)) {
      throw ApiException.notFound("no such principal: " + id);
    }
    return HttpResponse.noContent();
  }

  private HttpResponse resolve(final RequestContext ctx) {
    requireAdmin(ctx);
    final String id = ctx.pathParam("id");
    return HttpResponse.json(200, ResolutionView.from(directory.resolve(id)
        .orElseThrow(() -> ApiException.notFound("no such principal: " + id))));
  }

  // ---- Helpers -------------------------------------------------------------------------------

  private void requireAdmin(final RequestContext ctx) {
    adminAuth.requireAdmin(ctx.header("Authorization"));
  }

  /**
   * Run a service mutation, translating its validation exceptions into HTTP errors: an id collision
   * ({@link IllegalStateException}) becomes 409, and bad input or a dangling role/group reference
   * ({@link IllegalArgumentException}) becomes 400. The exception messages carry no secret material.
   */
  private static <T> T guard(final Supplier<T> action) {
    try {
      return action.get();
    } catch (final IllegalStateException e) {
      throw ApiException.conflict(e.getMessage());
    } catch (final IllegalArgumentException e) {
      throw ApiException.badRequest(e.getMessage());
    }
  }
}

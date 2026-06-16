package com.codeheadsystems.miniidp.server;

/**
 * The {@code /docs} HTML page: a minimal Swagger UI host that renders the served OpenAPI spec.
 *
 * <p>It loads the <b>vendored</b> Swagger UI assets ({@code /docs/swagger-ui.css} and
 * {@code /docs/swagger-ui-bundle.js}, served from {@code src/main/resources/swagger-ui/}) — no
 * CDN, so the docs work fully offline — and points the viewer at {@code /openapi.yaml}. The
 * bundle includes the presets it needs, so this is the only HTML required.
 */
public final class SwaggerUiPage {

  private SwaggerUiPage() {
  }

  /** The static docs page. */
  public static final String HTML = """
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>mini-idp API</title>
        <link rel="stylesheet" href="/docs/swagger-ui.css"/>
      </head>
      <body>
        <div id="swagger-ui"></div>
        <script src="/docs/swagger-ui-bundle.js"></script>
        <script>
          window.ui = SwaggerUIBundle({
            url: "/openapi.yaml",
            dom_id: "#swagger-ui",
            deepLinking: true,
            presets: [SwaggerUIBundle.presets.apis]
          });
        </script>
      </body>
      </html>
      """;
}

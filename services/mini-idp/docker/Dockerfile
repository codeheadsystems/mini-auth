# mini-idp container image: the machine-identity token issuer, for integration tests (Testcontainers)
# and small deployments.
#
# Build context = the installDist output, so the image never compiles anything itself:
#   ./gradlew :services:mini-idp:server:installDist
#   docker build -f services/mini-idp/docker/Dockerfile \
#     --build-context docker=services/mini-idp/docker \
#     -t mini-idp:dev services/mini-idp/server/build/install/server
#
# Run (in-memory service accounts, no mini-directory; see services/mini-idp/README.md):
#   docker run --rm -p 8455:8455 \
#     -e MINIIDP_ADMIN_TOKEN=... \
#     -e MINIIDP_AUDIENCE_ALGORITHMS=config-server=ES256 \
#     -e MINIIDP_SERVICE_ACCOUNTS='[{"clientId":"billing","secret":"...","audiences":["config-server"]}]' \
#     mini-idp:dev
#
# Inside a container the server must bind all interfaces (MINIIDP_HOST=0.0.0.0) to be reachable
# through the published port; choosing to publish it is the operator decision. The issuer defaults
# to http://localhost:$MINIIDP_PORT so a host-side verifier that maps the same port sees iss equal
# to the URL it fetches discovery from. Set MINIIDP_ISSUER to override.
FROM eclipse-temurin:21-jre

RUN groupadd --system --gid 10001 miniidp \
 && useradd --system --uid 10001 --gid miniidp --home-dir /data --no-create-home miniidp \
 && mkdir -p /data && chown miniidp:miniidp /data && chmod 0700 /data

COPY . /opt/mini-idp
COPY --from=docker entrypoint.sh /opt/mini-idp/entrypoint.sh

ENV MINIIDP_HOST=0.0.0.0 \
    MINIIDP_PORT=8455 \
    MINIIDP_DATA_DIR=/data

USER 10001:10001
EXPOSE 8455
ENTRYPOINT ["/opt/mini-idp/entrypoint.sh"]

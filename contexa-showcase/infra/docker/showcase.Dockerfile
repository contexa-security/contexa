# syntax=docker/dockerfile:1.7
# Builds the three showcase executables once and packages each into its own linux/amd64 runtime image.
# Run from the repository root (the build needs the Contexa core modules):
#   docker build --platform linux/amd64 -f contexa-showcase/infra/docker/showcase.Dockerfile --target portal  -t contexa-showcase-portal:local .
#   docker build --platform linux/amd64 -f contexa-showcase/infra/docker/showcase.Dockerfile --target plain   -t contexa-showcase-plain:local .
#   docker build --platform linux/amd64 -f contexa-showcase/infra/docker/showcase.Dockerfile --target contexa -t contexa-showcase-contexa:local .

FROM eclipse-temurin:17-jdk-jammy AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
# The build has no .git; pass the commit: --build-arg SHOWCASE_GIT_COMMIT=$(git rev-parse --short=12 HEAD)
ARG SHOWCASE_GIT_COMMIT=unknown
ENV SHOWCASE_GIT_COMMIT=${SHOWCASE_GIT_COMMIT}
COPY . .
RUN chmod +x gradlew \
    && ./gradlew --no-daemon -Pshowcase.nativePlatform=linux-x86_64 \
        :showcase-portal:bootJar :showcase-workload-plain:bootJar :showcase-workload-contexa:bootJar -x test

FROM eclipse-temurin:21-jre-jammy AS runtime-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 10001 showcase \
    && useradd -r -u 10001 -g showcase -m showcase \
    && mkdir -p /app \
    && chown showcase:showcase /app
WORKDIR /app
ENV TZ=UTC \
    SHOWCASE_BIND_ADDRESS=0.0.0.0 \
    JAVA_TOOL_OPTIONS="-Duser.timezone=UTC -Dfile.encoding=UTF-8 -XX:MaxRAMPercentage=75"
USER 10001
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

FROM runtime-base AS portal
COPY --from=builder --chown=10001:10001 /build/contexa-showcase/showcase-portal/build/libs/showcase-portal-0.1.0.jar /app/app.jar
EXPOSE 19180
HEALTHCHECK --interval=10s --timeout=3s --start-period=60s --retries=6 \
    CMD curl -fsS http://127.0.0.1:19180/actuator/health || exit 1

FROM runtime-base AS plain
COPY --from=builder --chown=10001:10001 /build/contexa-showcase/showcase-workload-plain/build/libs/showcase-workload-plain-0.1.0.jar /app/app.jar
EXPOSE 19181
HEALTHCHECK --interval=10s --timeout=3s --start-period=60s --retries=6 \
    CMD curl -fsS http://127.0.0.1:19181/actuator/health || exit 1

FROM runtime-base AS contexa
COPY --from=builder --chown=10001:10001 /build/contexa-showcase/showcase-workload-contexa/build/libs/showcase-workload-contexa-0.1.0.jar /app/app.jar
EXPOSE 19182
HEALTHCHECK --interval=10s --timeout=3s --start-period=120s --retries=12 \
    CMD curl -fsS http://127.0.0.1:19182/actuator/health || exit 1

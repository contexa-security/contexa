# ============================================================
# Contexa AI-Native Zero Trust Security Platform
# Multi-stage Docker build for production deployment
# ============================================================

# --- Stage 1: Build ---
FROM eclipse-temurin:21-jdk AS builder

WORKDIR /build

# Copy Gradle wrapper and config first (layer cache optimization)
COPY gradle/ gradle/
COPY gradlew settings.gradle build.gradle gradle.properties ./

# Copy module build files
COPY contexa-common/build.gradle contexa-common/build.gradle
COPY contexa-core/build.gradle contexa-core/build.gradle
COPY contexa-identity/build.gradle contexa-identity/build.gradle
COPY contexa-iam/build.gradle contexa-iam/build.gradle
COPY contexa-autoconfigure/build.gradle contexa-autoconfigure/build.gradle
COPY spring-boot-starter-contexa/build.gradle spring-boot-starter-contexa/build.gradle

# Download dependencies (cached layer)
RUN chmod +x gradlew && ./gradlew dependencies --no-daemon 2>/dev/null || true

# Copy source code
COPY contexa-common/src contexa-common/src
COPY contexa-core/src contexa-core/src
COPY contexa-identity/src contexa-identity/src
COPY contexa-iam/src contexa-iam/src
COPY contexa-autoconfigure/src contexa-autoconfigure/src
COPY spring-boot-starter-contexa/src spring-boot-starter-contexa/src

# Build application
RUN ./gradlew :spring-boot-starter-contexa:bootJar --no-daemon -x test

# --- Stage 2: Runtime ---
FROM eclipse-temurin:21-jre

LABEL maintainer="Contexa <contact@contexa.io>"
LABEL description="Contexa AI-Native Zero Trust Security Platform"

# Security: run as non-root user
RUN groupadd -r contexa && useradd -r -g contexa -m contexa

WORKDIR /app

# Copy built JAR
COPY --from=builder /build/spring-boot-starter-contexa/build/libs/*.jar app.jar

# Copy GeoLite2 database (if available)
COPY data/GeoLite2-City.mmdb data/GeoLite2-City.mmdb

# Create directories for logs and temp files
RUN mkdir -p /app/logs /app/temp && chown -R contexa:contexa /app

# Switch to non-root user
USER contexa

# JVM optimization for containers
ENV JAVA_OPTS="-XX:+UseG1GC \
  -XX:MaxRAMPercentage=75.0 \
  -XX:+UseContainerSupport \
  -XX:+HeapDumpOnOutOfMemoryError \
  -XX:HeapDumpPath=/app/logs/heapdump.hprof \
  -Djava.security.egd=file:/dev/./urandom \
  -Dfile.encoding=UTF-8"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=60s \
  CMD curl -sf http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS} -jar app.jar"]

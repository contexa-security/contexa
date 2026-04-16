FROM eclipse-temurin:21-jre

LABEL maintainer="Contexa <contexa73@gmail.com>"
LABEL description="Contexa Site - AI-Native Zero Trust Security Platform"

RUN groupadd -r contexa && useradd -r -g contexa -m contexa

WORKDIR /app
COPY build/libs/contexa-site-*.jar app.jar

RUN mkdir -p /app/logs && chown -R contexa:contexa /app
USER contexa

ENV JAVA_OPTS="-XX:+UseG1GC -XX:MaxRAMPercentage=75.0 -XX:+UseContainerSupport -Djava.security.egd=file:/dev/./urandom -Dfile.encoding=UTF-8"

EXPOSE 9080

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=60s \
  CMD curl -sf http://localhost:9080/actuator/health || exit 1

ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS} -jar app.jar"]

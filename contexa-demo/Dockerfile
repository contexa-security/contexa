FROM eclipse-temurin:17-jdk-jammy
WORKDIR /opt/lab
COPY build/libs/contexa-demo-0.1.0.jar /opt/lab/contexa-demo.jar
COPY infra/logback-public.xml /opt/lab/logback.xml
USER 10001:10001
ENTRYPOINT ["java", "-Xms128m", "-Xmx768m", "-Dlogging.config=/opt/lab/logback.xml", "-jar", "/opt/lab/contexa-demo.jar"]

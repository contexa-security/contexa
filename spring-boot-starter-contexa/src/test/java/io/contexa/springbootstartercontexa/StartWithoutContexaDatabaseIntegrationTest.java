/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.springbootstartercontexa;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * An application that keeps its own sign-in starts without Contexa when Contexa's database is down, and says so in one line.
 * These start a real application on a real port: the failure was a missing bean of Contexa's during the start.
 */
@ExtendWith(OutputCaptureExtension.class)
@Timeout(180)
class StartWithoutContexaDatabaseIntegrationTest {

    private static final String DOWN_DATABASE = "contexa.datasource.url=jdbc:postgresql://127.0.0.1:1/contexa";
    private static final String DATABASE_USER = "contexa.datasource.username=contexa";
    private static final String DATABASE_PASSWORD = "contexa.datasource.password=contexa";
    private static final String TEST_PACKAGE = "io.contexa.springbootstartercontexa";

    /** The operator's own settings name the mode: that is how the application was measured when it did not start. */
    @Test
    void aModeSetByTheOperatorDoesNotBringContexaBackWhenItsDatabaseIsDown(CapturedOutput output) throws Exception {
        try (ConfigurableApplicationContext context = start(HostApplication.class,
                "contexa.ai.security.mode=SANDBOX", DOWN_DATABASE, DATABASE_USER, DATABASE_PASSWORD)) {
            assertTheApplicationRunsWithoutContexa(context);
        }
        assertThat(errorLines(output)).hasSize(1);
        assertThat(errorLines(output).get(0)).contains("Contexa's database cannot be reached");
    }

    @Test
    void theModeOfTheAnnotationStartsWithoutContexaAsWell(CapturedOutput output) throws Exception {
        try (ConfigurableApplicationContext context = start(HostApplication.class, DOWN_DATABASE, DATABASE_USER, DATABASE_PASSWORD)) {
            assertTheApplicationRunsWithoutContexa(context);
        }
        assertThat(errorLines(output)).hasSize(1);
    }

    /** The application says it has no database of its own: with Contexa off nothing needs the one that is down. */
    @Test
    void anApplicationWithoutADatabaseOfItsOwnStartsWithoutContexaToo(CapturedOutput output) throws Exception {
        try (ConfigurableApplicationContext context = start(HostApplication.class, "contexa.ai.security.mode=SANDBOX",
                "contexa.datasource.isolation.contexa-owned-application=true", DOWN_DATABASE, DATABASE_USER, DATABASE_PASSWORD)) {
            assertTheApplicationRunsWithoutContexa(context);
        }
        assertThat(errorLines(output)).hasSize(1);
    }

    /** The same reading of the mode: Contexa was switched off, and everything of it came back. */
    @Test
    void contexaSwitchedOffStaysOffWithAModeInTheSettings(CapturedOutput output) throws Exception {
        try (ConfigurableApplicationContext context = start(HostApplication.class,
                "contexa.enabled=false", "contexa.ai.security.mode=SANDBOX", DOWN_DATABASE, DATABASE_USER, DATABASE_PASSWORD)) {
            assertTheApplicationRunsWithoutContexa(context);
        }
        assertThat(errorLines(output)).isEmpty();
    }

    /** @EnableAISecurity is the decision to apply security: a mode left in the settings is not. */
    @Test
    void aModeInTheSettingsWithoutTheAnnotationLeavesTheApplicationAlone(CapturedOutput output) throws Exception {
        try (ConfigurableApplicationContext context = start(HostWithoutAnnotation.class,
                "contexa.ai.security.mode=SANDBOX", DOWN_DATABASE, DATABASE_USER, DATABASE_PASSWORD)) {
            assertTheApplicationRunsWithoutContexa(context);
        }
        assertThat(errorLines(output)).isEmpty();
    }

    /** Where Contexa owns the sign-in nobody could sign in without it. */
    @Test
    void anApplicationWhoseSignInContexaOwnsDoesNotStart() {
        assertThatThrownBy(() -> start(ContexaOwnedApplication.class, DOWN_DATABASE, DATABASE_USER, DATABASE_PASSWORD).close())
                .hasStackTraceContaining("Connection to 127.0.0.1:1 refused");
    }

    private ConfigurableApplicationContext start(Class<?> application, String... settings) {
        List<String> properties = new ArrayList<>(List.of("spring.main.banner-mode=off", "server.port=0"));
        properties.addAll(Arrays.asList(settings));
        return new SpringApplicationBuilder(application)
                .web(WebApplicationType.SERVLET)
                .properties(properties.toArray(new String[0]))
                .run();
    }

    private void assertTheApplicationRunsWithoutContexa(ConfigurableApplicationContext context) throws IOException, InterruptedException {
        assertThat(contexaBeans(context)).isEmpty();
        int port = ((ServletWebServerApplicationContext) context).getWebServer().getPort();
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/host/ping")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo("the application answers");
    }

    private List<String> contexaBeans(ConfigurableApplicationContext context) {
        return Arrays.stream(context.getBeanDefinitionNames())
                .filter(name -> {
                    Class<?> type = context.getType(name, false);
                    return type != null && type.getName().startsWith("io.contexa.") && !type.getName().startsWith(TEST_PACKAGE);
                })
                .toList();
    }

    private List<String> errorLines(CapturedOutput output) {
        return output.getOut().lines().filter(line -> line.contains("] ERROR ")).toList();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    static class HostApplication extends HostBeans {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    static class HostWithoutAnnotation extends HostBeans {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class ContexaOwnedApplication {
    }

    /** Inherited, not imported: an import of a class under io.contexa goes through Contexa's auto-configuration filter. */
    abstract static class HostBeans {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll()).build();
        }

        @Bean
        HostController hostController() {
            return new HostController();
        }
    }

    @RestController
    static class HostController {

        @GetMapping("/host/ping")
        String ping() {
            return "the application answers";
        }
    }
}

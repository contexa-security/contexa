/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.springbootstartercontexa;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacore.testsupport.TestStores;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.UnreachableFilterChainException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * R-14 of docs/agent/운영모드-정상화-구현계획.md on a real application and a real PostgreSQL, a database of its own for each
 * test. With mode FULL Contexa's main chain takes every request the chains before it leave, and Spring Security runs no
 * chain after one that takes every request (F-2): an application chain that takes every request is refused at start, and
 * Spring Boot's failure analysis tells the refusal in Contexa's words, with the application's chain by name and what to
 * change. An application chain narrowed with {@code securityMatcher}, or none, starts in mode FULL; in mode SANDBOX the
 * application's chain stays its main one and starts.
 * <p>
 * The refusal comes from Spring Security while it builds its filter, after Contexa's database was reached: what the refused
 * start leaves in that database is measured and written out, not asserted (a limitation the plan records under M2-4).
 */
@ExtendWith(OutputCaptureExtension.class)
@Timeout(300)
@DisplayName("모드별 앱 보안 체인: FULL의 모든 요청 앱 체인은 Contexa 안내로 거부, 좁힌 체인·체인 없음·SANDBOX는 기동")
class ApplicationChainByModeIntegrationTest {

    /** The tables of Contexa's schema, as a start that is not refused installs them. */
    private static final int CONTEXA_TABLES = 117;

    private static final String REFUSAL = "With mode FULL Contexa's main chain takes every request, and the application declares"
            + " its own security chain(s) [hostChain] for every request as well. Spring Security runs no chain after one that"
            + " takes every request, so one of the two would never run.";
    private static final String ACTION = "Narrow the application's chain to the paths it protects, with http.securityMatcher(...):"
            + " it then runs ahead of Contexa's main chain. For an application whose own chain stays its main one, use"
            + " @EnableAISecurity without mode = FULL (SANDBOX).";
    private static final String ANSWER = "the application answers";

    private TestStores.Database server;
    private String database;
    private final List<String> dataSources = new CopyOnWriteArrayList<>();

    @BeforeEach
    void aDatabaseOfItsOwn() throws SQLException {
        server = TestStores.database();
        database = "r14_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        try (Connection admin = admin(); Statement statement = admin.createStatement()) {
            statement.execute("create database " + database);
        }
    }

    @AfterEach
    void dropIt() throws SQLException {
        if (database == null) {
            return;
        }
        try (Connection admin = admin(); Statement statement = admin.createStatement()) {
            statement.execute("drop database if exists " + database + " with (force)");
        }
    }

    @Test
    @DisplayName("FULL + 모든 요청을 받는 앱 체인: 기동이 거부되고, 실패 분석은 앱 체인 이름을 넣은 Contexa 안내(좁히거나 SANDBOX)다")
    void anApplicationChainForEveryRequestIsRefusedInContexasWords(CapturedOutput output) throws Exception {
        Throwable failure = catchThrowable(() -> run(FullWithAChainForEveryRequest.class).close());

        UnreachableFilterChainException unreachable = cause(failure, UnreachableFilterChainException.class);
        assertThat(unreachable).as("Spring Security refused the application's chain").isNotNull();
        assertThat(unreachable.getFilterChain().toString()).contains("defined as 'hostChain'");
        String reported = output.toString().replace("\r\n", "\n");
        assertThat(reported).contains("APPLICATION FAILED TO START", "Description:\n\n" + REFUSAL + "\n",
                "Action:\n\n" + ACTION + "\n");

        System.out.println("REFUSED START LEAVES [ctxa tables=" + contexaTables() + ", data sources created=" + dataSources + "]");
    }

    @Test
    @DisplayName("FULL + 앱 체인 없음: 기동하고 Contexa 표가 설치된다")
    void withoutAChainOfItsOwnTheApplicationStarts() throws Exception {
        try (ConfigurableApplicationContext context = run(FullWithoutAChain.class)) {
            assertThat(context.isActive()).isTrue();
        }
        assertThat(contexaTables()).isEqualTo(CONTEXA_TABLES);
    }

    @Test
    @DisplayName("FULL + securityMatcher로 좁힌 앱 체인: 기동하고, 그 경로는 앱 체인이 Contexa 주 체인보다 먼저 답한다")
    void aChainNarrowedToItsPathsStarts() throws Exception {
        try (ConfigurableApplicationContext context = run(FullWithANarrowedChain.class)) {
            HttpResponse<String> answer = get(context, "/h/ping");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo(ANSWER);
        }
        assertThat(contexaTables()).isEqualTo(CONTEXA_TABLES);
    }

    @Test
    @DisplayName("SANDBOX + 모든 요청을 받는 앱 체인: 기동하고 앱 체인이 답한다")
    void inModeSandboxTheApplicationsChainStarts() throws Exception {
        try (ConfigurableApplicationContext context = run(SandboxWithAChainForEveryRequest.class,
                "contexa.datasource.isolation.contexa-owned-application=true")) {
            HttpResponse<String> answer = get(context, "/host/ping");
            assertThat(answer.statusCode()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo(ANSWER);
        }
        assertThat(contexaTables()).isEqualTo(CONTEXA_TABLES);
    }

    /**
     * The application on the test's database. No model is configured, so the capability check reports it instead of
     * stopping the start once every bean exists.
     */
    private ConfigurableApplicationContext run(Class<?> application, String... settings) {
        List<String> properties = new ArrayList<>(List.of("spring.main.banner-mode=off", "server.port=0",
                "contexa.datasource.url=" + url(database), "contexa.datasource.username=" + server.username(),
                "contexa.datasource.password=" + server.password(), "contexa.capability.mode=WARN"));
        properties.addAll(Arrays.asList(settings));
        return new SpringApplicationBuilder(application)
                .web(WebApplicationType.SERVLET)
                .initializers(recorder())
                .properties(properties.toArray(new String[0]))
                .run();
    }

    /** Every data source the start creates, whether Contexa's or the application's. */
    private ApplicationContextInitializer<ConfigurableApplicationContext> recorder() {
        return context -> context.getBeanFactory().addBeanPostProcessor(new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (bean instanceof DataSource) {
                    dataSources.add(beanName);
                }
                return bean;
            }
        });
    }

    private static HttpResponse<String> get(ConfigurableApplicationContext context, String path) throws Exception {
        int port = ((ServletWebServerApplicationContext) context).getWebServer().getPort();
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static <T extends Throwable> T cause(Throwable failure, Class<T> type) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (type.isInstance(cause)) {
                return type.cast(cause);
            }
        }
        return null;
    }

    private int contexaTables() throws SQLException {
        try (Connection connection = DriverManager.getConnection(url(database), server.username(), server.password());
             Statement statement = connection.createStatement();
             ResultSet count = statement.executeQuery(
                     "select count(*) from information_schema.tables where table_name like 'ctxa\\_%'")) {
            count.next();
            return count.getInt(1);
        }
    }

    private Connection admin() throws SQLException {
        return DriverManager.getConnection(server.url(), server.username(), server.password());
    }

    private String url(String name) {
        String url = server.url();
        int query = url.indexOf('?');
        String base = query >= 0 ? url.substring(0, query) : url;
        return base.substring(0, base.lastIndexOf('/') + 1) + name + (query >= 0 ? url.substring(query) : "");
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FullWithAChainForEveryRequest {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated()).build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    @Import(HostController.class)
    static class FullWithoutAChain {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    @Import(HostController.class)
    static class FullWithANarrowedChain {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http.securityMatcher("/h/**").authorizeHttpRequests(requests -> requests.anyRequest().permitAll()).build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    @Import(HostController.class)
    static class SandboxWithAChainForEveryRequest {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll()).build();
        }
    }

    @RestController
    static class HostController {

        @GetMapping({"/host/ping", "/h/ping"})
        String ping() {
            return ANSWER;
        }
    }
}

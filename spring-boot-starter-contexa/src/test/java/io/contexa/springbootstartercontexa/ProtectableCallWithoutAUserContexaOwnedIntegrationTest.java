/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.springbootstartercontexa;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties.EnforcementMode;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsRuntimeApplier;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The same protected method where Contexa owns the sign-in (FULL), on a real application on a real port with Contexa's
 * database on a real PostgreSQL. Contexa's chain covers every path here, so its own exception translation answers a
 * refusal; where the operating mode decides on nobody (OBSERVE, DISABLED) the visitor's call runs, as it does where the
 * application owns the sign-in.
 */
@Timeout(600)
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class ProtectableCallWithoutAUserContexaOwnedIntegrationTest {

    private static final String CONTEXA_DATABASE = "contexa_owned";

    private static ConfigurableApplicationContext application;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER).build();

    @BeforeAll
    static void start() throws Exception {
        String user = System.getenv("CONTEXA_TEST_DB_USERNAME");
        String password = System.getenv("CONTEXA_TEST_DB_PASSWORD");
        List<String> properties = new ArrayList<>(List.of("spring.main.banner-mode=off", "server.port=0",
                "spring.datasource.url=" + database("host_app"),
                "spring.datasource.username=" + user, "spring.datasource.password=" + password,
                "contexa.datasource.url=" + database(CONTEXA_DATABASE),
                "contexa.datasource.username=" + user, "contexa.datasource.password=" + password,
                "contexa.security.zerotrust.mode=DISABLED",
                // the call has to reach the method: a path no policy names asks for a sign-in on a new installation, which would
                // answer before the method is ever called
                "contexa.policy.no-matching-url-policy-decision=PERMIT"));
        application = new SpringApplicationBuilder(ContexaOwnedApplication.class)
                .web(WebApplicationType.SERVLET)
                .properties(properties.toArray(new String[0]))
                .run();
    }

    @AfterAll
    static void stop() {
        if (application != null) {
            application.close();
        }
    }

    /** A database of its own on the test server, next to the one the variable names, made when missing. */
    private static String database(String name) throws Exception {
        String testDatabase = System.getenv("CONTEXA_TEST_DB_URL");
        try (Connection connection = DriverManager.getConnection(testDatabase,
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
             Statement statement = connection.createStatement()) {
            boolean exists;
            try (ResultSet found = statement.executeQuery("SELECT 1 FROM pg_database WHERE datname = '" + name + "'")) {
                exists = found.next();
            }
            if (!exists) {
                statement.execute("CREATE DATABASE " + name);
            }
        }
        int query = testDatabase.indexOf('?');
        String address = query < 0 ? testDatabase : testDatabase.substring(0, query);
        return address.substring(0, address.lastIndexOf('/') + 1) + name + (query < 0 ? "" : testDatabase.substring(query));
    }

    private static void mode(EnforcementMode mode) {
        SecurityZeroTrustProperties properties = application.getBean(SecurityZeroTrustProperties.class);
        SystemSettingsRuntimeApplier.applyZeroTrustSettings(properties, mode);
        assertThat(properties.getMode()).isEqualTo(mode);
    }

    private static int runs() {
        return application.getBean(Secured.class).runs();
    }

    private HttpResponse<String> get(String path) throws Exception {
        int port = ((ServletWebServerApplicationContext) application).getWebServer().getPort();
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                        .header("Accept", "application/json").timeout(Duration.ofSeconds(30)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"OBSERVE", "DISABLED"})
    void whereTheModeDecidesOnNobodyAVisitorsCallRuns(EnforcementMode mode) throws Exception {
        mode(mode);
        int runs = runs();

        HttpResponse<String> answer = get("/h/m/secured");

        assertThat(answer.statusCode()).as(answer.body()).isEqualTo(200);
        assertThat(answer.body()).isEqualTo("secured for anonymousUser");
        assertThat(runs() - runs).isEqualTo(1);
    }

    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"SHADOW", "ENFORCE"})
    void whereTheModeDecidesContexasChainAnswersTheRefusal(EnforcementMode mode) throws Exception {
        mode(mode);
        int runs = runs();

        HttpResponse<String> answer = get("/h/m/secured");

        assertThat(answer.statusCode()).as(answer.body()).isEqualTo(401);
        assertThat(answer.body()).as("the entry point of Contexa's chain, not the answer of a refusal no chain took")
                .contains("\"E001\"").doesNotContain("Internal Server Error");
        assertThat(runs() - runs).isZero();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class ContexaOwnedApplication extends ApplicationBeans {
    }

    /** Inherited, not imported: an import of a class under io.contexa goes through Contexa's auto-configuration filter. */
    abstract static class ApplicationBeans {

        @Bean
        Secured secured() {
            return new Secured();
        }

        @Bean
        Pages pages(Secured secured) {
            return new Pages(secured);
        }
    }

    public static class Secured {

        private final AtomicInteger runs = new AtomicInteger();

        @Protectable
        public String read() {
            runs.incrementAndGet();
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            return "secured for " + (authentication != null ? authentication.getName() : "nobody");
        }

        public int runs() {
            return runs.get();
        }
    }

    @RestController
    static class Pages {

        private final Secured secured;

        Pages(Secured secured) {
            this.secured = secured;
        }

        @GetMapping("/h/m/secured")
        String page() {
            return secured.read();
        }
    }
}

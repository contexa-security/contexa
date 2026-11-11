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
package io.contexa.autoconfigure.iam.xacml;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsRuntimeApplier;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaidentity.security.core.context.OrderedSecurityFilterChain;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The application owns the sign-in (SANDBOX): it keeps Spring Boot's default chain, and Contexa builds no chain of its
 * own, so its URL policies decide no request of the application. The decision for paths no URL policy names changes no
 * answer there, whatever it is.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@Timeout(300)
class HostOwnedUnnamedPathsPostgresTest {

    private static final String HOST_USER = "hostuser";
    private static final String HOST_PASSWORD = "fx6-host-password";

    private String database;
    private ConfigurableApplicationContext context;
    private JdbcTemplate jdbc;
    private int port;

    @BeforeAll
    void start() {
        database = "contexa_fx6_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        new JdbcTemplate(dataSource("postgres")).execute("create database " + database);
        jdbc = new JdbcTemplate(dataSource(database));
        context = new SpringApplicationBuilder(HostApplication.class)
                .web(WebApplicationType.SERVLET)
                .properties("spring.main.banner-mode=off", "server.port=0",
                        "contexa.datasource.url=" + urlOf(database),
                        "contexa.datasource.username=" + user(),
                        "contexa.datasource.password=" + password(),
                        "contexa.llm.selection.chat.mode=spring-primary",
                        "contexa.llm.selection.embedding.mode=spring-primary",
                        "contexa.security.zerotrust.mode=DISABLED")
                .run();
        port = ((ServletWebServerApplicationContext) context).getWebServer().getPort();
    }

    @AfterAll
    void stop() {
        if (context != null) {
            context.close();
        }
        JdbcTemplate admin = new JdbcTemplate(dataSource("postgres"));
        admin.queryForList("select pg_terminate_backend(pid) from pg_stat_activity where datname = ?", database);
        admin.execute("drop database if exists " + database);
    }

    @Test
    void contexaBuildsNoChainThatAsksItsUrlPolicies() {
        assertThat(context.getBean(FilterChainProxy.class).getFilterChains())
                .noneMatch(chain -> chain instanceof OrderedSecurityFilterChain);
    }

    @Test
    void theApplicationAnswersTheSameWhateverTheDecisionForPathsWithoutAPolicy() throws Exception {
        assertThat(jdbc.queryForObject("select no_matching_url_policy_decision from ctxa_system_settings", String.class))
                .as("nobody chose a decision").isNull();
        Map<String, String> withTheDefault = answers();
        Map<String, String> withPermit;
        Map<String, String> withDeny;
        try {
            decide("PERMIT");
            withPermit = answers();
            decide("DENY");
            withDeny = answers();
        } finally {
            decide("AUTHENTICATED");
        }

        assertThat(withPermit).isEqualTo(withTheDefault);
        assertThat(withDeny).isEqualTo(withTheDefault);
        assertThat(withTheDefault).containsEntry("/h/secured/data anonymous", "401 ")
                .containsEntry("/h/secured/data host user", "200 host data")
                .containsEntry("/h/not-there anonymous", "401 ");
    }

    private Map<String, String> answers() throws Exception {
        Map<String, String> answers = new LinkedHashMap<>();
        for (String path : List.of("/h/secured/data", "/h/not-there", "/error", "/contexa/admin", "/contexa/admin/login")) {
            HttpResponse<String> anonymous = send(path, null);
            answers.put(path + " anonymous", anonymous.statusCode() + " " + bodyOfTheApplication(anonymous));
            HttpResponse<String> hostUser = send(path, HOST_USER + ":" + HOST_PASSWORD);
            answers.put(path + " host user", hostUser.statusCode() + " " + bodyOfTheApplication(hostUser));
        }
        return answers;
    }

    private static String bodyOfTheApplication(HttpResponse<String> response) {
        return response.body().equals("host data") ? response.body() : "";
    }

    private HttpResponse<String> send(String path, String credentials) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .header("Accept", "application/json").GET();
        if (credentials != null) {
            request.header("Authorization", "Basic "
                    + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)));
        }
        return HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
                .send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private void decide(String decision) {
        jdbc.update("update ctxa_system_settings set no_matching_url_policy_decision = ?", decision);
        context.getBean(SystemSettingsRuntimeApplier.class).apply();
        CustomDynamicAuthorizationManager manager = context.getBean(CustomDynamicAuthorizationManager.class);
        manager.reload();
        assertThat(manager.getNoMatchingUrlPolicyDecision().name()).isEqualTo(decision);
    }

    private static DriverManagerDataSource dataSource(String name) {
        return new DriverManagerDataSource(urlOf(name), user(), password());
    }

    private static String urlOf(String name) {
        String url = System.getenv("CONTEXA_TEST_DB_URL");
        int slash = url.lastIndexOf('/');
        return url.substring(0, slash + 1) + name;
    }

    private static String user() {
        return System.getenv("CONTEXA_TEST_DB_USERNAME");
    }

    private static String password() {
        return System.getenv("CONTEXA_TEST_DB_PASSWORD");
    }

    /** Spring Boot's default chain only: every request needs a signed-in user, the application's user signs in with Basic. */
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    static class HostApplication {

        @Bean
        HostController hostController() {
            return new HostController();
        }

        @Bean
        UserDetailsService hostUsers() {
            return new InMemoryUserDetailsManager(
                    User.withUsername(HOST_USER).password("{noop}" + HOST_PASSWORD).roles("USER").build());
        }

        @Bean
        ChatModel silentChatModel() {
            return new FullModeUnnamedPathsPostgresTest.SilentChatModel();
        }

        @Bean
        EmbeddingModel flatEmbeddingModel() {
            return new FullModeUnnamedPathsPostgresTest.FlatEmbeddingModel();
        }
    }

    @RestController
    static class HostController {

        @GetMapping("/h/secured/data")
        String data() {
            return "host data";
        }
    }
}

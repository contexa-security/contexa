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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsRuntimeApplier;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
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
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLEncoder;
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
 * Contexa owns the sign-in with tokens (an OAuth2 flow of the application's platform configuration, the URL policies
 * asked for every other request): a call with an access token reaches a path no policy names, a call without one is
 * asked to sign in, and the endpoints that hand out and describe tokens stay open.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@Timeout(300)
class FullModeTokenCallsPostgresTest {

    private static final String USER = "fx6token";
    private static final String USER_PASSWORD = "fx6-token-password";
    private static final ObjectMapper JSON = new ObjectMapper();

    private String database;
    private ConfigurableApplicationContext context;
    private int port;

    @BeforeAll
    void start() {
        database = "contexa_fx6_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        new JdbcTemplate(dataSource("postgres")).execute("create database " + database);
        context = new SpringApplicationBuilder(TokenApplication.class)
                .web(WebApplicationType.SERVLET)
                .properties("spring.main.banner-mode=off", "server.port=0",
                        "contexa.datasource.url=" + urlOf(database),
                        "contexa.datasource.username=" + user(),
                        "contexa.datasource.password=" + password(),
                        "contexa.llm.selection.chat.mode=spring-primary",
                        "contexa.llm.selection.embedding.mode=spring-primary",
                        "contexa.auth.oauth2.client-secret=fx6-client-secret",
                        "contexa.security.zerotrust.mode=DISABLED")
                .run();
        port = ((ServletWebServerApplicationContext) context).getWebServer().getPort();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource(database));
        jdbc.update("insert into ctxa_users (username, email, password, name, enabled, account_locked, credentials_expired, "
                        + "failed_login_attempts, mfa_enabled, bridge_managed, external_auth_only, created_at, password_changed_at) "
                        + "values (?, ?, ?, ?, true, false, false, 0, false, false, false, current_timestamp, current_timestamp)",
                USER, USER + "@localhost", PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(USER_PASSWORD),
                "FX6 Token");
        Long id = jdbc.queryForObject("select id from ctxa_users where username = ?", Long.class, USER);
        jdbc.update("insert into ctxa_user_groups (user_id, group_id, assigned_at) values (?, 4, current_timestamp)", id);
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
    void aCallWithAnAccessTokenReachesAPathNoPolicyNamesAndACallWithoutOneIsAskedToSignIn() throws Exception {
        String token = accessToken();

        HttpResponse<String> withToken = get("/h/secured/data", token);
        assertThat(withToken.statusCode()).isEqualTo(200);
        assertThat(withToken.body()).isEqualTo("host data");
        HttpResponse<String> withoutToken = get("/h/secured/data", null);
        assertThat(withoutToken.statusCode()).isEqualTo(401);
        assertThat(withoutToken.body()).doesNotContain("host data");
        assertThat(get("/h/secured/data", "not-a-token").statusCode()).isEqualTo(401);
    }

    /**
     * The same requests under the former default (PERMIT) and under the new one: the sign-in, a call with a token and
     * the documents that describe tokens answer the same. A call without a token is asked to sign in, and so is a
     * request to the token endpoint that names no client, which no client can make: it was refused before as well.
     */
    @Test
    void onlyCallsWithoutATokenOrAClientChangeAgainstTheFormerDefault() throws Exception {
        JdbcTemplate jdbc = new JdbcTemplate(dataSource(database));
        Map<String, String> asBefore;
        decide(jdbc, "PERMIT");
        try {
            asBefore = answers();
        } finally {
            decide(jdbc, "AUTHENTICATED");
        }
        Map<String, String> now = answers();

        Map<String, String> changed = new LinkedHashMap<>();
        now.forEach((request, answer) -> {
            if (!answer.equals(asBefore.get(request))) {
                changed.put(request, asBefore.get(request) + " -> " + answer);
            }
        });
        assertThat(changed).containsOnly(
                Map.entry("GET /h/secured/data without a token", "200 -> 401"),
                Map.entry("GET /oauth2/token without a token", "404 -> 401"),
                Map.entry("POST /oauth2/token without a token", "400 -> 401"));
        assertThat(now).containsEntry("GET /oauth2/jwks without a token", "200")
                .containsEntry("GET /.well-known/openid-configuration without a token", "200")
                .containsEntry("GET /h/secured/data with a token", "200")
                .containsEntry("POST /login without a token", "200")
                .containsEntry("POST /oauth2/token as the client", "200 token");
    }

    /** One sign-in first: a sign-in ends the user's earlier ones, and its token is the one the call carries. */
    private Map<String, String> answers() throws Exception {
        Map<String, String> answers = new LinkedHashMap<>();
        HttpResponse<String> login = signIn();
        answers.put("POST /login without a token", String.valueOf(login.statusCode()));
        String token = JSON.readTree(login.body()).path("accessToken").asText("");
        for (String path : List.of("/h/secured/data", "/oauth2/jwks", "/.well-known/openid-configuration",
                "/.well-known/oauth-authorization-server", "/oauth2/token")) {
            answers.put("GET " + path + " without a token", String.valueOf(get(path, null).statusCode()));
        }
        answers.put("GET /h/secured/data with a token", String.valueOf(get("/h/secured/data", token).statusCode()));
        answers.put("POST /oauth2/token without a token", String.valueOf(send(HttpRequest.newBuilder(URI.create(base() + "/oauth2/token"))
                .header("Accept", "application/json").header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials"))).statusCode()));
        HttpResponse<String> client = send(HttpRequest.newBuilder(URI.create(base() + "/oauth2/token"))
                .header("Accept", "application/json").header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                        "default-client:fx6-client-secret".getBytes(StandardCharsets.UTF_8)))
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials&scope=read")));
        answers.put("POST /oauth2/token as the client", client.statusCode() + " "
                + (JSON.readTree(client.body()).has("access_token") ? "token" : client.body()));
        return answers;
    }

    /** What the system settings screen does when an operator saves the decision: the row, then the running instance. */
    private void decide(JdbcTemplate jdbc, String decision) {
        jdbc.update("update ctxa_system_settings set no_matching_url_policy_decision = ?", decision);
        context.getBean(SystemSettingsRuntimeApplier.class).apply();
        CustomDynamicAuthorizationManager manager = context.getBean(CustomDynamicAuthorizationManager.class);
        manager.reload();
        assertThat(manager.getNoMatchingUrlPolicyDecision().name()).isEqualTo(decision);
    }

    private String accessToken() throws Exception {
        HttpResponse<String> login = signIn();
        assertThat(login.statusCode()).as("sign-in: %s", login.body()).isEqualTo(200);
        String token = JSON.readTree(login.body()).path("accessToken").asText("");
        assertThat(token).as("the access token of the sign-in").isNotEmpty();
        return token;
    }

    private HttpResponse<String> signIn() throws Exception {
        return send(HttpRequest.newBuilder(URI.create(base() + "/login"))
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("username=" + USER + "&password="
                        + URLEncoder.encode(USER_PASSWORD, StandardCharsets.UTF_8))));
    }

    private HttpResponse<String> get(String path, String token) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base() + path)).header("Accept", "application/json");
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        return send(request.GET());
    }

    private HttpResponse<String> send(HttpRequest.Builder request) throws Exception {
        return HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
                .send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private String base() {
        return "http://127.0.0.1:" + port;
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

    /** The platform configuration of an application that signs in with a form and calls with tokens, like the examples. */
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class TokenApplication {

        @Bean
        PlatformConfig platformDslConfig(ApplicationContext applicationContext,
                                         @Lazy CustomDynamicAuthorizationManager contexaCustomDynamicAuthorizationManager)
                throws Exception {
            return new IdentityDslRegistry<HttpSecurity>(applicationContext)
                    .global(http -> http
                            .csrf(AbstractHttpConfigurer::disable)
                            .authorizeHttpRequests(requests -> requests
                                    .requestMatchers("/contexa/css/**", "/contexa/js/**").permitAll()
                                    .anyRequest().access(contexaCustomDynamicAuthorizationManager)))
                    .form(Customizer.withDefaults())
                    .oauth2(Customizer.withDefaults())
                    .build();
        }

        @Bean
        HostController hostController() {
            return new HostController();
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

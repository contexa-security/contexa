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
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The decision for URLs no policy names where Contexa owns the sign-in (FULL), on a real servlet container and a real
 * PostgreSQL database, from the answer to an anonymous request: a new installation holds no decision and closes the path,
 * a configured decision applies to it although the seed wrote a settings row, and an installation made by an older
 * version keeps what its row holds (PERMIT or AUTHENTICATED), whatever the configuration says, with its column changed in
 * place. Every case starts the application for real.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@Timeout(900)
class NoMatchingUrlDecisionUnsetPostgresTest {

    private static final String UNNAMED_PATH = "/h/secured/data";
    private static final String DECISION_COLUMN = "no_matching_url_policy_decision";

    private final List<String> databases = new ArrayList<>();
    private ConfigurableApplicationContext context;

    @AfterEach
    void cleanUp() {
        closeApplication();
        JdbcTemplate admin = new JdbcTemplate(dataSource("postgres"));
        for (String name : databases) {
            admin.queryForList("select pg_terminate_backend(pid) from pg_stat_activity where datname = ?", name);
            admin.execute("drop database if exists " + name);
        }
    }

    /** A new installation: the seed wrote a row, nobody chose a decision, and the path no policy names asks for a sign-in. */
    @Test
    void aNewInstallationHoldsNoDecisionAndClosesThePathsNoPolicyNames() throws Exception {
        String database = newDatabase();
        int port = start(database);
        JdbcTemplate jdbc = new JdbcTemplate(dataSource(database));

        assertThat(storedDecision(jdbc)).as("no decision is stored").isNull();
        assertThat(column(jdbc)).as("the column takes NULL and has no default").isEqualTo("YES none");
        assertThat(manager().getNoMatchingUrlPolicyDecision().name()).isEqualTo("AUTHENTICATED");
        String answers = answers(port);
        System.out.println("NEW INSTALLATION (no decision stored): " + answers);
        assertThat(answers).isEqualTo("api=401 browser=302 /mfa/login own sign-in=200");
    }

    /** The property applies to an installation whose seed row exists: before, the row's own value always overrode it. */
    @Test
    void theConfiguredDecisionAppliesWhenNobodyChoseOne() throws Exception {
        String database = newDatabase();
        int port = start(database, "contexa.policy.no-matching-url-policy-decision=PERMIT");
        JdbcTemplate jdbc = new JdbcTemplate(dataSource(database));

        assertThat(storedDecision(jdbc)).isNull();
        assertThat(manager().getNoMatchingUrlPolicyDecision().name()).isEqualTo("PERMIT");
        String answers = answers(port);
        System.out.println("NEW INSTALLATION, contexa.policy.no-matching-url-policy-decision=PERMIT: " + answers);
        assertThat(answers).isEqualTo("api=200 browser=200 own sign-in=200");
    }

    /**
     * Installations of older versions start with this one: the row they hold is kept (nobody can tell a choice from the
     * default of the column), the configuration does not replace it, and the column no longer decides for a new row.
     */
    @Test
    void anInstallationOfAnOlderVersionKeepsWhatItsRowHolds() throws Exception {
        String database = newDatabase();
        start(database);
        closeApplication();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource(database));

        becomeOlder(jdbc, "PERMIT");
        assertThat(column(jdbc)).as("as the older version made it").isEqualTo("NO default");
        int permitPort = start(database, "contexa.policy.no-matching-url-policy-decision=DENY");
        assertThat(storedDecision(jdbc)).as("the stored PERMIT is not changed by the start").isEqualTo("PERMIT");
        assertThat(column(jdbc)).as("the column was changed in place").isEqualTo("YES none");
        assertThat(manager().getNoMatchingUrlPolicyDecision().name()).as("the row beats the property").isEqualTo("PERMIT");
        String permit = answers(permitPort);
        System.out.println("UPGRADE, row PERMIT (property DENY): " + permit);
        assertThat(permit).isEqualTo("api=200 browser=200 own sign-in=200");
        closeApplication();

        becomeOlder(jdbc, "AUTHENTICATED");
        int authenticatedPort = start(database);
        assertThat(storedDecision(jdbc)).isEqualTo("AUTHENTICATED");
        assertThat(column(jdbc)).isEqualTo("YES none");
        String authenticated = answers(authenticatedPort);
        System.out.println("UPGRADE, row AUTHENTICATED: " + authenticated);
        assertThat(authenticated).isEqualTo("api=401 browser=302 /mfa/login own sign-in=200");
    }

    /** The column and the row as the version before this one left them. */
    private static void becomeOlder(JdbcTemplate jdbc, String decision) {
        jdbc.execute("alter table ctxa_system_settings alter column " + DECISION_COLUMN + " set default '" + decision + "'");
        jdbc.update("update ctxa_system_settings set " + DECISION_COLUMN + " = ?", decision);
        jdbc.execute("alter table ctxa_system_settings alter column " + DECISION_COLUMN + " set not null");
    }

    private static String storedDecision(JdbcTemplate jdbc) {
        return jdbc.queryForObject("select " + DECISION_COLUMN + " from ctxa_system_settings", String.class);
    }

    /** Whether the column takes NULL and whether it has a default, as the catalog says. */
    private static String column(JdbcTemplate jdbc) {
        return jdbc.queryForObject("select is_nullable || ' ' || case when column_default is null then 'none' else 'default' end "
                + "from information_schema.columns where table_schema = current_schema() "
                + "and table_name = 'ctxa_system_settings' and column_name = '" + DECISION_COLUMN + "'", String.class);
    }

    private CustomDynamicAuthorizationManager manager() {
        return context.getBean(CustomDynamicAuthorizationManager.class);
    }

    /** What an anonymous visitor gets for the path no policy names (as an API client and as a browser) and for Contexa's sign-in. */
    private static String answers(int port) throws Exception {
        HttpResponse<String> api = anonymous(port, UNNAMED_PATH, "application/json");
        HttpResponse<String> browser = anonymous(port, UNNAMED_PATH, "text/html");
        HttpResponse<String> signIn = anonymous(port, "/mfa/login", "text/html");
        assertThat(api.statusCode() == 200 ? api.body() : "").isIn("host data", "");
        String browserAnswer = browser.statusCode() + (browser.statusCode() == 302
                ? " " + browser.headers().firstValue("Location").map(location -> location.replaceFirst("^https?://[^/]+", "")).orElse("")
                : "");
        return "api=" + api.statusCode() + " browser=" + browserAnswer + " own sign-in=" + signIn.statusCode();
    }

    private static HttpResponse<String> anonymous(int port, String path, String accept) throws Exception {
        return HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build().send(
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).header("Accept", accept).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private String newDatabase() {
        String database = "contexa_d23_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        new JdbcTemplate(dataSource("postgres")).execute("create database " + database);
        databases.add(database);
        return database;
    }

    private int start(String database, String... properties) {
        List<String> all = new ArrayList<>(List.of("spring.main.banner-mode=off", "server.port=0",
                "contexa.datasource.url=" + urlOf(database),
                "contexa.datasource.username=" + user(),
                "contexa.datasource.password=" + password(),
                "contexa.auth.ott.fail-on-email-error=false",
                "contexa.llm.selection.chat.mode=spring-primary",
                "contexa.llm.selection.embedding.mode=spring-primary",
                "contexa.security.zerotrust.mode=DISABLED"));
        all.addAll(List.of(properties));
        context = new SpringApplicationBuilder(HostApplication.class)
                .web(WebApplicationType.SERVLET)
                .properties(all.toArray(String[]::new))
                .run();
        return ((ServletWebServerApplicationContext) context).getWebServer().getPort();
    }

    private void closeApplication() {
        if (context != null) {
            context.close();
            context = null;
        }
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

    /** An application without a security chain of its own whose sign-in Contexa owns. */
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class HostApplication {

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

        @GetMapping(UNNAMED_PATH)
        String data() {
            return "host data";
        }
    }
}

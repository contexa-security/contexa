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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsRuntimeApplier;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.Embedding;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingRequest;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contexa owns the sign-in (FULL) of an application without a security chain of its own, on a real servlet container
 * and a real PostgreSQL database. Such an application was closed by Spring Boot's default chain: a request needed a
 * signed-in user. A path no URL policy names still needs one where Contexa owns the sign-in, while a policy that names a
 * path decides it, a signed-in user reaches the application as before, and Contexa's own sign-in stays open to whoever
 * is not signed in yet. An operator who chooses PERMIT gets the former behaviour back.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@Timeout(300)
class FullModeUnnamedPathsPostgresTest {

    private static final int DIMENSIONS = 1024;
    private static final String USER = "fx6user";
    private static final String USER_PASSWORD = "fx6-user-password";
    private static final String ADMIN = "admin";
    private static final String ADMIN_PASSWORD = "fx6-admin-password";
    private static final Pattern CSRF = Pattern.compile("<meta name=\"_csrf\" content=\"([^\"]+)\"");
    private static final Pattern FORM_CSRF = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"");
    private static final ObjectMapper JSON = new ObjectMapper();

    /** Contexa's own requests that a person who is not signed in makes, or that answer such a person. */
    private static final List<String> CONTEXA_PATHS = List.of("/mfa/login", "/mfa/select-factor", "/js/contexa-mfa-sdk.js",
            "/api/mfa/config", "/contexa/admin/login", "/contexa/admin", "/contexa/css/main.css", "/contexa/css/missing.css",
            "/favicon.ico", "/contexa/password-change", "/.well-known/authzen-configuration", "/contexa/zero-trust/blocked");

    private String database;
    private ConfigurableApplicationContext context;
    private JdbcTemplate jdbc;
    private int port;

    @BeforeAll
    void start() throws Exception {
        database = "contexa_fx6_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        new JdbcTemplate(dataSource("postgres")).execute("create database " + database);
        jdbc = new JdbcTemplate(dataSource(database));
        context = new SpringApplicationBuilder(HostApplication.class)
                .web(WebApplicationType.SERVLET)
                .properties("spring.main.banner-mode=off", "server.port=0",
                        "contexa.datasource.url=" + urlOf(database),
                        "contexa.datasource.username=" + user(),
                        "contexa.datasource.password=" + password(),
                        "contexa.iam.seed.admin.password=" + ADMIN_PASSWORD,
                        "contexa.auth.ott.fail-on-email-error=false",
                        "contexa.llm.selection.chat.mode=spring-primary",
                        "contexa.llm.selection.embedding.mode=spring-primary",
                        "contexa.security.zerotrust.mode=DISABLED")
                .run();
        port = ((ServletWebServerApplicationContext) context).getWebServer().getPort();
        aUserOfTheApplication();
        policiesThatNameHostPaths();
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
    void aNewInstallationStartsWithSignInRequiredForPathsNoPolicyNames() {
        assertThat(jdbc.queryForObject("select no_matching_url_policy_decision from ctxa_system_settings", String.class))
                .isEqualTo("AUTHENTICATED");
        assertThat(jdbc.queryForObject("select missing_method_policy_decision from ctxa_system_settings", String.class))
                .as("the decision for methods without a policy is not touched").isEqualTo("PERMIT");
        assertThat(manager().getNoMatchingUrlPolicyDecision().name()).isEqualTo("AUTHENTICATED");
    }

    @Test
    void aRequestWithoutSignInToAPathNoPolicyNamesIsAskedToSignIn() throws Exception {
        for (String path : List.of("/h/secured/data", "/h/not-there")) {
            HttpResponse<String> page = anonymous(path, "text/html");
            assertThat(page.statusCode()).as("%s from a browser", path).isEqualTo(302);
            assertThat(page.headers().firstValue("Location")).as(path).hasValueSatisfying(
                    location -> assertThat(location).endsWith("/mfa/login"));
            HttpResponse<String> call = anonymous(path, "application/json");
            assertThat(call.statusCode()).as("%s from an API client", path).isEqualTo(401);
            assertThat(call.body()).doesNotContain("host data");
        }
        assertThat(anonymous("/error", "application/json").statusCode())
                .as("the error page is no page of its own for someone not signed in").isEqualTo(401);
    }

    @Test
    void aSignedInUserReachesThePathsNoPolicyNamesAsBefore() throws Exception {
        Browser browser = signIn(USER, USER_PASSWORD);

        HttpResponse<String> data = browser.get("/h/secured/data", "application/json");
        assertThat(data.statusCode()).isEqualTo(200);
        assertThat(data.body()).isEqualTo("host data");
        assertThat(browser.get("/h/not-there", "application/json").statusCode()).isEqualTo(404);
    }

    @Test
    void aPolicyThatNamesAPathDecidesItForEveryone() throws Exception {
        HttpResponse<String> open = anonymous("/h/public/info", "application/json");
        assertThat(open.statusCode()).as("named permitAll, no sign-in").isEqualTo(200);
        assertThat(open.body()).isEqualTo("public info");
        assertThat(anonymous("/h/staff/report", "application/json").statusCode())
                .as("named for administrators, no sign-in").isEqualTo(401);

        Browser browser = signIn(USER, USER_PASSWORD);
        assertThat(browser.get("/h/public/info", "application/json").statusCode()).isEqualTo(200);
        assertThat(browser.get("/h/staff/report", "application/json").statusCode())
                .as("named for administrators, a signed-in user without the role").isEqualTo(403);
    }

    /**
     * The same requests with the decision of an operator who keeps the former behaviour (PERMIT) and with the new
     * default: Contexa's own requests and the paths a policy names answer the same, and only the paths no policy names
     * ask for a sign-in.
     */
    @Test
    void onlyThePathsNoPolicyNamesChangeAgainstTheFormerDefault() throws Exception {
        List<String> hostPaths = List.of("/h/secured/data", "/h/not-there", "/h/public/info", "/h/staff/report", "/error");
        Map<String, String> asBefore;
        decide("PERMIT");
        try {
            asBefore = answers(hostPaths);
            assertThat(anonymous("/h/secured/data", "application/json").body())
                    .as("PERMIT keeps paths without a policy open, as before").isEqualTo("host data");
        } finally {
            decide("AUTHENTICATED");
        }
        Map<String, String> now = answers(hostPaths);

        Map<String, String> changed = new LinkedHashMap<>();
        now.forEach((request, answer) -> {
            if (!answer.equals(asBefore.get(request))) {
                changed.put(request, asBefore.get(request) + " -> " + answer);
            }
        });
        assertThat(changed.keySet()).containsExactlyInAnyOrder(
                "/h/secured/data html", "/h/secured/data json", "/h/not-there html", "/h/not-there json",
                "/error html", "/error json");
        assertThat(changed.values()).allSatisfy(change -> assertThat(change).matches(".* -> (302 .*/mfa/login|401 )"));
    }

    @Test
    void contexasOwnSignInStaysOpenToWhoeverIsNotSignedIn() throws Exception {
        assertThat(anonymous("/mfa/login", "text/html").statusCode()).isEqualTo(200);
        assertThat(anonymous("/js/contexa-mfa-sdk.js", "*/*").statusCode()).isEqualTo(200);
        assertThat(anonymous("/api/mfa/config", "application/json").statusCode()).isEqualTo(200);
        assertThat(anonymous("/contexa/css/main.css", "text/css").statusCode()).isEqualTo(200);
        HttpResponse<String> console = anonymous("/contexa/admin/login", "text/html");
        assertThat(console.statusCode()).isEqualTo(302);
        assertThat(console.headers().firstValue("Location")).hasValueSatisfying(
                location -> assertThat(location).endsWith("/mfa/login"));
        assertThat(anonymous("/contexa/css/missing.css", "application/json").statusCode())
                .as("the error page answers a missing file of Contexa's").isEqualTo(404);
        assertThat(signIn(USER, USER_PASSWORD)).as("the whole sign-in, password and one-time code").isNotNull();
    }

    /**
     * The operator's way: the system settings screen offers the three decisions for URLs and the two for methods, a save of
     * PERMIT opens the paths no policy names at once, a save of AUTHENTICATED closes them again, and AUTHENTICATED for
     * methods is refused without storing anything.
     */
    @Test
    void theSystemSettingsScreenChoosesTheDecision() throws Exception {
        Browser administrator = signIn(ADMIN, ADMIN_PASSWORD);
        HttpResponse<String> screen = administrator.get("/contexa/admin/system-settings", "text/html");
        assertThat(screen.statusCode()).isEqualTo(200);
        String urlSelect = select(screen.body(), "noMatchingUrlPolicyDecision");
        assertThat(urlSelect).contains("value=\"PERMIT\"", "value=\"DENY\"", "value=\"AUTHENTICATED\"")
                .containsPattern("value=\"AUTHENTICATED\"\\s+selected");
        assertThat(urlSelect).doesNotContain("??");
        String methodSelect = select(screen.body(), "missingMethodPolicyDecision");
        assertThat(methodSelect).contains("value=\"PERMIT\"", "value=\"DENY\"").doesNotContain("AUTHENTICATED");

        try {
            assertThat(save(administrator, "PERMIT", "PERMIT").statusCode()).isEqualTo(302);
            assertThat(jdbc.queryForObject("select no_matching_url_policy_decision from ctxa_system_settings", String.class))
                    .isEqualTo("PERMIT");
            assertThat(anonymous("/h/secured/data", "application/json").body()).isEqualTo("host data");

            save(administrator, "DENY", "AUTHENTICATED");
            assertThat(jdbc.queryForObject("select no_matching_url_policy_decision from ctxa_system_settings", String.class))
                    .as("a form with AUTHENTICATED for methods stores nothing").isEqualTo("PERMIT");
            assertThat(jdbc.queryForObject("select missing_method_policy_decision from ctxa_system_settings", String.class))
                    .isEqualTo("PERMIT");
        } finally {
            save(administrator, "AUTHENTICATED", "PERMIT");
        }
        assertThat(jdbc.queryForObject("select no_matching_url_policy_decision from ctxa_system_settings", String.class))
                .isEqualTo("AUTHENTICATED");
        assertThat(anonymous("/h/secured/data", "application/json").statusCode()).isEqualTo(401);
    }

    private HttpResponse<String> save(Browser administrator, String urls, String methods) throws Exception {
        HttpResponse<String> screen = administrator.get("/contexa/admin/system-settings", "text/html");
        Matcher token = FORM_CSRF.matcher(screen.body());
        assertThat(token.find()).as("the form's CSRF token").isTrue();
        return administrator.submit("/contexa/admin/system-settings", form("_csrf", token.group(1),
                "securityZeroTrustMode", "DISABLED", "auditLogRetentionDays", "90", "defaultRole", "ROLE_USER",
                "policyCombiningAlgorithm", "FIRST_APPLICABLE", "noMatchingUrlPolicyDecision", urls,
                "missingMethodPolicyDecision", methods, "mvcResourceScannerBasePackages", "io.contexa.contexaiam."));
    }

    private static String select(String page, String id) {
        int start = page.indexOf("<select id=\"" + id + "\"");
        assertThat(start).as("the %s select", id).isNotNegative();
        return page.substring(start, page.indexOf("</select>", start));
    }

    private Map<String, String> answers(List<String> hostPaths) throws Exception {
        Map<String, String> answers = new LinkedHashMap<>();
        List<String> paths = new ArrayList<>(CONTEXA_PATHS);
        paths.addAll(hostPaths);
        for (String path : paths) {
            for (String accept : List.of("text/html", "application/json")) {
                HttpResponse<String> response = anonymous(path, accept);
                answers.put(path + (accept.equals("text/html") ? " html" : " json"),
                        response.statusCode() + " " + response.headers().firstValue("Location").orElse(""));
            }
        }
        return answers;
    }

    /** What the system settings screen does when an operator saves the decision: the row, then the running instance. */
    private void decide(String decision) {
        jdbc.update("update ctxa_system_settings set no_matching_url_policy_decision = ?", decision);
        context.getBean(SystemSettingsRuntimeApplier.class).apply();
        manager().reload();
        assertThat(manager().getNoMatchingUrlPolicyDecision().name()).isEqualTo(decision);
    }

    private CustomDynamicAuthorizationManager manager() {
        return context.getBean(CustomDynamicAuthorizationManager.class);
    }

    private void aUserOfTheApplication() {
        jdbc.update("insert into ctxa_users (username, email, password, name, enabled, account_locked, credentials_expired, "
                        + "failed_login_attempts, mfa_enabled, bridge_managed, external_auth_only, created_at, password_changed_at) "
                        + "values (?, ?, ?, ?, true, false, false, 0, true, false, false, current_timestamp, current_timestamp)",
                USER, USER + "@localhost", PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(USER_PASSWORD),
                "FX6 User");
        Long id = jdbc.queryForObject("select id from ctxa_users where username = ?", Long.class, USER);
        jdbc.update("insert into ctxa_user_groups (user_id, group_id, assigned_at) values (?, 4, current_timestamp)", id);
    }

    private void policiesThatNameHostPaths() {
        policy("FX6_PUBLIC_INFO", "/h/public/**", "permitAll");
        policy("FX6_STAFF_REPORT", "/h/staff/**", "hasAuthority('ROLE_ADMIN')");
        manager().reload();
    }

    private void policy(String name, String target, String condition) {
        jdbc.update("insert into ctxa_policy (name, description, effect, priority, is_active, source, approval_status, created_at) "
                + "values (?, ?, 'ALLOW', 50, true, 'MANUAL', 'NOT_REQUIRED', current_timestamp)", name, name);
        Long policy = jdbc.queryForObject("select id from ctxa_policy where name = ?", Long.class, name);
        jdbc.update("insert into ctxa_policy_target (policy_id, target_type, target_identifier, http_method, target_order, source_type) "
                + "values (?, 'URL', ?, 'ANY', 1, 'MANUAL')", policy, target);
        jdbc.update("insert into ctxa_policy_rule (policy_id, description) values (?, ?)", policy, name);
        Long rule = jdbc.queryForObject("select id from ctxa_policy_rule where policy_id = ?", Long.class, policy);
        jdbc.update("insert into ctxa_policy_condition (rule_id, condition_expression, authorization_phase) "
                + "values (?, ?, 'PRE_AUTHORIZE')", rule, condition);
    }

    /** Contexa's sign-in as its MFA script drives it: the password, then the one-time code. */
    private Browser signIn(String username, String password) throws Exception {
        Browser browser = new Browser();
        browser.page("/mfa/login");
        HttpResponse<String> first = browser.post("/mfa/login", form("username", username, "password", password,
                "_csrf", browser.csrf), "application/x-www-form-urlencoded");
        assertThat(first.statusCode()).as("password step: %s", first.body()).isEqualTo(200);
        JsonNode answer = JSON.readTree(first.body());
        if (answer.path("authenticated").asBoolean() || "MFA_COMPLETED".equals(answer.path("status").asText())) {
            return browser;
        }
        browser.page("/mfa/select-factor");
        HttpResponse<String> select = browser.post("/mfa/select-factor",
                "{\"factorType\":\"MFA_OTT\",\"username\":\"" + username + "\"}", "application/json");
        assertThat(select.statusCode()).as("factor step: %s", select.body()).isEqualTo(200);
        HttpResponse<String> sent = browser.post("/mfa/ott/generate-code", form("username", username),
                "application/x-www-form-urlencoded");
        assertThat(sent.statusCode()).as("code step: %s", sent.body()).isLessThan(400);
        String code = jdbc.queryForObject("select token_value from ctxa_one_time_tokens where username = ? "
                + "order by expires_at desc limit 1", String.class, username);
        browser.page("/mfa/challenge/ott");
        HttpResponse<String> verified = browser.post("/login/mfa-ott", form("username", username, "token", code,
                "_csrf", browser.csrf), "application/x-www-form-urlencoded");
        assertThat(verified.statusCode()).as("verification step: %s", verified.body()).isEqualTo(200);
        return browser;
    }

    private HttpResponse<String> anonymous(String path, String accept) throws Exception {
        return HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build().send(
                HttpRequest.newBuilder(URI.create(base() + path)).header("Accept", accept).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private String base() {
        return "http://127.0.0.1:" + port;
    }

    private static String form(String... pairs) {
        StringBuilder form = new StringBuilder();
        for (int index = 0; index < pairs.length; index += 2) {
            if (form.length() > 0) {
                form.append('&');
            }
            form.append(URLEncoder.encode(pairs[index], StandardCharsets.UTF_8)).append('=')
                    .append(URLEncoder.encode(pairs[index + 1], StandardCharsets.UTF_8));
        }
        return form.toString();
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

    /** One person's browser: its cookies, the page's CSRF token and the MFA session the answers name. */
    private final class Browser {

        private final HttpClient client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        private String csrf = "";
        private String mfaSession;
        private String step;

        HttpResponse<String> page(String path) throws Exception {
            HttpResponse<String> response = get(path, "text/html");
            Matcher token = CSRF.matcher(response.body());
            if (token.find()) {
                csrf = token.group(1);
            }
            return response;
        }

        HttpResponse<String> get(String path, String accept) throws Exception {
            return client.send(HttpRequest.newBuilder(URI.create(base() + path)).header("Accept", accept)
                    .header("Accept-Language", "en").GET().build(), HttpResponse.BodyHandlers.ofString());
        }

        /** A form as a browser posts it. */
        HttpResponse<String> submit(String path, String body) throws Exception {
            return client.send(HttpRequest.newBuilder(URI.create(base() + path))
                    .header("Accept", "text/html")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        }

        HttpResponse<String> post(String path, String body, String contentType) throws Exception {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base() + path))
                    .header("Accept", "application/json")
                    .header("Content-Type", contentType)
                    .header("X-Device-Id", "fx6-device")
                    .header("X-CSRF-TOKEN", csrf)
                    .POST(HttpRequest.BodyPublishers.ofString(body));
            if (step != null) {
                request.header("X-MFA-Step-Id", step);
            }
            if (mfaSession != null) {
                request.header("X-MFA-Session-Id", mfaSession);
            }
            HttpResponse<String> response = client.send(request.build(), HttpResponse.BodyHandlers.ofString());
            try {
                JsonNode answer = JSON.readTree(response.body());
                if (answer.hasNonNull("mfaSessionId")) {
                    mfaSession = answer.get("mfaSessionId").asText();
                }
                if (answer.hasNonNull("nextStepId")) {
                    step = answer.get("nextStepId").asText();
                }
            } catch (Exception notJson) {
                // a page, not an answer of the sign-in
            }
            return response;
        }
    }

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
            return new SilentChatModel();
        }

        @Bean
        EmbeddingModel flatEmbeddingModel() {
            return new FlatEmbeddingModel();
        }
    }

    @RestController
    static class HostController {

        @GetMapping("/h/secured/data")
        String data() {
            return "host data";
        }

        @GetMapping("/h/public/info")
        String publicInfo() {
            return "public info";
        }

        @GetMapping("/h/staff/report")
        String staffReport() {
            return "staff report";
        }
    }

    /** Zero trust is off here, so no model is asked anything: a model only has to exist for Contexa to start. */
    static final class SilentChatModel implements ChatModel {

        @Override
        public ChatResponse call(Prompt prompt) {
            return new ChatResponse(List.of(new Generation(new AssistantMessage("{}"))));
        }
    }

    static final class FlatEmbeddingModel implements EmbeddingModel {

        @Override
        public EmbeddingResponse call(EmbeddingRequest request) {
            List<Embedding> embeddings = new ArrayList<>();
            for (int index = 0; index < request.getInstructions().size(); index++) {
                embeddings.add(new Embedding(new float[DIMENSIONS], index));
            }
            return new EmbeddingResponse(embeddings);
        }

        @Override
        public float[] embed(Document document) {
            return new float[DIMENSIONS];
        }

        @Override
        public int dimensions() {
            return DIMENSIONS;
        }
    }
}

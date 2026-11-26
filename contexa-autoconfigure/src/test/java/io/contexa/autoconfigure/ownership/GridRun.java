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
package io.contexa.autoconfigure.ownership;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.operating.ContexaOperatingProfileException;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaSignInRealm;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.lang.Nullable;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One application of the operating-mode grid (docs/agent/운영모드-정상화-구현계획.md, M0): a real application on a real port
 * over a throwaway PostgreSQL database of Contexa's and an in-memory database of the host's own, or the reason its start was
 * refused. A refused start is a result, not an error of the test: it is what the grid reports for that combination.
 * <p>
 * The decisions are off ({@code contexa.security.zerotrust.mode=DISABLED}) so that no answer depends on a model; what the
 * decisions themselves do in each combination is left to the real-server grid.
 */
final class GridRun implements AutoCloseable {

    static final String ADMIN = "admin";
    static final String ADMIN_PASSWORD = "grid-admin-pw-1";
    static final String HOST_USER = "hostuser";
    static final String HOST_PASSWORD = "grid-host-pw-1";
    static final String STARTED = "started";

    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"[^>]*? (?:content|value)=\"([^\"]+)\"");
    private static final Pattern STATUS = Pattern.compile("\"status\"\\s*:\\s*\"([^\"]+)\"");
    private static final String FORM = "application/x-www-form-urlencoded";
    private static final String JSON = "application/json";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String database;
    private final ApplicationNamespace.Scope namespace;
    @Nullable
    private final ConfigurableApplicationContext context;
    @Nullable
    private final Throwable refusal;

    private GridRun(String database, ApplicationNamespace.Scope namespace, @Nullable ConfigurableApplicationContext context,
                    @Nullable Throwable refusal) {
        this.database = database;
        this.namespace = namespace;
        this.context = context;
        this.refusal = refusal;
    }

    /**
     * Starts the application of the combination's mode with the combination's settings. The application's name, which it
     * binds for the whole JVM at its start, is bound here first, so that {@link #close} gives back what was bound before.
     */
    static GridRun start(Class<?> sandboxApplication, Class<?> fullApplication, OperatingCombination combination,
                         String... extraSettings) throws Exception {
        String database = "grid_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        admin("create database " + database);
        ApplicationNamespace.Scope namespace = ApplicationNamespace.using("grid-" + database);
        List<String> settings = new ArrayList<>(List.of(
                "spring.main.banner-mode=off",
                "server.port=0",
                "spring.application.name=grid-" + database,
                "spring.datasource.url=jdbc:h2:mem:host_" + database + ";DB_CLOSE_DELAY=-1",
                // Flyway is on this module's test class path (contexa-iam's test fixtures), not on an application's: without
                // these Spring Boot would leave the host's in-memory schema to a Flyway that has no migrations for it
                "spring.flyway.enabled=false",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "contexa.infrastructure.mode=standalone",
                "contexa.datasource.url=" + databaseUrl(database),
                "contexa.datasource.username=" + System.getenv("CONTEXA_TEST_DB_USERNAME"),
                "contexa.datasource.password=" + System.getenv("CONTEXA_TEST_DB_PASSWORD"),
                "contexa.vectorstore.pgvector.dimensions=" + GridModels.DIMENSIONS,
                "contexa.vectorstore.pgvector.initialize-schema=true",
                "contexa.iam.seed.admin.username=" + ADMIN,
                "contexa.iam.seed.admin.password=" + ADMIN_PASSWORD,
                "contexa.iam.seed.admin.email=admin@grid.test",
                "contexa.auth.ott.fail-on-email-error=false",
                "contexa.llm.selection.chat.mode=spring-primary",
                "contexa.llm.selection.embedding.mode=spring-primary",
                "contexa.security.zerotrust.mode=DISABLED",
                "contexa.startup.class-path-report=false"));
        settings.addAll(combination.properties());
        settings.addAll(List.of(extraSettings));
        Class<?> application = combination.mode() == SecurityMode.FULL ? fullApplication : sandboxApplication;
        try {
            ConfigurableApplicationContext context = new SpringApplicationBuilder(application)
                    .web(WebApplicationType.SERVLET)
                    .properties(settings.toArray(String[]::new))
                    .run();
            return new GridRun(database, namespace, context, null);
        } catch (RuntimeException | LinkageError refused) {
            return new GridRun(database, namespace, null, refused);
        }
    }

    boolean started() {
        return context != null;
    }

    ConfigurableApplicationContext context() {
        if (context == null) {
            throw new IllegalStateException("the application did not start: " + startOutcome());
        }
        return context;
    }

    /** {@value #STARTED}, or why the start was refused: the operating profile's reason when it gave one, else the root cause. */
    String startOutcome() {
        if (refusal == null) {
            return STARTED;
        }
        Throwable reason = refusal;
        for (Throwable cause = refusal; cause != null; cause = cause.getCause()) {
            if (cause instanceof ContexaOperatingProfileException) {
                reason = cause;
                break;
            }
            reason = cause;
        }
        String message = String.valueOf(reason.getMessage()).lines().findFirst().orElse("");
        return "refused: " + reason.getClass().getSimpleName() + ": " + (message.length() > 300 ? message.substring(0, 300) : message);
    }

    /** Contexa's database of this run. */
    JdbcTemplate contexaDatabase() {
        return new JdbcTemplate(new DriverManagerDataSource(databaseUrl(database),
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD")));
    }

    Browser browser() {
        return new Browser("http://127.0.0.1:" + ((ServletWebServerApplicationContext) context()).getWebServer().getPort());
    }

    /**
     * Contexa's own sign-in of its administrator, as Contexa's MFA script drives it: the password, then the code it mails,
     * read from the token table as the administrator reads it from the mail. Every address is the one Contexa says it serves
     * ({@link AuthUrlProvider}), so the probe follows Contexa's sign-in wherever a change puts it: the flow of Contexa's
     * administrators where they sign in apart from the application's users (R-13), Contexa's sign-in otherwise.
     */
    String contexaSignIn(Browser browser) throws Exception {
        MfaFlowUrlRegistry flows = context().getBean(MfaFlowUrlRegistry.class);
        AuthUrlProvider admin = flows.getProvider(ContexaSignInRealm.adminFlowTypeName());
        AuthUrlProvider urls = admin != null ? admin : context().getBean("contexaAuthUrlProvider", AuthUrlProvider.class);
        browser.page(urls.getPrimaryLoginPage());
        HttpResponse<String> password = browser.post(urls.getPrimaryFormLoginProcessing(),
                form("username", ADMIN, "password", ADMIN_PASSWORD, "_csrf", browser.csrf), FORM);
        if (password.statusCode() != 200) {
            return "password step " + password.statusCode() + location(password);
        }
        JsonNode answer = json(password.body());
        if (answer.path("authenticated").asBoolean() || "MFA_COMPLETED".equals(answer.path("status").asText())) {
            return "200 MFA_COMPLETED";
        }
        browser.page(urls.getMfaSelectFactor());
        HttpResponse<String> select = browser.post(urls.getMfaSelectFactor(),
                "{\"factorType\":\"MFA_OTT\",\"username\":\"" + ADMIN + "\"}", JSON);
        if (select.statusCode() != 200) {
            return "factor step " + select.statusCode() + location(select);
        }
        HttpResponse<String> sent = browser.post(urls.getMfaOttCodeGeneration(), form("username", ADMIN), FORM);
        if (sent.statusCode() >= 400) {
            return "code step " + sent.statusCode() + location(sent);
        }
        List<String> codes = contexaDatabase().queryForList(
                "select token_value from ctxa_one_time_tokens where username = ? order by expires_at desc limit 1", String.class, ADMIN);
        if (codes.isEmpty()) {
            return "no code was issued";
        }
        browser.page(urls.getMfaOttChallengeUi());
        HttpResponse<String> verified = browser.post(urls.getMfaOttLoginProcessing(),
                form("username", ADMIN, "token", codes.get(0), "_csrf", browser.csrf), FORM);
        return verified.statusCode() + " " + jsonStatus(verified.body());
    }

    /** The host's own form sign-in (Spring Security's default login page): the status and where it sends the browser. */
    String hostSignIn(Browser browser, String username, String password) throws Exception {
        return hostSignIn(browser, username, password, "/login");
    }

    /** The host's own form sign-in at its own sign-in page. */
    String hostSignIn(Browser browser, String username, String password, String loginPath) throws Exception {
        browser.page(loginPath);
        HttpResponse<String> login = browser.post(loginPath, form("username", username, "password", password, "_csrf", browser.csrf), FORM);
        return login.statusCode() + location(login);
    }

    /**
     * The chain of a host that keeps its sign-in. With mode FULL it is narrowed to the host's own paths and signs in at
     * {@link GridController#HOST_LOGIN}: Spring Security runs no chain after one that takes every request, and Contexa's main
     * chain takes every request the chains before it leave (R-14, F-2 of docs/agent/운영모드-정상화-구현계획.md).
     */
    static SecurityFilterChain hostChain(HttpSecurity http, boolean narrowed) throws Exception {
        if (narrowed) {
            http.securityMatcher("/h/**")
                    .formLogin(form -> form.loginPage(GridController.HOST_LOGIN).permitAll());
        } else {
            http.formLogin(Customizer.withDefaults());
        }
        return http.authorizeHttpRequests(requests -> requests
                        .requestMatchers("/h/open/**").permitAll()
                        .anyRequest().authenticated())
                .build();
    }

    /** Where the host of the combination's mode signs in. */
    static String hostLoginPath(OperatingCombination combination) {
        return combination.mode() == SecurityMode.FULL ? GridController.HOST_LOGIN : "/login";
    }

    /**
     * A URL policy of Contexa's, as the console stores it, then the policies reloaded as a save in the console reloads
     * them.
     */
    void urlPolicy(String name, String target, String condition) {
        JdbcTemplate jdbc = contexaDatabase();
        jdbc.update("insert into ctxa_policy (name, description, effect, priority, is_active, source, approval_status, created_at) "
                + "values (?, ?, 'ALLOW', 50, true, 'MANUAL', 'NOT_REQUIRED', current_timestamp)", name, name);
        Long policy = jdbc.queryForObject("select id from ctxa_policy where name = ?", Long.class, name);
        jdbc.update("insert into ctxa_policy_target (policy_id, target_type, target_identifier, http_method, target_order, source_type) "
                + "values (?, 'URL', ?, 'ANY', 1, 'MANUAL')", policy, target);
        jdbc.update("insert into ctxa_policy_rule (policy_id, description) values (?, ?)", policy, name);
        Long rule = jdbc.queryForObject("select id from ctxa_policy_rule where policy_id = ?", Long.class, policy);
        jdbc.update("insert into ctxa_policy_condition (rule_id, condition_expression, authorization_phase) "
                + "values (?, ?, 'PRE_AUTHORIZE')", rule, condition);
        context().getBean(CustomDynamicAuthorizationManager.class).reload();
    }

    /**
     * Whether Contexa's tracked sessions hold a session of this user: asked for a few seconds, as the row is written after
     * the response.
     */
    String tracked(String username) throws InterruptedException {
        JdbcTemplate jdbc = contexaDatabase();
        for (int attempt = 0; attempt < 20; attempt++) {
            Integer rows = jdbc.queryForObject("select count(*) from ctxa_active_sessions where username = ?", Integer.class, username);
            if (rows != null && rows > 0) {
                return "tracked";
            }
            Thread.sleep(250);
        }
        return "not tracked";
    }

    /** What a probe found, or how it failed: one probe that fails does not hide the others. */
    static String attempt(Callable<String> probe) {
        try {
            return probe.call();
        } catch (Throwable failed) {
            String message = String.valueOf(failed.getMessage()).lines().findFirst().orElse("");
            return "failed: " + failed.getClass().getSimpleName() + " " + (message.length() > 200 ? message.substring(0, 200) : message);
        }
    }

    static String form(String... pairs) {
        StringBuilder form = new StringBuilder();
        for (int index = 0; index < pairs.length; index += 2) {
            if (form.length() > 0) {
                form.append('&');
            }
            form.append(URLEncoder.encode(pairs[index], StandardCharsets.UTF_8)).append('=')
                    .append(URLEncoder.encode(pairs[index + 1] == null ? "" : pairs[index + 1], StandardCharsets.UTF_8));
        }
        return form.toString();
    }

    private static String location(HttpResponse<String> response) {
        return response.headers().firstValue("Location")
                .map(location -> " " + URI.create(location).getPath() + (location.contains("error") ? "?error" : ""))
                .orElse("");
    }

    private static String jsonStatus(String body) {
        Matcher status = STATUS.matcher(body);
        return status.find() ? status.group(1) : "-";
    }

    private static JsonNode json(String body) {
        try {
            return MAPPER.readTree(body);
        } catch (Exception notJson) {
            return MAPPER.createObjectNode();
        }
    }

    /** Stops the application, gives back the name it bound and drops its database. */
    @Override
    public void close() throws Exception {
        try {
            if (context != null) {
                context.close();
            }
        } finally {
            namespace.close();
            admin("drop database if exists " + database + " with (force)");
        }
    }

    private static String databaseUrl(String name) {
        String url = System.getenv("CONTEXA_TEST_DB_URL");
        int query = url.indexOf('?');
        String base = query >= 0 ? url.substring(0, query) : url;
        return base.substring(0, base.lastIndexOf('/') + 1) + name;
    }

    private static void admin(String sql) throws Exception {
        try (Connection connection = DriverManager.getConnection(databaseUrl("postgres"),
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
             Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    /** One person's browser: its cookies, the page's CSRF token, and the MFA session and step Contexa's answers name. */
    static final class Browser {

        private final String base;
        private final HttpClient client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        private String csrf = "";
        private String mfaSession;
        private String step;

        private Browser(String base) {
            this.base = base;
        }

        /** A page as a browser opens it; the CSRF token it carries is kept for the next form. */
        HttpResponse<String> page(String path) throws Exception {
            HttpResponse<String> response = get(path, "text/html");
            Matcher token = CSRF.matcher(response.body());
            if (token.find()) {
                csrf = token.group(1);
            }
            return response;
        }

        HttpResponse<String> get(String path, String accept) throws Exception {
            return client.send(HttpRequest.newBuilder(URI.create(base + path)).header("Accept", accept)
                    .header("Accept-Language", "en").timeout(Duration.ofSeconds(60)).GET().build(), HttpResponse.BodyHandlers.ofString());
        }

        /** An anonymous request of an API client: the status and the body. */
        String anonymous(String path) throws Exception {
            HttpResponse<String> response = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
                    .send(HttpRequest.newBuilder(URI.create(base + path)).header("Accept", JSON).timeout(Duration.ofSeconds(60))
                            .GET().build(), HttpResponse.BodyHandlers.ofString());
            return response.statusCode() + " " + response.body();
        }

        HttpResponse<String> post(String path, String body, String contentType) throws Exception {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                    .header("Accept", JSON)
                    .header("Content-Type", contentType)
                    .header("X-Device-Id", "grid-device")
                    .header("X-CSRF-TOKEN", csrf)
                    .timeout(Duration.ofSeconds(60))
                    .POST(HttpRequest.BodyPublishers.ofString(body));
            if (step != null) {
                request.header("X-MFA-Step-Id", step);
            }
            if (mfaSession != null) {
                request.header("X-MFA-Session-Id", mfaSession);
            }
            HttpResponse<String> response = client.send(request.build(), HttpResponse.BodyHandlers.ofString());
            JsonNode answer = json(response.body());
            if (answer.hasNonNull("mfaSessionId")) {
                mfaSession = answer.get("mfaSessionId").asText();
            }
            if (answer.hasNonNull("nextStepId")) {
                step = answer.get("nextStepId").asText();
            }
            return response;
        }
    }
}

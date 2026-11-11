/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaPasswordSignIn;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.mockito.Mockito;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.Embedding;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingRequest;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.lang.reflect.Proxy;
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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockingDetails;

/**
 * Where Contexa owns the sign-in (FULL), a sign-in with a password is decided by Contexa's own provider over Contexa's own
 * store, whatever user stores and providers the application declares. Spring Security gives its global authentication
 * manager a password provider only when it can pick one alone; an application with several stores and providers of its
 * own left Contexa's form and MFA sign-in without any, and nobody, not even the administrator, could sign in.
 * <p>
 * Each case starts a real application on a real port over a throwaway PostgreSQL database and signs in over HTTP: the
 * same requests answer the same way with no store of the application's, and with two of everything.
 */
@Timeout(900)
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class ContexaOwnedSignInBesideApplicationStoresIntegrationTest {

    private static final String ADMIN = "admin";
    private static final String ADMIN_PASSWORD = "contexa-admin-pw-1";
    private static final String PROVIDER = ContexaPasswordSignIn.PROVIDER_BEAN;
    /** The first step passed: the answer of the password sign-in, which asks for the code next. */
    private static final String PAST_THE_PASSWORD = "200 MFA_REQUIRED Additional authentication is required.";
    /** One answer for every refusal, whatever refused it. */
    private static final String REFUSED = "401 - PRIMARY_AUTH_FAILED Invalid username or password.";
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"[^>]*? (?:content|value)=\"([^\"]+)\"");
    private static final Pattern STATUS = Pattern.compile("\"status\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern MFA_SESSION = Pattern.compile("\"mfaSessionId\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern ERROR = Pattern.compile("\"error\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern MESSAGE = Pattern.compile("\"message\"\\s*:\\s*\"([^\"]+)\"");

    private static final int DIMENSIONS = 128;
    private static final List<String> databases = new ArrayList<>();

    @BeforeAll
    static void driver() throws Exception {
        Class.forName("org.postgresql.Driver");
    }

    @AfterAll
    static void dropDatabases() throws Exception {
        for (String database : databases) {
            admin("drop database if exists " + database + " with (force)");
        }
    }

    /** What an application with no store of its own answers; every other case must answer the same. */
    @Test
    void anApplicationWithoutStoresOfItsOwnSignsTheAdministratorIn() throws Exception {
        try (Running app = Running.start(NoStoresOfItsOwn.class)) {
            Map<String, String> answers = app.passwordSignIns();

            assertThat(answers).containsEntry("wrong password", REFUSED)
                    .containsEntry("unknown name", REFUSED)
                    .containsEntry("right password", PAST_THE_PASSWORD)
                    .containsEntry("wrong password 5", REFUSED)
                    .containsEntry("locked in the database", "true")
                    .containsEntry("right password while locked", REFUSED)
                    .containsEntry("right password after the unlock", PAST_THE_PASSWORD);
            assertThat(app.completesTheCodeStep()).isEqualTo("200 MFA_COMPLETED");
            assertThat(app.console()).isEqualTo(200);
            assertThat(app.providerCalls()).as("one provider call per sign-in").isEqualTo(app.signIns);
        }
    }

    /** The application of the grid: two stores, two encoders, two providers of its own. */
    @Test
    void twoStoresAndTwoProvidersOfTheApplicationLeaveContexaSignInAsItIs() throws Exception {
        Map<String, String> expected;
        try (Running app = Running.start(NoStoresOfItsOwn.class)) {
            expected = app.passwordSignIns();
        }
        try (Running app = Running.start(TwoOfEverything.class)) {
            Map<String, String> answers = app.passwordSignIns();

            assertThat(answers).isEqualTo(expected);
            assertThat(answers).containsEntry("right password", PAST_THE_PASSWORD)
                    .containsEntry("right password while locked", REFUSED);
            assertThat(app.completesTheCodeStep()).isEqualTo("200 MFA_COMPLETED");
            assertThat(app.console()).isEqualTo(200);
            assertThat(app.providerCalls()).as("one provider call per sign-in").isEqualTo(app.signIns);
        }
    }

    /** The application's own users are not Contexa's: their names and passwords are refused like any unknown one. */
    @Test
    void theUsersOfTheApplicationsStoresDoNotSignInToContexa() throws Exception {
        try (Running app = Running.start(TwoOfEverything.class)) {
            String unknown = app.signIn("nobody-at-all", "whatever-pw-1");

            assertThat(app.signIn("alice", "alice-pw-1")).isEqualTo(unknown);
            assertThat(app.signIn("bob", "bob-pw-1")).isEqualTo(unknown);
            assertThat(app.signIn(ADMIN, "host-admin-pw-1")).as("the application's own 'admin'")
                    .isEqualTo(app.signIn(ADMIN, "not-the-password-1"));
            assertThat(unknown).doesNotStartWith("200");
            assertThat(unknown).isEqualTo(REFUSED);
            assertThat(app.signIn(ADMIN, ADMIN_PASSWORD)).as("Contexa's administrator").isEqualTo(PAST_THE_PASSWORD);
        }
    }

    /**
     * One store of the application's answers Contexa's sign-in, as Contexa says at start and in its documentation: the
     * store is the application's choice. A provider of the application's beside it left Spring's global manager without a
     * password provider, and nobody signed in; now the answers are the same with it and without it.
     */
    @Test
    void oneStoreOfTheApplicationAnswersTheSameWithAProviderOfTheApplicationsBesideIt() throws Exception {
        Map<String, String> alone;
        try (Running app = Running.start(OneStoreOfItsOwn.class)) {
            alone = app.storeSignIns();
            assertThat(app.providerCalls()).as("one provider call per sign-in").isEqualTo(app.signIns);
        }
        try (Running app = Running.start(OneStoreAndOneProvider.class)) {
            assertThat(app.storeSignIns()).isEqualTo(alone);
            assertThat(app.providerCalls()).as("one provider call per sign-in").isEqualTo(app.signIns);
        }
    }

    /**
     * Where the application keeps its sign-in (SANDBOX) there is no provider of Contexa's: Contexa's form filter keeps the
     * chain's manager, as before, and the application's own sign-in answers as it did.
     */
    @Test
    void whereTheApplicationKeepsItsSignInNothingOfThisApplies() throws Exception {
        try (Running app = Running.start(ApplicationKeepsItsSignIn.class)) {
            assertThat(app.context.containsBean(PROVIDER)).isFalse();
            assertThat(ContexaPasswordSignIn.manager(app.context)).isNull();
            assertThat(app.formSignIn("alice", "alice-pw-1")).isEqualTo("302 /");
            assertThat(app.formSignIn("alice", "not-the-password-1")).isEqualTo("302 /login?error");
            assertThat(app.formSignIn(ADMIN, ADMIN_PASSWORD)).as("Contexa's administrator is not the application's user")
                    .isEqualTo("302 /login?error");
        }
    }

    /** A single-step form sign-in of a flow the application declares goes through Contexa's provider as well. */
    @Test
    void aSingleFormSignInBesideTwoStoresSignsTheAdministratorIn() throws Exception {
        String expectedRight;
        String expectedWrong;
        try (Running app = Running.start(FormSignInWithoutStores.class)) {
            expectedRight = app.formSignIn(ADMIN, ADMIN_PASSWORD);
            expectedWrong = app.formSignIn(ADMIN, "not-the-password-1");
            assertThat(expectedRight).startsWith("302 /signed-in");
            assertThat(expectedWrong).isEqualTo("302 /login?error");
            assertThat(app.providerCalls()).isEqualTo(2);
        }
        try (Running app = Running.start(FormSignInWithTwoOfEverything.class)) {
            assertThat(app.formSignIn(ADMIN, ADMIN_PASSWORD)).isEqualTo(expectedRight).startsWith("302 /");
            assertThat(app.formSignIn(ADMIN, "not-the-password-1")).isEqualTo(expectedWrong);
            assertThat(app.formSignIn("alice", "alice-pw-1")).isEqualTo(expectedWrong);
            assertThat(app.providerCalls()).isEqualTo(3);
        }
    }

    // ----- a running application -----

    private static final class Running implements AutoCloseable {

        private final ConfigurableApplicationContext context;
        private final String database;
        private final String base;
        private HttpClient client;
        private String csrf;
        private String mfaSession;
        private int signIns;

        private Running(ConfigurableApplicationContext context, String database) {
            this.context = context;
            this.database = database;
            this.base = "http://127.0.0.1:" + ((ServletWebServerApplicationContext) context).getWebServer().getPort();
        }

        static Running start(Class<?> application) throws Exception {
            String database = "fx8_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
            admin("create database " + database);
            databases.add(database);
            ConfigurableApplicationContext context = new SpringApplicationBuilder(application)
                    .web(WebApplicationType.SERVLET)
                    .properties(settings(database))
                    .run();
            return new Running(context, database);
        }

        /** Wrong password, right password, an unknown name, then five wrong ones and the right one on a locked account. */
        Map<String, String> passwordSignIns() throws Exception {
            Map<String, String> answers = new LinkedHashMap<>();
            answers.put("wrong password", signIn(ADMIN, "not-the-password-1"));
            answers.put("unknown name", signIn("nobody-at-all", "whatever-pw-1"));
            answers.put("right password", signIn(ADMIN, ADMIN_PASSWORD));
            String keptSession = mfaSession;
            String keptCsrf = csrf;
            HttpClient keptClient = client;
            for (int attempt = 1; attempt <= 5; attempt++) {
                answers.put("wrong password " + attempt, signIn(ADMIN, "not-the-password-" + attempt));
            }
            answers.put("locked in the database", String.valueOf(locked(ADMIN)));
            answers.put("right password while locked", signIn(ADMIN, ADMIN_PASSWORD));
            unlock(ADMIN);
            answers.put("right password after the unlock", signIn(ADMIN, ADMIN_PASSWORD));
            client = keptClient;
            csrf = keptCsrf;
            mfaSession = keptSession;
            return answers;
        }

        /** Contexa's administrator, then the names of the application's store. */
        Map<String, String> storeSignIns() throws Exception {
            Map<String, String> answers = new LinkedHashMap<>();
            answers.put("Contexa's administrator", signIn(ADMIN, ADMIN_PASSWORD));
            answers.put("the application's admin", signIn(ADMIN, "host-admin-pw-1"));
            answers.put("the application's user", signIn("alice", "alice-pw-1"));
            answers.put("the application's user, wrong password", signIn("alice", "not-the-password-1"));
            answers.put("unknown name", signIn("nobody-at-all", "whatever-pw-1"));
            return answers;
        }

        /** A fresh browser: the login page, then the form with its CSRF token. Answers "status json-status". */
        String signIn(String username, String password) throws Exception {
            newBrowser();
            HttpResponse<String> page = send(HttpRequest.newBuilder(URI.create(base + "/mfa/login")).GET());
            Matcher token = CSRF.matcher(page.body());
            csrf = token.find() ? token.group(1) : null;
            HttpResponse<String> login = send(form("/mfa/login", Map.of("username", username, "password", password)));
            signIns++;
            Matcher session = MFA_SESSION.matcher(login.body());
            mfaSession = session.find() ? session.group(1) : null;
            return login.statusCode() + " " + jsonStatus(login.body()) + errorOf(login.body());
        }

        /** The one-time code of the mail: chosen, sent, read from the token table as the user reads it from the mail. */
        String completesTheCodeStep() throws Exception {
            send(json("/mfa/select-factor", "{\"factorType\":\"MFA_OTT\",\"username\":\"" + ADMIN + "\"}"));
            send(form("/mfa/ott/generate-code", Map.of("username", ADMIN)));
            String code = latestCode(ADMIN);
            assertThat(code).as("a code was issued").isNotNull();
            HttpResponse<String> verify = send(form("/login/mfa-ott", Map.of("username", ADMIN, "token", code)));
            return verify.statusCode() + " " + jsonStatus(verify.body());
        }

        /** An API of the console, which only an administrator who finished both steps may call. */
        int console() throws Exception {
            return send(HttpRequest.newBuilder(URI.create(base + "/contexa/admin/api/blacklist")).GET()).statusCode();
        }

        /** A single-step form sign-in: the status and where it sends the browser. */
        String formSignIn(String username, String password) throws Exception {
            newBrowser();
            HttpResponse<String> page = send(HttpRequest.newBuilder(URI.create(base + "/login")).GET());
            Matcher token = CSRF.matcher(page.body());
            csrf = token.find() ? token.group(1) : null;
            HttpResponse<String> login = send(form("/login", Map.of("username", username, "password", password)));
            String location = login.headers().firstValue("Location").map(URI::create).map(URI::getPath).orElse("");
            return login.statusCode() + " " + location + (login.headers().firstValue("Location").orElse("").contains("error") ? "?error" : "");
        }

        long providerCalls() {
            Object provider = context.getBean(PROVIDER);
            return mockingDetails(provider).getInvocations().stream()
                    .filter(invocation -> invocation.getMethod().getName().equals("authenticate"))
                    .count();
        }

        private void newBrowser() {
            CookieManager cookies = new CookieManager();
            cookies.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
            client = HttpClient.newBuilder().cookieHandler(cookies).followRedirects(HttpClient.Redirect.NEVER)
                    .connectTimeout(Duration.ofSeconds(10)).build();
            mfaSession = null;
        }

        private HttpRequest.Builder form(String path, Map<String, String> fields) {
            Map<String, String> all = new LinkedHashMap<>(fields);
            if (csrf != null) {
                all.put("_csrf", csrf);
            }
            String body = all.entrySet().stream()
                    .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                            + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                    .collect(Collectors.joining("&"));
            return HttpRequest.newBuilder(URI.create(base + path))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body));
        }

        private HttpRequest.Builder json(String path, String body) {
            return HttpRequest.newBuilder(URI.create(base + path))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body));
        }

        private HttpResponse<String> send(HttpRequest.Builder request) throws IOException, InterruptedException {
            request.header("Accept", "application/json").header("X-Device-Id", "fx8-device-1").timeout(Duration.ofSeconds(60));
            if (csrf != null) {
                request.header("X-CSRF-TOKEN", csrf);
            }
            if (mfaSession != null) {
                request.header("X-MFA-Session-Id", mfaSession);
            }
            return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
        }

        private boolean locked(String username) throws Exception {
            try (Connection connection = connect(database);
                 PreparedStatement statement = connection.prepareStatement(
                         "select account_locked from ctxa_users where username = ?")) {
                statement.setString(1, username);
                try (ResultSet rows = statement.executeQuery()) {
                    return rows.next() && rows.getBoolean(1);
                }
            }
        }

        private void unlock(String username) throws Exception {
            try (Connection connection = connect(database);
                 PreparedStatement statement = connection.prepareStatement("update ctxa_users set account_locked = false, "
                         + "failed_login_attempts = 0, lock_expires_at = null where username = ?")) {
                statement.setString(1, username);
                statement.executeUpdate();
            }
        }

        private String latestCode(String username) throws Exception {
            try (Connection connection = connect(database);
                 PreparedStatement statement = connection.prepareStatement(
                         "select token_value from ctxa_one_time_tokens where username = ? order by expires_at desc limit 1")) {
                statement.setString(1, username);
                try (ResultSet rows = statement.executeQuery()) {
                    return rows.next() ? rows.getString(1) : null;
                }
            }
        }

        @Override
        public void close() {
            context.close();
        }
    }

    private static float[] unit() {
        float[] vector = new float[DIMENSIONS];
        vector[0] = 1f;
        return vector;
    }

    /** The code and the words of a refusal; the rest of its body is the time and the path. */
    private static String errorOf(String body) {
        Matcher error = ERROR.matcher(body);
        Matcher message = MESSAGE.matcher(body);
        return (error.find() ? " " + error.group(1) : "") + (message.find() ? " " + message.group(1) : "");
    }

    private static String jsonStatus(String body) {
        Matcher status = STATUS.matcher(body);
        return status.find() ? status.group(1) : "-";
    }

    private static String[] settings(String database) {
        return new String[] {
                "spring.main.banner-mode=off",
                "server.port=0",
                "spring.application.name=fx8-" + database,
                "contexa.infrastructure.mode=standalone",
                "contexa.datasource.url=" + databaseUrl(database),
                "contexa.datasource.username=" + System.getenv("CONTEXA_TEST_DB_USERNAME"),
                "contexa.datasource.password=" + System.getenv("CONTEXA_TEST_DB_PASSWORD"),
                "contexa.datasource.isolation.contexa-owned-application=true",
                "contexa.vectorstore.pgvector.dimensions=" + DIMENSIONS,
                "contexa.vectorstore.pgvector.initialize-schema=true",
                "contexa.iam.seed.admin.username=" + ADMIN,
                "contexa.iam.seed.admin.password=" + ADMIN_PASSWORD,
                "contexa.iam.seed.admin.email=admin@contexa.test",
                "contexa.startup.class-path-report=false"
        };
    }

    private static String databaseUrl(String database) {
        String url = System.getenv("CONTEXA_TEST_DB_URL");
        int query = url.indexOf('?');
        String base = query >= 0 ? url.substring(0, query) : url;
        return base.substring(0, base.lastIndexOf('/') + 1) + database;
    }

    private static Connection connect(String database) throws Exception {
        return DriverManager.getConnection(databaseUrl(database),
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
    }

    private static void admin(String sql) throws Exception {
        try (Connection connection = connect("postgres"); Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    // ----- the applications -----

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class NoStoresOfItsOwn extends ModelsAndMail {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class TwoOfEverything extends ApplicationStores {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class OneStoreOfItsOwn extends OneApplicationStore {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    static class ApplicationKeepsItsSignIn extends OneApplicationStore {

        @Bean
        SecurityFilterChain applicationChain(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                    .formLogin(Customizer.withDefaults())
                    .build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class OneStoreAndOneProvider extends OneApplicationStore {

        @Bean
        AuthenticationProvider providerA() {
            DaoAuthenticationProvider provider = new DaoAuthenticationProvider(usersA());
            provider.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
            return provider;
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FormSignInWithoutStores extends ModelsAndMail {

        @Bean
        PlatformConfig platformConfig(ApplicationContext applicationContext) throws Exception {
            return formSignIn(applicationContext);
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FormSignInWithTwoOfEverything extends ApplicationStores {

        @Bean
        PlatformConfig platformConfig(ApplicationContext applicationContext) throws Exception {
            return formSignIn(applicationContext);
        }
    }

    private static PlatformConfig formSignIn(ApplicationContext applicationContext) throws Exception {
        return new IdentityDslRegistry<>(applicationContext)
                .global(http -> http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated()))
                .form(form -> form.defaultSuccessUrl("/signed-in"))
                .session(Customizer.withDefaults())
                .build();
    }

    /** A store of the application's, which names one of its users 'admin' as Contexa's administrator is named. */
    abstract static class OneApplicationStore extends ModelsAndMail {

        @Bean
        UserDetailsService usersA() {
            PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
            return new InMemoryUserDetailsManager(
                    User.withUsername("alice").password(encoder.encode("alice-pw-1")).roles("USER").build(),
                    User.withUsername(ADMIN).password(encoder.encode("host-admin-pw-1")).roles("ADMIN").build());
        }
    }

    /** Two of everything a sign-in is made of, as the grid's application has them. */
    abstract static class ApplicationStores extends OneApplicationStore {

        @Bean
        UserDetailsService usersB() {
            PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
            return new InMemoryUserDetailsManager(
                    User.withUsername("bob").password(encoder.encode("bob-pw-1")).roles("USER").build());
        }

        @Bean
        PasswordEncoder encoderA() {
            return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        }

        @Bean
        PasswordEncoder encoderB() {
            return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        }

        @Bean
        AuthenticationProvider providerA() {
            DaoAuthenticationProvider provider = new DaoAuthenticationProvider(usersA());
            provider.setPasswordEncoder(encoderA());
            return provider;
        }

        @Bean
        AuthenticationProvider providerB() {
            DaoAuthenticationProvider provider = new DaoAuthenticationProvider(usersB());
            provider.setPasswordEncoder(encoderB());
            return provider;
        }
    }

    /**
     * What every case has: a chat model and an embedding model that never leave the machine, a mail sender that keeps
     * the mail, a page to land on, and a spy on Contexa's provider that counts its calls and calls it as it is.
     */
    abstract static class ModelsAndMail {

        @Bean
        ChatModel localChatModel() {
            return new ChatModel() {
                @Override
                public ChatResponse call(Prompt prompt) {
                    return new ChatResponse(List.of(new Generation(new AssistantMessage(
                            "{\"riskScore\":0.05,\"confidence\":0.95,\"action\":\"ALLOW\",\"reasoning\":\"test\"}"))));
                }

                @Override
                public ChatOptions getDefaultOptions() {
                    return ChatOptions.builder().build();
                }
            };
        }

        @Bean
        EmbeddingModel localEmbeddingModel() {
            return new EmbeddingModel() {
                @Override
                public EmbeddingResponse call(EmbeddingRequest request) {
                    List<Embedding> embeddings = new ArrayList<>();
                    for (int index = 0; index < request.getInstructions().size(); index++) {
                        embeddings.add(new Embedding(unit(), index));
                    }
                    return new EmbeddingResponse(embeddings);
                }

                @Override
                public float[] embed(Document document) {
                    return unit();
                }

                @Override
                public int dimensions() {
                    return DIMENSIONS;
                }
            };
        }

        /** Makes its messages as Spring's sender does and sends none of them: the code is read from the token table. */
        @Bean
        JavaMailSender keptMail() {
            JavaMailSenderImpl maker = new JavaMailSenderImpl();
            return (JavaMailSender) Proxy.newProxyInstance(JavaMailSender.class.getClassLoader(),
                    new Class<?>[] {JavaMailSender.class},
                    (proxy, method, arguments) -> method.getName().startsWith("send") ? null : method.invoke(maker, arguments));
        }

        @Bean
        SignedIn signedIn() {
            return new SignedIn();
        }

        @Bean
        static BeanPostProcessor providerSpy() {
            return new BeanPostProcessor() {
                @Override
                public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
                    return PROVIDER.equals(beanName) ? Mockito.spy(bean) : bean;
                }
            };
        }
    }

    @RestController
    static class SignedIn {

        @GetMapping("/signed-in")
        String signedIn() {
            return "signed in";
        }
    }
}

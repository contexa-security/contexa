/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.springbootstartercontexa;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.cache.ContexaCacheService;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.pip.context.SubjectCache;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
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
import org.springframework.ai.vectorstore.SimpleVectorStore;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

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
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The application's request does not wait for Contexa's database to find the copy of its user, on a real application, a
 * real port and a real PostgreSQL (started with {@code shared_preload_libraries=pg_stat_statements}, so the statements
 * Contexa sends can be counted). Where Contexa owns the sign-in a user is one of Contexa's own accounts and needs no copy:
 * nothing is looked up for it. Where the application owns the sign-in the copy is synchronised once and then remembered.
 * Either way the subject the access decisions are given is the one they were given before.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@Timeout(600)
class UserCopyOffTheRequestPathPostgresIntegrationTest {

    private static final int REQUESTS = 40;
    private static final String ADMIN_PASSWORD = "Fx1-Admin-Pass-9";
    private static final String HOST_USER = "alice";
    private static final String HOST_PASSWORD = "alice-pass";
    private static final String SERVICE_CLIENT = "fx-service";
    private static final String SERVICE_SECRET = "fx-service-secret";
    private static final ObjectMapper JSON = new ObjectMapper();

    /** The statement that asks whether a name is one of Contexa's own accounts (UserRepository.findOwnAccountId). */
    private static final String OWN_ACCOUNT_LOOKUP = "select % from ctxa_users % where %.username=$1 and %.bridge_managed=$2";
    /** The statements that find and read a copy of the application's user. */
    private static final String COPY_LOOKUP = "select % from ctxa_users % where %.bridge_subject_key=$1";
    private static final String COPY_PROFILE_LOOKUP = "select % from ctxa_bridge_user_profile % where %.user_id=$1";

    @Test
    void aSessionUserOfContexaIsLookedUpForNoCopyAndKeepsItsSubject() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             ConfigurableApplicationContext app = start(FullSessionApplication.class, database)) {
            Client client = new Client(port(app));
            Statements beforeTheSignIn = database.statements();
            assertThat(client.formLogin("/login", "admin", ADMIN_PASSWORD)).isEqualTo(302);

            Map<String, Object> subject = client.json("/h/context");
            report("FULL session subject", subject);
            assertThat(subject.get("subjectId")).isEqualTo(database.accountIdOf("admin"));
            Map<String, Object> fresh = client.json("/h/context?fresh=true");
            assertTheSubjectIsTheAccount(database, fresh, "admin");

            Statements before = database.statements();
            for (int i = 0; i < REQUESTS; i++) {
                assertThat(client.get("/h/ping")).isEqualTo(200);
            }
            Statements after = database.statements();
            report("FULL session, " + REQUESTS + " requests", after.minus(before));

            assertThat(after.minus(before).calls(OWN_ACCOUNT_LOOKUP)).as("own-account lookups").isZero();
            assertThat(after.minus(before).calls(COPY_LOOKUP)).as("copy lookups").isZero();
            assertThat(after.minus(beforeTheSignIn).calls(OWN_ACCOUNT_LOOKUP)).as("own-account lookups since the sign-in")
                    .isZero();
            assertThat(database.userRows()).as("no copy of the account").isEqualTo(1);
            assertThat(client.json("/h/context")).isEqualTo(subject);
            assertThat(client.json("/h/context?fresh=true")).isEqualTo(fresh);
        }
    }

    @Test
    void aTokenUserOfContexaIsLookedUpForNoCopyAndKeepsItsSubject() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             ConfigurableApplicationContext app = start(FullTokenApplication.class, database,
                     "contexa.auth.oauth2.service-client-ids=" + SERVICE_CLIENT,
                     "contexa.auth.oauth2.client-secret=fx-internal-client-secret")) {
            Client client = new Client(port(app));
            Statements beforeTheSignIn = database.statements();
            client.bearer(client.restLogin("/api/login", "admin", ADMIN_PASSWORD));

            Map<String, Object> subject = client.json("/h/context");
            report("FULL token subject", subject);
            assertThat(subject.get("subjectId")).isEqualTo(database.accountIdOf("admin"));
            Map<String, Object> fresh = client.json("/h/context?fresh=true");
            assertTheSubjectIsTheAccount(database, fresh, "admin");

            Statements before = database.statements();
            for (int i = 0; i < REQUESTS; i++) {
                assertThat(client.get("/h/ping")).isEqualTo(200);
            }
            Statements after = database.statements();
            report("FULL token, " + REQUESTS + " requests", after.minus(before));

            assertThat(after.minus(before).calls(OWN_ACCOUNT_LOOKUP)).as("own-account lookups").isZero();
            assertThat(after.minus(before).calls(COPY_LOOKUP)).as("copy lookups").isZero();
            assertThat(after.minus(beforeTheSignIn).calls(OWN_ACCOUNT_LOOKUP)).as("own-account lookups since the sign-in")
                    .isZero();
            assertThat(database.userRows()).as("no copy of the account").isEqualTo(1);
            assertThat(client.json("/h/context")).isEqualTo(subject);
            assertThat(client.json("/h/context?fresh=true")).isEqualTo(fresh);
        }
    }

    /**
     * A service client's own token stands for no account. It keeps the copy it always had, synchronised away from the
     * request and remembered: after the first requests none of the client's requests sends a statement for it.
     */
    @Test
    void aServiceClientKeepsItsCopyWithoutAStatementForEachRequest() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             ConfigurableApplicationContext app = start(FullTokenApplication.class, database,
                     "contexa.auth.oauth2.service-client-ids=" + SERVICE_CLIENT,
                     "contexa.auth.oauth2.client-secret=fx-internal-client-secret")) {
            registerServiceClient(app);
            Client client = new Client(port(app));
            client.bearer(client.clientCredentials("/oauth2/token", SERVICE_CLIENT, SERVICE_SECRET));

            assertThat(client.get("/h/ping")).isEqualTo(200);
            awaitTrue(() -> database.copyRowsOf(SERVICE_CLIENT) == 1, Duration.ofSeconds(10));
            Map<String, Object> subject = awaitSubject(client, database.copyIdOf(SERVICE_CLIENT));
            report("FULL service client subject", subject);
            Map<String, Object> fresh = client.json("/h/context?fresh=true");
            assertThat(fresh.get("subjectId")).isEqualTo(database.copyIdOf(SERVICE_CLIENT));

            Statements before = database.statements();
            for (int i = 0; i < REQUESTS; i++) {
                assertThat(client.get("/h/ping")).isEqualTo(200);
            }
            Statements after = database.statements();
            report("FULL service client, " + REQUESTS + " requests", after.minus(before));

            assertThat(after.minus(before).calls(OWN_ACCOUNT_LOOKUP)).as("own-account lookups").isZero();
            assertThat(after.minus(before).calls(COPY_LOOKUP)).as("copy lookups").isZero();
            assertThat(after.minus(before).calls(COPY_PROFILE_LOOKUP)).as("copy profile reads").isZero();
            assertThat(database.copyRowsOf(SERVICE_CLIENT)).as("the client's copy, as before").isEqualTo(1);
            assertThat(client.json("/h/context")).isEqualTo(subject);
            assertThat(client.json("/h/context?fresh=true")).isEqualTo(fresh);
        }
    }

    @Test
    void theApplicationsUserIsCopiedOnceAndItsRequestsSendNoStatementForIt() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             ConfigurableApplicationContext app = start(HostOwnedApplication.class, database,
                     "spring.datasource.url=" + database.hostUrl(),
                     "spring.datasource.username=" + database.username(),
                     "spring.datasource.password=" + database.password())) {
            Client client = new Client(port(app));
            assertThat(client.formLogin("/login", HOST_USER, HOST_PASSWORD)).isEqualTo(302);
            awaitTrue(() -> database.copyRowsOf(HOST_USER) == 1, Duration.ofSeconds(10));
            database.addToTheAdministratorsGroup(database.copyIdOf(HOST_USER));

            Map<String, Object> subject = awaitSubject(client, database.copyIdOf(HOST_USER));
            report("HOST_OWNED subject", subject);
            Map<String, Object> fresh = client.json("/h/context?fresh=true");
            report("HOST_OWNED subject read from the database", fresh);
            assertThat(fresh.get("subjectId")).isEqualTo(database.copyIdOf(HOST_USER));
            assertThat(fresh.get("userGroups")).isEqualTo(database.groupsOf(database.copyIdOf(HOST_USER)));
            assertThat(fresh.get("userRoles")).isEqualTo(database.rolesOf(database.copyIdOf(HOST_USER)));
            assertThat((List<?>) fresh.get("userRoles")).isNotEmpty();

            Statements before = database.statements();
            for (int i = 0; i < REQUESTS; i++) {
                assertThat(client.get("/h/ping")).isEqualTo(200);
            }
            Statements after = database.statements();
            report("HOST_OWNED, " + REQUESTS + " requests", after.minus(before));

            assertThat(after.minus(before).calls(COPY_LOOKUP)).as("copy lookups").isZero();
            assertThat(after.minus(before).calls(COPY_PROFILE_LOOKUP)).as("copy profile reads").isZero();
            assertThat(database.copyRowsOf(HOST_USER)).isEqualTo(1);
            // a copy read from the users' cache carries no groups or roles: the one read from the database is compared
            assertThat(client.json("/h/context").get("subjectId")).isEqualTo(subject.get("subjectId"));
            assertThat(client.json("/h/context?fresh=true")).isEqualTo(fresh);
        }
    }

    // ----- the subject the decisions are given -----

    private static void assertTheSubjectIsTheAccount(TestDatabase database, Map<String, Object> subject, String username)
            throws Exception {
        long id = database.accountIdOf(username);
        report("subject read from the database", subject);
        assertThat(subject.get("subjectId")).isEqualTo(id);
        assertThat(subject.get("subjectUsername")).isEqualTo(username);
        assertThat(subject.get("userGroups")).isEqualTo(database.groupsOf(id));
        assertThat(subject.get("userRoles")).isEqualTo(database.rolesOf(id));
        assertThat((List<?>) subject.get("userRoles")).isNotEmpty();
    }

    /** The subject the decisions read once the copy is remembered for the request. */
    private static Map<String, Object> awaitSubject(Client client, long copyId) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        Map<String, Object> subject = client.json("/h/context");
        while (!Long.valueOf(copyId).equals(subject.get("subjectId")) && System.nanoTime() < deadline) {
            Thread.sleep(50);
            subject = client.json("/h/context");
        }
        assertThat(subject.get("subjectId")).isEqualTo(copyId);
        return subject;
    }

    private static void awaitTrue(CheckedCondition condition, Duration within) throws Exception {
        long deadline = System.nanoTime() + within.toNanos();
        while (!condition.holds()) {
            assertThat(System.nanoTime()).as("condition within " + within).isLessThan(deadline);
            Thread.sleep(50);
        }
    }

    private interface CheckedCondition {
        boolean holds() throws Exception;
    }

    private static void report(String what, Object value) {
        System.out.println("[UserCopyOffTheRequestPath] " + what + ": " + value);
    }

    private static void registerServiceClient(ConfigurableApplicationContext app) {
        PasswordEncoder encoder = app.getBeanProvider(PasswordEncoder.class).getIfUnique();
        String secret = encoder != null ? encoder.encode(SERVICE_SECRET) : "{noop}" + SERVICE_SECRET;
        app.getBean(RegisteredClientRepository.class).save(RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(SERVICE_CLIENT)
                .clientSecret(secret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("read")
                .build());
    }

    // ----- the application -----

    private static ConfigurableApplicationContext start(Class<?> application, TestDatabase database, String... settings) {
        List<String> properties = new ArrayList<>(List.of(
                "spring.main.banner-mode=off",
                "server.port=0",
                "contexa.datasource.url=" + database.url(),
                "contexa.datasource.username=" + database.username(),
                "contexa.datasource.password=" + database.password(),
                "contexa.iam.seed.admin.password=" + ADMIN_PASSWORD));
        properties.addAll(List.of(settings));
        return new SpringApplicationBuilder(application)
                .web(WebApplicationType.SERVLET)
                .properties(properties.toArray(new String[0]))
                .run();
    }

    private static int port(ConfigurableApplicationContext app) {
        return ((ServletWebServerApplicationContext) app).getWebServer().getPort();
    }

    /** A model that answers every decision with ALLOW, and vectors of a fixed size: no model server is reached. */
    abstract static class FixedModels {

        @Bean
        ChatModel fixedChatModel() {
            return new ChatModel() {
                @Override
                public ChatResponse call(Prompt prompt) {
                    return new ChatResponse(List.of(new Generation(new AssistantMessage(
                            "{\"riskScore\":0.1,\"confidence\":0.9,\"action\":\"ALLOW\",\"reasoning\":\"Normal activity\"}"))));
                }

                @Override
                public ChatOptions getDefaultOptions() {
                    return ChatOptions.builder().build();
                }
            };
        }

        @Bean
        EmbeddingModel fixedEmbeddingModel() {
            return new EmbeddingModel() {
                @Override
                public EmbeddingResponse call(EmbeddingRequest request) {
                    List<Embedding> embeddings = new ArrayList<>();
                    for (int i = 0; i < request.getInstructions().size(); i++) {
                        embeddings.add(new Embedding(vector(), i));
                    }
                    return new EmbeddingResponse(embeddings);
                }

                @Override
                public float[] embed(Document document) {
                    return vector();
                }

                private float[] vector() {
                    return new float[]{0.1f, 0.2f, 0.3f, 0.4f};
                }
            };
        }

        @Bean(name = "contexaVectorStore")
        VectorStore contexaVectorStore(EmbeddingModel fixedEmbeddingModel) {
            return SimpleVectorStore.builder(fixedEmbeddingModel).build();
        }

        @Bean
        HostEndpoints hostEndpoints(ContextHandler contextHandler, ContexaCacheService contexaCacheService) {
            return new HostEndpoints(contextHandler, contexaCacheService);
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FullSessionApplication extends FixedModels {

        @Bean
        PlatformConfig platformConfig(ApplicationContext context, CustomDynamicAuthorizationManager authorization)
                throws Exception {
            return new IdentityDslRegistry<HttpSecurity>(context)
                    .global(http -> http
                            .csrf(AbstractHttpConfigurer::disable)
                            .authorizeHttpRequests(requests -> requests.anyRequest().access(authorization)))
                    .form(form -> form.defaultSuccessUrl("/h/ping"))
                    .session(Customizer.withDefaults())
                    .build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FullTokenApplication extends FixedModels {

        @Bean
        PlatformConfig platformConfig(ApplicationContext context, CustomDynamicAuthorizationManager authorization)
                throws Exception {
            return new IdentityDslRegistry<HttpSecurity>(context)
                    .global(http -> http
                            .csrf(AbstractHttpConfigurer::disable)
                            .authorizeHttpRequests(requests -> requests.anyRequest().access(authorization)))
                    .rest(rest -> rest.loginProcessingUrl("/api/login"))
                    .oauth2(Customizer.withDefaults())
                    .build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    static class HostOwnedApplication extends FixedModels {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http
                    .csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                    .formLogin(form -> form.defaultSuccessUrl("/h/ping", true))
                    .build();
        }

        @Bean
        InMemoryUserDetailsManager hostUsers() {
            return new InMemoryUserDetailsManager(User.withUsername(HOST_USER).password("{noop}" + HOST_PASSWORD)
                    .roles("USER").build());
        }
    }

    @RestController
    static class HostEndpoints {

        private final ContextHandler contextHandler;
        private final ContexaCacheService cacheService;

        HostEndpoints(ContextHandler contextHandler, ContexaCacheService cacheService) {
            this.contextHandler = contextHandler;
            this.cacheService = cacheService;
        }

        @GetMapping("/h/ping")
        String ping() {
            return "pong";
        }

        /**
         * What the access decisions are given for this request, and what the bridge found for it; with {@code fresh}
         * the users' cache is emptied first, so the subject is read from the database with its groups and roles.
         */
        @GetMapping("/h/context")
        Map<String, Object> context(HttpServletRequest request, @RequestParam(defaultValue = "false") boolean fresh) {
            if (fresh) {
                SubjectCache.clear(cacheService);
            }
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            AuthorizationContext context = contextHandler.create(authentication, request);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("subjectId", context.subjectEntity() != null ? context.subjectEntity().getId() : null);
            body.put("subjectUsername", context.subjectEntity() != null ? context.subjectEntity().getUsername() : null);
            body.put("userRoles", sorted(context.attributes().get("userRoles")));
            body.put("userGroups", sorted(context.attributes().get("userGroups")));
            body.put("attributeKeys", new TreeSet<>(context.attributes().keySet()).toString());
            body.put("authentication", authentication != null ? authentication.getClass().getSimpleName() : null);
            body.put("principal", authentication != null && authentication.getPrincipal() != null
                    ? authentication.getPrincipal().getClass().getSimpleName() : null);
            Object stamp = request.getAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP);
            body.put("stampPrincipalId", stamp instanceof AuthenticationStamp authenticationStamp
                    ? authenticationStamp.principalId() : null);
            body.put("copyFound", request.getAttribute(BridgeRequestAttributes.USER_SYNC_RESULT)
                    instanceof BridgeUserMirrorSyncResult);
            return body;
        }

        private static List<String> sorted(Object values) {
            List<String> names = new ArrayList<>();
            if (values instanceof Iterable<?> iterable) {
                iterable.forEach(value -> names.add(String.valueOf(value)));
            }
            return List.copyOf(new TreeSet<>(names));
        }
    }

    // ----- HTTP -----

    private static final class Client {

        private final String base;
        private final HttpClient http;
        private String bearer;

        Client(int port) {
            this.base = "http://127.0.0.1:" + port;
            CookieManager cookies = new CookieManager();
            cookies.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
            this.http = HttpClient.newBuilder().cookieHandler(cookies).followRedirects(HttpClient.Redirect.NEVER).build();
        }

        void bearer(String token) {
            this.bearer = token;
        }

        int formLogin(String path, String username, String password) throws Exception {
            String form = "username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                    + "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8);
            return http.send(HttpRequest.newBuilder(URI.create(base + path))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.discarding())
                    .statusCode();
        }

        String restLogin(String path, String username, String password) throws Exception {
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create(base + path))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(
                            Map.of("username", username, "password", password)))).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
            Object token = JSON.readValue(response.body(), Map.class).get("accessToken");
            assertThat(token).as(response.body()).isNotNull();
            return token.toString();
        }

        String clientCredentials(String path, String clientId, String secret) throws Exception {
            String basic = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create(base + path))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Authorization", "Basic " + basic)
                    .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials&scope=read")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
            return JSON.readValue(response.body(), Map.class).get("access_token").toString();
        }

        int get(String path) throws Exception {
            return http.send(request(path), HttpResponse.BodyHandlers.discarding()).statusCode();
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> json(String path) throws Exception {
            HttpResponse<String> response = http.send(request(path), HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
            Map<String, Object> body = JSON.readValue(response.body(), Map.class);
            if (body.get("subjectId") instanceof Number number) {
                body.put("subjectId", number.longValue());
            }
            return body;
        }

        private HttpRequest request(String path) {
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(base + path)).GET();
            if (bearer != null) {
                builder.header("Authorization", "Bearer " + bearer);
            }
            return builder.build();
        }
    }

    // ----- the database -----

    /** The statements of one database, by text, as pg_stat_statements counts them. */
    private record Statements(Map<String, Long> calls) {

        Statements minus(Statements earlier) {
            Map<String, Long> difference = new LinkedHashMap<>();
            calls.forEach((query, count) -> {
                long delta = count - earlier.calls.getOrDefault(query, 0L);
                if (delta != 0) {
                    difference.put(query, delta);
                }
            });
            return new Statements(difference);
        }

        /** The calls of the statements the pattern matches whole; {@code %} stands for any text. */
        long calls(String likePattern) {
            StringBuilder regex = new StringBuilder();
            for (String part : likePattern.toLowerCase(Locale.ROOT).split("%", -1)) {
                if (regex.length() > 0) {
                    regex.append(".*");
                }
                regex.append(Pattern.quote(part));
            }
            Pattern pattern = Pattern.compile(regex.toString(), Pattern.DOTALL);
            return calls.entrySet().stream()
                    .filter(entry -> pattern.matcher(entry.getKey().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ")).matches())
                    .mapToLong(Map.Entry::getValue)
                    .sum();
        }

        @Override
        public String toString() {
            StringBuilder text = new StringBuilder();
            calls.forEach((query, count) -> {
                if (query.toLowerCase(Locale.ROOT).contains("ctxa_users")
                        || query.toLowerCase(Locale.ROOT).contains("ctxa_bridge_user_profile")) {
                    text.append(System.lineSeparator()).append("    ").append(count).append(" x ")
                            .append(query.replaceAll("\\s+", " "));
                }
            });
            return text.length() == 0 ? "no statement on ctxa_users or ctxa_bridge_user_profile" : text.toString();
        }
    }

    private static final class TestDatabase implements AutoCloseable {

        private final String adminUrl;
        private final String url;
        private final String hostUrl;
        private final String name;
        private final String username;
        private final String password;

        private TestDatabase(String adminUrl, String url, String hostUrl, String name, String username, String password) {
            this.adminUrl = adminUrl;
            this.url = url;
            this.hostUrl = hostUrl;
            this.name = name;
            this.username = username;
            this.password = password;
        }

        static TestDatabase create() throws Exception {
            String configured = System.getenv("CONTEXA_TEST_DB_URL");
            String username = System.getenv().getOrDefault("CONTEXA_TEST_DB_USERNAME", "contexa_test");
            String password = System.getenv().getOrDefault("CONTEXA_TEST_DB_PASSWORD", "contexa_test");
            String base = configured.substring(0, configured.lastIndexOf('/') + 1);
            String name = "contexa_copy_" + UUID.randomUUID().toString().replace("-", "");
            TestDatabase database = new TestDatabase(base + "postgres", base + name, base + name + "_host", name,
                    username, password);
            try (Connection admin = DriverManager.getConnection(database.adminUrl, username, password);
                 Statement statement = admin.createStatement()) {
                statement.execute("create database " + name);
                statement.execute("create database " + name + "_host");
            }
            try (Connection connection = database.connect(); Statement statement = connection.createStatement()) {
                statement.execute("create schema if not exists fx_statistics");
                statement.execute("create extension if not exists pg_stat_statements schema fx_statistics");
            }
            return database;
        }

        String url() {
            return url;
        }

        /** The application's own database. */
        String hostUrl() {
            return hostUrl;
        }

        String username() {
            return username;
        }

        String password() {
            return password;
        }

        Connection connect() throws Exception {
            return DriverManager.getConnection(url, username, password);
        }

        Statements statements() throws Exception {
            Map<String, Long> calls = new LinkedHashMap<>();
            try (Connection connection = connect();
                 PreparedStatement statement = connection.prepareStatement(
                         "select query, sum(calls) from fx_statistics.pg_stat_statements where dbid = "
                                 + "(select oid from pg_database where datname = current_database()) group by query");
                 ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    calls.put(rows.getString(1), rows.getLong(2));
                }
            }
            return new Statements(calls);
        }

        long userRows() throws Exception {
            return single("select count(*) from ctxa_users");
        }

        long accountIdOf(String username) throws Exception {
            return single("select id from ctxa_users where username = ? and bridge_managed = false", username);
        }

        long copyRowsOf(String subject) throws Exception {
            return single("select count(*) from ctxa_users where external_subject_id = ? and bridge_managed = true", subject);
        }

        long copyIdOf(String subject) throws Exception {
            return single("select id from ctxa_users where external_subject_id = ? and bridge_managed = true", subject);
        }

        void addToTheAdministratorsGroup(long userId) throws Exception {
            try (Connection connection = connect();
                 PreparedStatement statement = connection.prepareStatement(
                         "insert into ctxa_user_groups (user_id, group_id) values (?, 1)")) {
                statement.setLong(1, userId);
                statement.executeUpdate();
            }
        }

        List<String> groupsOf(long userId) throws Exception {
            return names("select g.group_name from ctxa_user_groups ug join ctxa_app_group g on g.group_id = ug.group_id "
                    + "where ug.user_id = ?", userId);
        }

        List<String> rolesOf(long userId) throws Exception {
            return names("select r.role_name from ctxa_user_roles ur join ctxa_role r on r.role_id = ur.role_id "
                    + "where ur.user_id = ? union select r.role_name from ctxa_user_groups ug "
                    + "join ctxa_group_roles gr on gr.group_id = ug.group_id join ctxa_role r on r.role_id = gr.role_id "
                    + "where ug.user_id = ?", userId, userId);
        }

        private List<String> names(String sql, Object... parameters) throws Exception {
            TreeSet<String> names = new TreeSet<>();
            try (Connection connection = connect(); PreparedStatement statement = connection.prepareStatement(sql)) {
                for (int i = 0; i < parameters.length; i++) {
                    statement.setObject(i + 1, parameters[i]);
                }
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        names.add(rows.getString(1));
                    }
                }
            }
            return List.copyOf(names);
        }

        private long single(String sql, Object... parameters) throws Exception {
            try (Connection connection = connect(); PreparedStatement statement = connection.prepareStatement(sql)) {
                for (int i = 0; i < parameters.length; i++) {
                    statement.setObject(i + 1, parameters[i]);
                }
                try (ResultSet rows = statement.executeQuery()) {
                    assertThat(rows.next()).as(sql).isTrue();
                    return rows.getLong(1);
                }
            }
        }

        @Override
        public void close() throws Exception {
            try (Connection admin = DriverManager.getConnection(adminUrl, username, password);
                 Statement statement = admin.createStatement()) {
                statement.execute("select pg_terminate_backend(pid) from pg_stat_activity where datname in ('" + name
                        + "', '" + name + "_host') and pid <> pg_backend_pid()");
                statement.execute("drop database if exists " + name);
                statement.execute("drop database if exists " + name + "_host");
            }
        }
    }
}

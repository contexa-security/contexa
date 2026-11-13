/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.springbootstartercontexa;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.testsupport.TestStores;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexaiam.agent.JdbcAgentRegistry;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
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
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
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
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The application's request does not wait for Contexa's database to find out whether its account is an approved agent,
 * on a real application, a real port and a real PostgreSQL (started with {@code shared_preload_libraries=pg_stat_statements},
 * so the statements Contexa sends can be counted): the approved agents are kept in memory. What the request is read as
 * does not change (an agent's account is the agent, a person's is not), a change made in the application's own JVM shows
 * at once, one made by another server within seconds, and what decides whether an agent's token is accepted (its
 * suspension) is still asked of the database, so the failure of the database never lifts it.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@Timeout(900)
class AgentListOffTheRequestPathPostgresIntegrationTest {

    private static final int PEOPLE = 40;
    private static final String ADMIN_PASSWORD = "Fx26-Admin-Pass-9";
    private static final String PASSWORD = "host-pass";
    private static final String AGENT_CLIENT = "fx-agent-client";
    private static final String AGENT_SECRET = "fx-agent-secret";
    private static final Duration WITHIN_FIVE_SECONDS = Duration.ofSeconds(8);
    private static final ObjectMapper JSON = new ObjectMapper();

    /** The statement of the registry that asks which agent a client or an identifier is (JdbcAgentRegistry.findByClientId). */
    private static final String CLIENT_LOOKUP = "select % from ctxa_agent_registration where tenant_key = $1 and (client_id = $2 or agent_id = $3)%";
    /** The statement that reads the approved agents again (JdbcAgentRegistry.approvals). */
    private static final String APPROVALS_READ = "select tenant_key, agent_id, client_id, status, allowlisted from (%";

    // ----- the application owns the sign-in (SANDBOX) -----

    /** What the request is read as does not depend on where the registry is kept. */
    @Test
    void anAgentsAccountIsReadAsTheAgentAndAPersonsIsNot() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             ConfigurableApplicationContext app = start(HostOwnedApplication.class, database)) {
            register(app, "report-bot", "report-client");

            Client agent = new Client(port(app));
            assertThat(agent.formLogin("/login", "report-bot", PASSWORD)).isEqualTo(302);
            Map<String, Object> stamp = agent.json("/h/stamp");
            report("agent account stamp", stamp);
            assertThat(stamp).containsEntry("agentId", "report-bot").containsEntry("subjectId", "report-bot")
                    .containsEntry("delegated", false).containsEntry("resolver", "AGENT_ACCOUNT")
                    .containsEntry("evidenceState", "AGENT_REGISTRY_RECORD").containsEntry("agentAccount", "report-bot");

            Client person = new Client(port(app));
            assertThat(person.formLogin("/login", "alice", PASSWORD)).isEqualTo(302);
            assertThat(person.json("/h/stamp")).as("a person yields no stamp").isEmpty();

            Client draft = new Client(port(app));
            app.getBean(AgentRegistry.class).register(new AgentRegistrationRequest(null, "draft-bot", "Draft", "AGENT",
                    "draft-client", "sponsor", false));
            assertThat(draft.formLogin("/login", "draft-bot", PASSWORD)).isEqualTo(302);
            assertThat(draft.json("/h/stamp")).as("an agent that is not approved is not read as one").isEmpty();
        }
    }

    /**
     * The requests of forty people, each met for the first time, send no statement to ask the registry who they are, and
     * a request does not wait while the registry's table cannot be read at all.
     */
    @Test
    void aRequestSendsNoLookupToTheRegistryAndDoesNotWaitForItsTable() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             ConfigurableApplicationContext app = start(HostOwnedApplication.class, database)) {
            register(app, "report-bot", "report-client");

            Statements before = database.statements();
            long begun = System.nanoTime();
            for (int person = 0; person < PEOPLE; person++) {
                Client client = new Client(port(app));
                assertThat(client.formLogin("/login", "user" + person, PASSWORD)).isEqualTo(302);
                assertThat(client.json("/h/stamp")).isEmpty();
            }
            long millis = Duration.ofNanos(System.nanoTime() - begun).toMillis();
            Statements during = database.statements().minus(before);
            report(PEOPLE + " people signed in and read in " + millis + " ms; lookups of the registry",
                    during.calls(CLIENT_LOOKUP) + ", readings of the approved agents " + during.calls(APPROVALS_READ));
            assertThat(during.calls(CLIENT_LOOKUP)).as("lookups of the registry for " + PEOPLE + " new people").isZero();

            try (RegistryLock locked = database.lockRegistryTable()) {
                long start = System.nanoTime();
                Client person = new Client(port(app));
                assertThat(person.formLogin("/login", "alice", PASSWORD)).isEqualTo(302);
                assertThat(person.json("/h/stamp")).isEmpty();
                long personMillis = Duration.ofNanos(System.nanoTime() - start).toMillis();

                // what reads the agent's request (the other reads of an agent's own requests are not this one's)
                AgentClientDirectory directory = app.getBean(AgentClientDirectory.class);
                start = System.nanoTime();
                Optional<String> agent = directory.requestPathActiveAgentForAccount(null, "report-bot");
                long agentMillis = Duration.ofNanos(System.nanoTime() - start).toMillis();

                report("with the registry's table locked: a new person signs in and is read in " + personMillis
                        + " ms, the agent's account is read in " + agentMillis + " ms", agent);
                assertThat(agent).as("the agent is still read as the agent").contains("report-bot");
                assertThat(personMillis).as("the person's sign-in and request while the table is locked").isLessThan(700);
                assertThat(agentMillis).as("the agent's account while the table is locked").isLessThan(50);
            }
        }
    }

    /** A change made through this application's registry shows in the very next request, as it did before. */
    @Test
    void aChangeMadeInThisServerShowsInTheNextRequest() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             ConfigurableApplicationContext app = start(HostOwnedApplication.class, database)) {
            AgentRegistry registry = app.getBean(AgentRegistry.class);
            AgentClientDirectory directory = app.getBean(AgentClientDirectory.class);
            Client bot = new Client(port(app));
            assertThat(bot.formLogin("/login", "late-bot", PASSWORD)).isEqualTo(302);
            assertThat(bot.json("/h/stamp")).as("not yet registered: read as a person").isEmpty();

            register(app, "late-bot", "late-client");
            assertThat(bot.json("/h/stamp")).as("registered").containsEntry("agentId", "late-bot");
            assertThat(directory.activeAgentForAccount(null, "late-bot")).contains("late-bot");

            registry.suspend(null, "late-bot", "stopped");
            assertThat(bot.json("/h/stamp")).as("suspended").isEmpty();
            assertThat(directory.suspendedAgentClient(null, "late-client")).isTrue();

            registry.resume(null, "late-bot", "released");
            assertThat(bot.json("/h/stamp")).as("resumed").containsEntry("agentId", "late-bot");

            registry.deregister(null, "late-bot", "retired");
            assertThat(bot.json("/h/stamp")).as("deregistered").isEmpty();

            register(app, "late-bot", "late-client");
            assertThat(bot.json("/h/stamp")).as("registered again").containsEntry("agentId", "late-bot");

            registry.remove(null, "late-bot");
            assertThat(bot.json("/h/stamp")).as("removed").isEmpty();
        }
    }

    /** A change another server made to the shared database shows within seconds (before, only when a 30 second cache ended). */
    @Test
    void aChangeAnotherServerMadeShowsWithinSeconds() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             ConfigurableApplicationContext app = start(HostOwnedApplication.class, database)) {
            Client bot = new Client(port(app));
            assertThat(bot.formLogin("/login", "other-bot", PASSWORD)).isEqualTo(302);
            assertThat(bot.json("/h/stamp")).as("not yet registered: read as a person").isEmpty();

            AgentRegistry elsewhere = new JdbcAgentRegistry(new JdbcTemplate(
                    new DriverManagerDataSource(database.url(), database.username(), database.password())));
            elsewhere.register(new AgentRegistrationRequest(null, "other-bot", "Other", "AGENT", "other-client", "sponsor", true));
            long registered = awaitStamp(bot, true);
            report("another server registered the agent: read as the agent after", registered + " ms");
            assertThat(registered).as("registered elsewhere, read as the agent").isLessThan(WITHIN_FIVE_SECONDS.toMillis());

            elsewhere.suspend(null, "other-bot", "stopped elsewhere");
            long suspended = awaitStamp(bot, false);
            report("another server suspended the agent: read as a person after", suspended + " ms");
            assertThat(suspended).as("suspended elsewhere, no longer read as the agent")
                    .isLessThan(WITHIN_FIVE_SECONDS.toMillis());

            elsewhere.resume(null, "other-bot", "released elsewhere");
            assertThat(awaitStamp(bot, true)).isLessThan(WITHIN_FIVE_SECONDS.toMillis());
            elsewhere.remove(null, "other-bot");
            assertThat(awaitStamp(bot, false)).isLessThan(WITHIN_FIVE_SECONDS.toMillis());
        }
    }

    // ----- Contexa owns the sign-in (FULL) -----

    /**
     * An agent's token is accepted only while the database says it is not suspended, and the database not answering never
     * says so: the token waits (401). A person's token, which asks nothing of the registry but its stamp, does not wait.
     */
    @Test
    void aSuspensionIsStillReadFromTheDatabaseAndAPersonsTokenDoesNotWaitForIt() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             ConfigurableApplicationContext app = start(FullTokenApplication.class, database,
                     "contexa.auth.oauth2.client-secret=fx-internal-client-secret")) {
            AgentRegistry registry = app.getBean(AgentRegistry.class);
            registerAgentClient(app);
            register(app, "fx-agent", AGENT_CLIENT);
            Client person = new Client(port(app));
            person.bearer(person.restLogin("/api/login", "admin", ADMIN_PASSWORD));
            Client agent = new Client(port(app));
            agent.bearer(agent.clientCredentials("/oauth2/token", AGENT_CLIENT, AGENT_SECRET));

            assertThat(person.json("/h/stamp")).as("a person's token names no agent").isEmpty();
            Map<String, Object> stamp = agent.json("/h/stamp");
            report("agent token stamp", stamp);
            assertThat(stamp).containsEntry("agentId", "fx-agent").containsEntry("delegated", false)
                    .containsEntry("resolver", "TOKEN");

            // a change of the registry in this JVM clears what the registry remembered of the client: the next suspension
            // check goes to the database
            registry.transferSponsor(null, "fx-agent", "another-sponsor");
            try (RegistryLock locked = database.lockRegistryTable()) {
                long start = System.nanoTime();
                assertThat(person.json("/h/stamp")).isEmpty();
                long personMillis = Duration.ofNanos(System.nanoTime() - start).toMillis();
                report("with the registry's table locked, the person's token is read in", personMillis + " ms");
                assertThat(personMillis).as("a person's token while the table is locked").isLessThan(700);

                assertThat(agent.get("/h/stamp")).as("the agent's token while its suspension cannot be read").isEqualTo(401);
            }
            long unlocked = System.nanoTime();
            while (agent.get("/h/stamp") != 200) {
                assertThat(Duration.ofNanos(System.nanoTime() - unlocked)).as("the token is accepted again")
                        .isLessThan(Duration.ofSeconds(40));
                Thread.sleep(250);
            }

            registry.suspend(null, "fx-agent", "stopped");
            assertThat(agent.get("/h/stamp")).as("a suspended agent's token").isEqualTo(401);
            registry.resume(null, "fx-agent", "released");
            assertThat(agent.get("/h/stamp")).as("a resumed agent's token").isEqualTo(200);
        }
    }

    // ----- helpers -----

    private static long awaitStamp(Client client, boolean agent) throws Exception {
        long begun = System.nanoTime();
        long deadline = begun + Duration.ofSeconds(40).toNanos();
        while (System.nanoTime() < deadline) {
            if (client.json("/h/stamp").isEmpty() != agent) {
                return Duration.ofNanos(System.nanoTime() - begun).toMillis();
            }
            Thread.sleep(100);
        }
        throw new AssertionError("the stamp did not become " + (agent ? "the agent's" : "empty") + " within 40 seconds");
    }

    private static void register(ConfigurableApplicationContext app, String agentId, String clientId) {
        app.getBean(AgentRegistry.class).register(new AgentRegistrationRequest(null, agentId, agentId, "AGENT", clientId,
                "sponsor", true));
    }

    private static void registerAgentClient(ConfigurableApplicationContext app) {
        PasswordEncoder encoder = app.getBeanProvider(PasswordEncoder.class).getIfUnique();
        String secret = encoder != null ? encoder.encode(AGENT_SECRET) : "{noop}" + AGENT_SECRET;
        app.getBean(RegisteredClientRepository.class).save(RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(AGENT_CLIENT)
                .clientSecret(secret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("read")
                .build());
    }

    private static void report(String what, Object value) {
        System.out.println("[AgentListOffTheRequestPath] " + what + ": " + value);
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
        if (application == HostOwnedApplication.class) {
            properties.addAll(List.of(
                    "spring.datasource.url=" + database.hostUrl(),
                    "spring.datasource.username=" + database.username(),
                    "spring.datasource.password=" + database.password()));
        }
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
        HostEndpoints hostEndpoints() {
            return new HostEndpoints();
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
                    .formLogin(form -> form.defaultSuccessUrl("/h/stamp", true))
                    .build();
        }

        @Bean
        InMemoryUserDetailsManager hostUsers() {
            List<UserDetails> users = new ArrayList<>();
            List<String> names = new ArrayList<>(List.of("alice", "report-bot", "draft-bot", "late-bot", "other-bot"));
            for (int person = 0; person < PEOPLE; person++) {
                names.add("user" + person);
            }
            for (String name : names) {
                users.add(User.withUsername(name).password("{noop}" + PASSWORD).roles("USER").build());
            }
            return new InMemoryUserDetailsManager(users);
        }
    }

    @RestController
    static class HostEndpoints {

        @GetMapping("/h/stamp")
        Map<String, Object> stamp(HttpServletRequest request) {
            Map<String, Object> body = new LinkedHashMap<>();
            if (request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP) instanceof DelegationStamp stamp) {
                body.put("agentId", stamp.agentId());
                body.put("subjectId", stamp.subjectId());
                body.put("delegated", stamp.delegated());
                body.put("resolver", stamp.attributes().get("delegationResolver"));
                body.put("evidenceState", stamp.attributes().get("delegationEvidenceState"));
                body.put("agentAccount", stamp.attributes().get("agentAccount"));
            }
            return body;
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
            return JSON.readValue(response.body(), Map.class);
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
            TestStores.Database store = TestStores.database();
            String configured = store.url();
            String username = store.username();
            String password = store.password();
            String base = configured.substring(0, configured.lastIndexOf('/') + 1);
            String name = "contexa_agents_" + UUID.randomUUID().toString().replace("-", "");
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

        /** A transaction that holds the registry's table: no one else can read or write it until the connection is closed. */
        RegistryLock lockRegistryTable() throws Exception {
            Connection connection = connect();
            connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement()) {
                statement.execute("lock table ctxa_agent_registration in access exclusive mode");
            }
            return new RegistryLock(connection);
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

    /** The transaction that holds the lock: closing it rolls the transaction back and ends the lock. */
    private static final class RegistryLock implements AutoCloseable {

        private final Connection connection;

        RegistryLock(Connection connection) {
            this.connection = connection;
        }

        @Override
        public void close() throws Exception {
            connection.rollback();
            connection.close();
        }
    }
}

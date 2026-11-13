/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.springbootstartercontexa;

import io.contexa.contexacore.testsupport.TestStores;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
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
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
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
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The blocks the database holds in force are in force again after the decision store was emptied while the application
 * runs, on a real application on a real port, Contexa's database on a real PostgreSQL and the decisions in a real Redis
 * that is emptied here. The application keeps the sign-in, the way a Contexa under HOST_OWNED does; the one Redis of the
 * test is its decision store (distributed mode), and a user that is blocked is refused on the application's own pages.
 * <p>
 * A model that answers ALLOW stands behind every decision: a user the store forgot is let through by it, and nothing but
 * the record of blocks can put the block back.
 */
@Timeout(900)
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_REDIS_PORT", matches = ".+")
class RestrictionRestorerRedisFlushPostgresIntegrationTest {

    private static final String APPLICATION = "restorer-it";
    private static final String PASSWORD = "pass-1";
    private static final String ADMIN_PASSWORD = "Fx1-Admin-Pass-9";
    /** The longest a block may stay out of the store after it was emptied, in this test; the look is far more often than that. */
    private static final Duration RESTORED_WITHIN = Duration.ofSeconds(60);

    @Test
    void aBlockTheStoreLostIsBackWithoutARestartAndNoOtherUserIsBlockedByIt() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             RedisServer redis = RedisServer.connect();
             ConfigurableApplicationContext app = start(HostOwnedApplication.class, database, redis.port())) {
            Client alice = new Client(port(app));
            Client bob = new Client(port(app));
            Client carol = new Client(port(app));
            assertThat(alice.formLogin("/login", "alice")).isEqualTo(302);
            assertThat(bob.formLogin("/login", "bob")).isEqualTo(302);
            assertThat(carol.formLogin("/login", "carol")).isEqualTo(302);
            assertThat(alice.get("/h/ping").status()).isEqualTo(200);
            assertThat(bob.get("/h/ping").status()).isEqualTo(200);
            assertThat(carol.get("/h/ping").status()).isEqualTo(200);

            // The way the engine blocks: the flag first, then the record.
            block(app, "alice");
            block(app, "carol");
            Answer blocked = alice.get("/h/ping");
            report("alice before the release and the flush", blocked);
            assertThat(blocked.status()).as(blocked.body()).isIn(401, 403);
            assertThat(blocked.body()).contains("BLOCK");
            assertThat(carol.get("/h/ping").status()).as("carol is blocked too").isIn(401, 403);
            assertThat(bob.get("/h/ping").status()).isEqualTo(200);

            // An administrator releases carol: the record is resolved, the flag goes.
            release(app, "carol");
            assertThat(carol.get("/h/ping").status()).as("carol is released").isEqualTo(200);
            assertThat(redis.blockedUsers()).containsExactly("alice");

            redis.flushAll();
            assertThat(redis.blockedUsers()).as("the store was emptied").isEmpty();

            long emptied = System.nanoTime();
            awaitBlockedUsers(redis, Set.of("alice"), RESTORED_WITHIN);
            report("alice's block was back after", Duration.ofNanos(System.nanoTime() - emptied));

            Answer again = alice.get("/h/ping");
            report("alice after the restore", again);
            assertThat(again.status()).as(again.body()).isIn(401, 403);
            assertThat(again.body()).contains("BLOCK");
            assertThat(carol.get("/h/ping").status()).as("carol, whom an administrator released, is not blocked again")
                    .isEqualTo(200);
            assertThat(bob.get("/h/ping").status()).as("bob was never blocked").isEqualTo(200);
            assertThat(redis.blockedUsers()).containsExactly("alice");
        }
    }


    /**
     * An administrator releases a user while the store is empty: the record is resolved first, so no look finds the user in
     * force and nothing writes the block back, however long it waits.
     */
    @Test
    void aBlockReleasedWhileTheStoreWasEmptyIsNotWrittenBack() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             RedisServer redis = RedisServer.connect();
             ConfigurableApplicationContext app = start(HostOwnedApplication.class, database, redis.port())) {
            Client alice = new Client(port(app));
            assertThat(alice.formLogin("/login", "alice")).isEqualTo(302);
            block(app, "alice");
            assertThat(alice.get("/h/ping").status()).isIn(401, 403);

            redis.flushAll();
            release(app, "alice");

            // Longer than a look and the time it takes: the flag stays away and the user is let through.
            Thread.sleep(Duration.ofSeconds(25).toMillis());
            assertThat(redis.blockedUsers()).isEmpty();
            assertThat(alice.get("/h/ping").status()).as("released by an administrator").isEqualTo(200);
        }
    }

    /**
     * The list the look is made from is the question {@code isBlockInForce} asks, answered for every user at once, on a
     * real database: the latest record of a user decides, whatever the records before it were.
     */
    @Test
    void theListOfBlocksInForceIsWhatIsBlockInForceAnswersOnARealDatabase() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             RedisServer redis = RedisServer.connect();
             ConfigurableApplicationContext app = start(HostOwnedApplication.class, database, redis.port(),
                     "contexa.security.zerotrust.mode=DISABLED")) {
            BlockedUserJpaRepository rows = app.getBean(BlockedUserJpaRepository.class);
            LocalDateTime base = LocalDateTime.of(2026, 11, 1, 9, 0);
            record(rows, "only-blocked", BlockedUserStatus.BLOCKED, base);
            record(rows, "released-after", BlockedUserStatus.BLOCKED, base);
            record(rows, "released-after", BlockedUserStatus.RESOLVED, base.plusMinutes(5));
            record(rows, "blocked-again", BlockedUserStatus.RESOLVED, base);
            record(rows, "blocked-again", BlockedUserStatus.BLOCKED, base.plusMinutes(6));
            record(rows, "unblock-requested", BlockedUserStatus.UNBLOCK_REQUESTED, base);
            record(rows, "timed-out", BlockedUserStatus.TIMEOUT_RESPONDED, base);
            record(rows, "mfa-failed", BlockedUserStatus.MFA_FAILED, base);
            record(rows, "never-in-force", BlockedUserStatus.RESOLVED, base);
            record(rows, "old-unresolved-newest-resolved", BlockedUserStatus.MFA_FAILED, base);
            record(rows, "old-unresolved-newest-resolved", BlockedUserStatus.RESOLVED, base.plusMinutes(9));
            record(rows, "console::admin", BlockedUserStatus.BLOCKED, base);
            record(rows, "twice-blocked", BlockedUserStatus.BLOCKED, base);
            record(rows, "twice-blocked", BlockedUserStatus.BLOCKED, base.plusMinutes(2));

            BlockedUserService service = app.getBean(BlockedUserService.class);
            Set<String> listed = Set.copyOf(service.blocksInForce());
            Set<String> asked = new TreeSet<>();
            for (BlockedUser row : rows.findAll()) {
                if (service.isBlockInForce(row.getUserId())) {
                    asked.add(row.getUserId());
                }
            }

            report("blocks in force", new TreeSet<>(listed));
            assertThat(listed).isEqualTo(asked);
            assertThat(listed).containsExactlyInAnyOrder("only-blocked", "blocked-again", "unblock-requested", "timed-out",
                    "mfa-failed", "console::admin", "twice-blocked");
            assertThat(service.blocksInForce()).doesNotHaveDuplicates();
        }
    }

    /**
     * Redis goes away, a request meets the outage, it comes back empty: the block is written again as soon as Redis
     * answers, not at the next look (the look is made every fifteen seconds, and the outage here is a few seconds long).
     * The Redis of the application is reached through a proxy that is closed and opened here.
     */
    @Test
    void aRedisThatCameBackEmptyGetsItsBlocksBeforeTheNextLook() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             RedisServer redis = RedisServer.connect();
             RedisProxy proxy = new RedisProxy(redis.port());
             ConfigurableApplicationContext app = start(HostOwnedApplication.class, database, proxy.port())) {
            Client alice = new Client(port(app));
            Client bob = new Client(port(app));
            assertThat(alice.formLogin("/login", "alice")).isEqualTo(302);
            assertThat(bob.formLogin("/login", "bob")).isEqualTo(302);
            block(app, "alice");
            assertThat(alice.get("/h/ping").status()).isIn(401, 403);
            ContexaStores stores = app.getBean(ContexaStores.class);

            proxy.cut();
            long meetTheOutage = System.nanoTime() + Duration.ofSeconds(10).toNanos();
            while (!stores.redis().isDown() && System.nanoTime() < meetTheOutage) {
                bob.get("/h/ping");
                Thread.sleep(100);
            }
            assertThat(stores.redis().isDown()).as("a request met the outage").isTrue();
            redis.flushAll();
            Thread.sleep(1500);

            long back = System.nanoTime();
            proxy.open();
            awaitBlockedUsers(redis, Set.of("alice"), Duration.ofSeconds(12));
            report("alice's block was back, after Redis answered again, in", Duration.ofNanos(System.nanoTime() - back));
            assertThat(alice.get("/h/ping").status()).isIn(401, 403);
            assertThat(bob.get("/h/ping").status()).isEqualTo(200);
        }
    }

    /** The same where Contexa keeps the sign-in: the account of the administrator is the one that is blocked. */
    @Test
    void aBlockTheStoreLostIsBackWhereContexaKeepsTheSignIn() throws Exception {
        try (TestDatabase database = TestDatabase.create();
             RedisServer redis = RedisServer.connect();
             ConfigurableApplicationContext app = start(ContexaOwnedApplication.class, database, redis.port(),
                     "contexa.ai.security.mode=FULL", "contexa.iam.seed.admin.password=" + ADMIN_PASSWORD)) {
            ZeroTrustActionRepository actions = app.getBean(ZeroTrustActionRepository.class);
            block(app, "admin");
            assertThat(actions.getCurrentAction("admin", "context-1")).isEqualTo(ZeroTrustAction.BLOCK);

            redis.flushAll();
            assertThat(actions.getCurrentAction("admin", "context-1")).as("the store was emptied")
                    .isNotEqualTo(ZeroTrustAction.BLOCK);

            awaitBlockedUsers(redis, Set.of("admin"), RESTORED_WITHIN);
            assertThat(actions.getCurrentAction("admin", "context-1")).isEqualTo(ZeroTrustAction.BLOCK);
            assertThat(actions.getCurrentAction("nobody", "context-1")).isNotEqualTo(ZeroTrustAction.BLOCK);
        }
    }

    private static void record(BlockedUserJpaRepository rows, String user, BlockedUserStatus status, LocalDateTime at) {
        rows.save(BlockedUser.builder().userId(user).username(user).requestId("req-" + UUID.randomUUID()).status(status)
                .blockedAt(at).blockCount(1).build());
    }

    // ----- the application -----

    private static void block(ConfigurableApplicationContext app, String user) {
        app.getBean(ZeroTrustActionRepository.class).setBlockedFlag(user);
        app.getBean(IBlockedUserRecorder.class).recordBlock("req-" + UUID.randomUUID(), user, user, "BLOCK",
                "the model decided a block", "127.0.0.1", "restorer-test");
    }

    /** As the block list's release does: the record is resolved first, and the store is cleared once that is committed. */
    private static void release(ConfigurableApplicationContext app, String user) {
        BlockedUser row = app.getBean(BlockedUserJpaRepository.class)
                .findFirstByUserIdAndStatusOrderByBlockedAtDesc(user, BlockedUserStatus.BLOCKED).orElseThrow();
        app.getBean(BlockedUserService.class).resolveBlockById(row.getId(), "ops-admin", "ALLOW", "released by the test");
    }

    private static void awaitBlockedUsers(RedisServer redis, Set<String> expected, Duration within) throws Exception {
        long deadline = System.nanoTime() + within.toNanos();
        while (!redis.blockedUsers().equals(expected)) {
            assertThat(System.nanoTime()).as("the blocks " + expected + " were back within " + within + ", found "
                    + redis.blockedUsers()).isLessThan(deadline);
            Thread.sleep(200);
        }
    }

    private static void report(String what, Object value) {
        System.out.println("[RestrictionRestorerRedisFlush] " + what + ": " + value);
    }

    private static ConfigurableApplicationContext start(Class<?> application, TestDatabase database, int redisPort,
                                                         String... settings) {
        List<String> properties = new ArrayList<>(List.of(
                "spring.main.banner-mode=off",
                "server.port=0",
                "spring.application.name=" + APPLICATION,
                "spring.datasource.url=" + database.hostUrl(),
                "spring.datasource.username=" + database.username(),
                "spring.datasource.password=" + database.password(),
                "contexa.datasource.url=" + database.url(),
                "contexa.datasource.username=" + database.username(),
                "contexa.datasource.password=" + database.password(),
                "contexa.saas.enabled=false",
                "contexa.infrastructure.mode=distributed",
                "spring.data.redis.host=127.0.0.1",
                "spring.data.redis.port=" + redisPort,
                "spring.kafka.bootstrap-servers=127.0.0.1:1"));
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
        HostPages hostPages() {
            return new HostPages();
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
            return new InMemoryUserDetailsManager(
                    User.withUsername("alice").password("{noop}" + PASSWORD).roles("USER").build(),
                    User.withUsername("bob").password("{noop}" + PASSWORD).roles("USER").build(),
                    User.withUsername("carol").password("{noop}" + PASSWORD).roles("USER").build());
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class ContexaOwnedApplication extends FixedModels {

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

    @RestController
    static class HostPages {

        @GetMapping("/h/ping")
        String ping() {
            return "pong";
        }
    }

    // ----- HTTP -----

    private record Answer(int status, String body) {
    }

    private static final class Client {

        private final String base;
        private final HttpClient http;

        Client(int port) {
            this.base = "http://127.0.0.1:" + port;
            CookieManager cookies = new CookieManager();
            cookies.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
            this.http = HttpClient.newBuilder().cookieHandler(cookies).followRedirects(HttpClient.Redirect.NEVER).build();
        }

        int formLogin(String path, String username) throws Exception {
            String form = "username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                    + "&password=" + URLEncoder.encode(PASSWORD, StandardCharsets.UTF_8);
            return http.send(HttpRequest.newBuilder(URI.create(base + path))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.discarding())
                    .statusCode();
        }

        /** As an API client calls: the answer to a block is a body, not a redirect to a page. */
        Answer get(String path) throws Exception {
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create(base + path)).GET()
                    .header("Accept", "application/json").header("X-Requested-With", "XMLHttpRequest").build(),
                    HttpResponse.BodyHandlers.ofString());
            return new Answer(response.statusCode(), response.body());
        }
    }


    // ----- a Redis that can go away -----

    /** A TCP proxy to the Redis of the test that can be closed, which cuts every connection, and opened again. */
    private static final class RedisProxy implements AutoCloseable {

        private final int target;
        private final int port;
        private final List<Socket> sockets = new CopyOnWriteArrayList<>();
        private volatile ServerSocket server;

        RedisProxy(int target) throws IOException {
            this.target = target;
            try (ServerSocket free = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
                this.port = free.getLocalPort();
            }
            open();
        }

        int port() {
            return port;
        }

        void open() throws IOException {
            ServerSocket listening = new ServerSocket();
            listening.setReuseAddress(true);
            listening.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
            server = listening;
            Thread acceptor = new Thread(() -> {
                while (!listening.isClosed()) {
                    try {
                        Socket client = listening.accept();
                        Socket upstream = new Socket(InetAddress.getLoopbackAddress(), target);
                        sockets.add(client);
                        sockets.add(upstream);
                        pump(client, upstream);
                        pump(upstream, client);
                    } catch (IOException closed) {
                        // the proxy was closed, or the Redis is not there
                    }
                }
            }, "restorer-it-redis-proxy");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        private void pump(Socket from, Socket to) {
            Thread thread = new Thread(() -> {
                byte[] buffer = new byte[8192];
                try {
                    int read;
                    while ((read = from.getInputStream().read(buffer)) >= 0) {
                        to.getOutputStream().write(buffer, 0, read);
                        to.getOutputStream().flush();
                    }
                } catch (IOException closed) {
                    // one side went away
                } finally {
                    closeQuietly(from);
                    closeQuietly(to);
                }
            }, "restorer-it-redis-pump");
            thread.setDaemon(true);
            thread.start();
        }

        /** The Redis is away: nothing listens and every connection is closed. */
        void cut() {
            closeQuietly(server);
            sockets.forEach(RedisProxy::closeQuietly);
            sockets.clear();
        }

        @Override
        public void close() {
            cut();
        }

        private static void closeQuietly(AutoCloseable closeable) {
            try {
                if (closeable != null) {
                    closeable.close();
                }
            } catch (Exception ignored) {
                // closing is all that is asked
            }
        }
    }

    // ----- Redis -----

    /** The Redis of the test, reached as a client of its own; it is emptied here, so never the usual port of a developer's Redis. */
    private static final class RedisServer implements AutoCloseable {

        private final LettuceConnectionFactory factory;
        private final StringRedisTemplate strings;
        private final int port;

        private RedisServer(LettuceConnectionFactory factory, StringRedisTemplate strings, int port) {
            this.factory = factory;
            this.strings = strings;
            this.port = port;
        }

        static RedisServer connect() {
            // a test that empties its Redis: TestStores refuses the port a developer's own Redis listens on
            TestStores.Redis store = TestStores.disposableRedis();
            LettuceConnectionFactory factory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(store.host(), store.port()));
            factory.afterPropertiesSet();
            StringRedisTemplate strings = new StringRedisTemplate(factory);
            strings.afterPropertiesSet();
            RedisServer server = new RedisServer(factory, strings, store.port());
            server.flushAll();
            return server;
        }

        int port() {
            return port;
        }

        void flushAll() {
            try (RedisConnection connection = factory.getConnection()) {
                connection.serverCommands().flushAll();
            }
        }

        /** The users whose BLOCK flag the store holds. */
        Set<String> blockedUsers() {
            Set<String> users = new TreeSet<>();
            Set<String> keys = strings.keys("*security:blocked:users:*");
            if (keys != null) {
                for (String key : keys) {
                    users.add(key.substring(key.indexOf("security:blocked:users:") + "security:blocked:users:".length()));
                }
            }
            return users;
        }

        @Override
        public void close() {
            flushAll();
            factory.destroy();
        }
    }

    // ----- the database -----

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
            String name = "contexa_restorer_" + UUID.randomUUID().toString().replace("-", "");
            TestDatabase database = new TestDatabase(base + "postgres", base + name, base + name + "_host", name,
                    username, password);
            try (Connection admin = DriverManager.getConnection(database.adminUrl, username, password);
                 Statement statement = admin.createStatement()) {
                statement.execute("create database " + name);
                statement.execute("create database " + name + "_host");
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

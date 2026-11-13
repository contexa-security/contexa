/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.springbootstartercontexa;

import com.zaxxer.hikari.HikariDataSource;
import io.contexa.contexacore.testsupport.TestStores;
import io.contexa.autoconfigure.core.scope.ContexaPackages;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.micrometer.core.instrument.MeterRegistry;
import org.assertj.core.api.SoftAssertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.sql.DataSource;
import java.lang.management.ManagementFactory;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The names an operator reads in the metrics, in JMX and in a thread dump stay the application's own when Contexa is added, and
 * what Contexa adds says it is Contexa's. A real application on a real port, the application's own pool and Contexa's on a real
 * PostgreSQL, and the live threads of the process read after the start, once alone and once with Contexa.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@Timeout(900)
class ContexaPoolAndThreadNamesIntegrationTest {

    private static final String HIKARI_POOL_NUMBER = "com.zaxxer.hikari.pool_number";
    private static final String HOST_DATABASE = "fx2_naming_host";
    private static final String CONTEXA_POOL = "contexa-db";
    private static final Pattern NUMBERS = Pattern.compile("[-#_ ]?\\d+");

    /**
     * Threads that come with Contexa and whose names a library or the JVM sets, with no way for Contexa to set them without changing
     * the pool itself. Each is said why; a thread that is neither the application's nor Contexa's by its name nor one of these fails the
     * test with its name.
     */
    private static final Map<String, String> NAMED_BY_OTHERS = Map.of(
            "^(C\\d? )?CompilerThread", "the JVM's compiler threads, started with the amount of code that runs",
            "^Attach Listener$|^Common-Cleaner$|^process reaper$|^Signal Dispatcher$", "the JVM's own",
            "^PostgreSQL-JDBC-", "the PostgreSQL driver's shared timer, one for all the connections of the process",
            "^spring-one-time-tokens-\\d+$", "Spring Security's purge of the JdbcOneTimeTokenService Contexa creates; Spring names it inside",
            "^redisson-(netty-|timer-)?\\d+-\\d+$", "Contexa's Redisson client: Redisson names its threads, its timer cannot be named",
            "^ThreadPoolTaskScheduler-\\d+$", "the scheduler Spring Kafka starts inside the container of Contexa's listener, one for each consumer");

    /** Names no pool can be told by: a thread of one of these that was not there before is never put down to the application. */
    private static final Set<String> NAMELESS = Set.of("Thread", "pool-thread", "ForkJoinPool.commonPool-worker", "ForkJoinPool-worker");

    private static String hostDatabaseUrl;

    @BeforeAll
    static void createTheApplicationsDatabase() throws SQLException {
        String contexaUrl = environment("CONTEXA_TEST_DB_URL");
        try (Connection connection = DriverManager.getConnection(contexaUrl, environment("CONTEXA_TEST_DB_USERNAME"),
                environment("CONTEXA_TEST_DB_PASSWORD"));
             Statement statement = connection.createStatement()) {
            try (ResultSet found = statement.executeQuery("SELECT 1 FROM pg_database WHERE datname = '" + HOST_DATABASE + "'")) {
                if (!found.next()) {
                    statement.execute("CREATE DATABASE " + HOST_DATABASE);
                }
            }
        }
        hostDatabaseUrl = contexaUrl.substring(0, contexaUrl.lastIndexOf('/') + 1) + HOST_DATABASE;
    }

    /**
     * Hikari numbers the pools it is not given a name for in the order they start, over the whole JVM. Contexa's pool used to take
     * the number first: the application's pool became the second, and its metrics, its JMX name and its threads were the other pool's.
     */
    @Test
    void theApplicationsPoolKeepsItsNameAndContexasPoolIsNamedContexa() throws Exception {
        int before = Integer.getInteger(HIKARI_POOL_NUMBER, 0);
        try (ConfigurableApplicationContext context = start(HostApplication.class, settings(false, false))) {
            DataSource contexa = context.getBean("contexaDataSource", DataSource.class);
            DataSource application = context.getBean(DataSource.class);
            try (Connection first = contexa.getConnection(); Connection second = application.getConnection()) {
                assertThat(first.isValid(5)).isTrue();
                assertThat(second.isValid(5)).isTrue();
            }
            String applicationPool = "HikariPool-" + (before + 1);
            assertThat(application.unwrap(HikariDataSource.class).getPoolName()).isEqualTo(applicationPool);
            assertThat(contexa.unwrap(HikariDataSource.class).getPoolName()).isEqualTo(CONTEXA_POOL);
            assertThat(Integer.getInteger(HIKARI_POOL_NUMBER, 0)).as("Contexa's pool takes no number of the JVM's").isEqualTo(before + 1);

            MeterRegistry registry = context.getBean(MeterRegistry.class);
            assertThat(registry.get("hikaricp.connections.max").tag("pool", applicationPool).gauge().value()).isEqualTo(10.0);
            assertThat(registry.get("hikaricp.connections.max").tag("pool", CONTEXA_POOL).gauge().value()).isEqualTo(48.0);

            MBeanServer server = ManagementFactory.getPlatformMBeanServer();
            assertThat(server.getAttribute(new ObjectName("com.zaxxer.hikari:type=PoolConfig (" + applicationPool + ")"), "MaximumPoolSize"))
                    .as("the JMX name of the application's pool is its own pool").isEqualTo(10);
            assertThat(server.queryNames(new ObjectName("com.zaxxer.hikari:type=Pool (" + CONTEXA_POOL + ")"), null))
                    .as("Contexa registers no management bean of its pool, as before").isEmpty();

            assertThat(liveThreadNames()).contains(applicationPool + ":housekeeper", CONTEXA_POOL + ":housekeeper");
        }
    }

    /**
     * An application that has no database of its own takes Contexa's as its data source: there is one pool, the application's, and it
     * keeps the name Hikari gives it, as before.
     */
    @Test
    void anApplicationWithoutADatabaseOfItsOwnKeepsHikarisNameForItsOnlyPool() throws Exception {
        List<String> settings = new ArrayList<>(settings(false, false).stream().filter(s -> !s.startsWith("spring.datasource.")).toList());
        settings.add("contexa.datasource.isolation.contexa-owned-application=true");
        // an application of Contexa's own stops at its start when it cannot decide (no model, no vector store); this test has neither
        settings.add("contexa.capability.mode=WARN");
        int before = Integer.getInteger(HIKARI_POOL_NUMBER, 0);
        try (ConfigurableApplicationContext context = start(HostApplication.class, settings)) {
            DataSource application = context.getBean(DataSource.class);
            assertThat(context.getBean("contexaDataSource")).isSameAs(application);
            try (Connection connection = application.getConnection()) {
                assertThat(connection.isValid(5)).isTrue();
            }
            assertThat(application.unwrap(HikariDataSource.class).getPoolName()).isEqualTo("HikariPool-" + (before + 1));
        }
    }

    @Test
    void contexasThreadsSayTheyAreContexasWhereContexaKeepsTheApplicationsSignIn() throws Exception {
        assertTheThreadNames(HostApplication.class, settings(false, false), CONTEXA_POOL + ":housekeeper");
    }

    @Test
    void contexasThreadsSayTheyAreContexasWhereContexaOwnsTheSignIn() throws Exception {
        assertTheThreadNames(ContexaOwnedApplication.class, settings(true, false), CONTEXA_POOL + ":housekeeper");
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_REDIS_PORT", matches = ".+")
    void contexasThreadsSayTheyAreContexasInTheDistributedModeWhereContexaKeepsTheApplicationsSignIn() throws Exception {
        assertTheThreadNames(HostApplication.class, settings(false, true), CONTEXA_POOL + ":housekeeper", "contexa-security-event-collector-");
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_REDIS_PORT", matches = ".+")
    void contexasThreadsSayTheyAreContexasInTheDistributedModeWhereContexaOwnsTheSignIn() throws Exception {
        assertTheThreadNames(ContexaOwnedApplication.class, settings(true, true), CONTEXA_POOL + ":housekeeper", "contexa-security-event-collector-");
    }

    private void assertTheThreadNames(Class<?> application, List<String> settings, String... contexasExpected) throws Exception {
        Set<String> alone = applicationAlone(application, settings);

        Set<Thread> before = Thread.getAllStackTraces().keySet();
        Map<String, String> executors;
        HostWork work;
        try (ConfigurableApplicationContext context = start(application, settings)) {
            work = context.getBean(HostWork.class);
            exerciseTheApplication(context, work);
            executors = runOnEveryExecutorOfContexa(context);
            List<String> added = threadsStartedSince(before);

            // Contexa makes a Lettuce client of its own only for an application without a Redis connection; otherwise its connections use
            // the application's client, whose threads are the application's (the application alone starts its timer already)
            boolean applicationsLettuce = !context.containsBean("contexaClientResources") && alone.contains("lettuce-timer");
            Map<String, String> unexplained = new TreeMap<>();
            for (String name : added) {
                String pool = pool(name);
                boolean theApplications = alone.contains(pool) && !NAMELESS.contains(pool)
                        || applicationsLettuce && name.startsWith("lettuce-");
                if (theApplications || isContexas(name) || namedByOthers(name)) {
                    continue;
                }
                unexplained.put(name, pool);
            }
            SoftAssertions.assertSoftly(softly -> {
                softly.assertThat(executors).as("the executors of Contexa that were found").isNotEmpty();
                softly.assertThat(executors).as("the thread each executor of Contexa ran a task on")
                        .allSatisfy((bean, thread) -> assertThat(thread).startsWith("contexa-"));
                softly.assertThat(unexplained).as("threads that are neither the application's nor Contexa's by their name; the application alone had "
                        + alone + "; all the threads started with Contexa were " + added).isEmpty();
                softly.assertThat(work.asyncThreads()).as("the application's @Async").isNotEmpty()
                        .allSatisfy(name -> assertThat(name).startsWith("task-"));
                softly.assertThat(work.scheduledThreads()).as("the application's @Scheduled").isNotEmpty()
                        .allSatisfy(name -> assertThat(name).startsWith("scheduling-"));
                softly.assertThat(added.stream().map(ContexaPoolAndThreadNamesIntegrationTest::pool).collect(Collectors.toSet()))
                        .as("the application's own pools are there under their names").contains("HikariPool:housekeeper", "task", "scheduling");
                for (String expected : contexasExpected) {
                    softly.assertThat(added).as("a thread of Contexa's that this layout starts").anyMatch(name -> name.startsWith(expected));
                }
            });
        }
    }

    /** The application without Contexa: the pools of the threads it starts, read the same way. */
    private Set<String> applicationAlone(Class<?> application, List<String> settings) throws Exception {
        List<String> off = new ArrayList<>(settings);
        off.add("contexa.enabled=false");
        Set<Thread> before = Thread.getAllStackTraces().keySet();
        try (ConfigurableApplicationContext context = start(application, off)) {
            HostWork work = context.getBean(HostWork.class);
            exerciseTheApplication(context, work);
            List<String> added = threadsStartedSince(before);
            assertThat(added).as("the application alone starts no thread named for Contexa").noneMatch(name -> name.startsWith("contexa"));
            assertThat(work.asyncThreads()).allSatisfy(name -> assertThat(name).startsWith("task-"));
            assertThat(work.scheduledThreads()).allSatisfy(name -> assertThat(name).startsWith("scheduling-"));
            return added.stream().map(ContexaPoolAndThreadNamesIntegrationTest::pool).collect(Collectors.toCollection(TreeSet::new));
        }
    }

    private void exerciseTheApplication(ConfigurableApplicationContext context, HostWork work) throws Exception {
        int port = ((ServletWebServerApplicationContext) context).getWebServer().getPort();
        HttpClient client = HttpClient.newHttpClient();
        for (int i = 0; i < 5; i++) {
            client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/host/ping")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
        }
        try (Connection connection = context.getBean(DataSource.class).getConnection()) {
            assertThat(connection.isValid(5)).isTrue();
        }
        work.inBackground().get(30, TimeUnit.SECONDS);
        long until = System.currentTimeMillis() + 10_000;
        while (work.scheduledThreads().isEmpty() && System.currentTimeMillis() < until) {
            Thread.sleep(100);
        }
        Thread.sleep(2000);
    }

    /** Every executor and scheduler Contexa defines runs one task, so that a pool which starts its threads on demand shows them. */
    private Map<String, String> runOnEveryExecutorOfContexa(ConfigurableApplicationContext context) throws Exception {
        ConfigurableListableBeanFactory beans = context.getBeanFactory();
        Map<String, String> ranOn = new TreeMap<>();
        Set<String> names = new TreeSet<>();
        names.addAll(Arrays.asList(beans.getBeanNamesForType(Executor.class, false, false)));
        names.addAll(Arrays.asList(beans.getBeanNamesForType(TaskScheduler.class, false, false)));
        for (String name : names) {
            if (!beans.containsBeanDefinition(name) || !ownedByContexa(beans.getBeanDefinition(name), beans.getType(name))) {
                continue;
            }
            Object bean = beans.getBean(name);
            CompletableFuture<String> thread = new CompletableFuture<>();
            Runnable task = () -> thread.complete(Thread.currentThread().getName());
            if (bean instanceof TaskScheduler scheduler) {
                scheduler.schedule(task, Instant.now());
            } else {
                ((Executor) bean).execute(task);
            }
            ranOn.put(name, thread.get(30, TimeUnit.SECONDS));
        }
        return ranOn;
    }

    private static boolean ownedByContexa(BeanDefinition definition, Class<?> type) {
        return ContexaPackages.owns(type) || ContexaPackages.owns(definition.getBeanClassName())
                || ContexaPackages.owns(definition.getFactoryBeanName());
    }

    /** Contexa's threads start with "contexa-", those Hikari starts for Contexa's pool too: they carry the pool's name ("contexa-db:housekeeper"). */
    private static boolean isContexas(String name) {
        return name.startsWith("contexa-");
    }

    private static boolean namedByOthers(String name) {
        return NAMED_BY_OTHERS.keySet().stream().anyMatch(pattern -> Pattern.compile(pattern).matcher(name).find());
    }

    /** The pool of a thread is its name without its numbers, as a thread dump is read. */
    private static String pool(String name) {
        String pool = NUMBERS.matcher(name).replaceAll("");
        return pool.isEmpty() ? name : pool;
    }

    private static List<String> threadsStartedSince(Set<Thread> before) {
        Set<Thread> known = Collections.newSetFromMap(new IdentityHashMap<>());
        known.addAll(before);
        return Thread.getAllStackTraces().keySet().stream()
                .filter(thread -> thread.isAlive() && !known.contains(thread))
                .map(Thread::getName)
                .sorted()
                .toList();
    }

    private static List<String> liveThreadNames() {
        return Thread.getAllStackTraces().keySet().stream().filter(Thread::isAlive).map(Thread::getName).sorted().toList();
    }

    private List<String> settings(boolean contexaOwnsTheSignIn, boolean distributed) {
        List<String> settings = new ArrayList<>(List.of(
                "spring.datasource.url=" + hostDatabaseUrl,
                "spring.datasource.username=" + environment("CONTEXA_TEST_DB_USERNAME"),
                "spring.datasource.password=" + environment("CONTEXA_TEST_DB_PASSWORD"),
                "spring.datasource.hikari.register-mbeans=true",
                "contexa.datasource.url=" + environment("CONTEXA_TEST_DB_URL"),
                "contexa.datasource.username=" + environment("CONTEXA_TEST_DB_USERNAME"),
                "contexa.datasource.password=" + environment("CONTEXA_TEST_DB_PASSWORD"),
                "contexa.saas.enabled=false",
                "contexa.ai.security.mode=" + (contexaOwnsTheSignIn ? SecurityMode.FULL : SecurityMode.SANDBOX)));
        if (contexaOwnsTheSignIn) {
            settings.addAll(List.of(
                    "contexa.iam.seed.admin.username=admin",
                    "contexa.iam.seed.admin.password=Naming-admin-Password-1!",
                    "contexa.iam.seed.admin.email=admin@naming.test"));
        }
        if (distributed) {
            settings.addAll(List.of(
                    "contexa.infrastructure.mode=distributed",
                    "spring.data.redis.host=" + TestStores.redis().host(),
                    "spring.data.redis.port=" + TestStores.redis().port(),
                    "spring.kafka.bootstrap-servers=127.0.0.1:1"));
        } else {
            settings.add("contexa.infrastructure.mode=standalone");
        }
        return settings;
    }

    private static ConfigurableApplicationContext start(Class<?> application, List<String> settings) {
        List<String> properties = new ArrayList<>(List.of("spring.main.banner-mode=off", "server.port=0"));
        properties.addAll(settings);
        return new SpringApplicationBuilder(application)
                .web(WebApplicationType.SERVLET)
                .properties(properties.toArray(new String[0]))
                .run();
    }

    private static String environment(String name) {
        String value = System.getenv(name);
        assertThat(value).as(name).isNotBlank();
        return value;
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    static class HostApplication extends HostBeans {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll()).build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class ContexaOwnedApplication extends HostBeans {
    }

    /** Inherited, not imported: an import of a class under io.contexa goes through Contexa's auto-configuration filter. */
    @EnableAsync
    @EnableScheduling
    abstract static class HostBeans {

        @Bean
        HostWork hostWork() {
            return new HostWork();
        }

        @Bean
        PingController pingController() {
            return new PingController();
        }
    }

    @RestController
    static class PingController {

        @GetMapping("/host/ping")
        String ping() {
            return "the application answers";
        }
    }

    /** The application's own @Async and @Scheduled work, which runs on the application's executor and scheduler. */
    static class HostWork {

        private final List<String> asyncThreads = new CopyOnWriteArrayList<>();
        private final Set<String> scheduledThreads = ConcurrentHashMap.newKeySet();

        @Async
        public CompletableFuture<String> inBackground() {
            asyncThreads.add(Thread.currentThread().getName());
            return CompletableFuture.completedFuture(Thread.currentThread().getName());
        }

        @Scheduled(fixedDelay = 200)
        public void everyFewMoments() {
            scheduledThreads.add(Thread.currentThread().getName());
        }

        public List<String> asyncThreads() {
            return asyncThreads;
        }

        public Set<String> scheduledThreads() {
            return scheduledThreads;
        }
    }
}

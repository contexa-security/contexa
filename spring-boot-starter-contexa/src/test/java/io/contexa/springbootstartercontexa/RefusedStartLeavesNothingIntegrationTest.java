/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.springbootstartercontexa;

import com.legacyshop.importedsecurity.ImportedHostSecurity;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.operating.ContexaOperatingProfileException;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * A start refused because the application keeps a chain of its own where Contexa owns the sign-in leaves nothing in the
 * database: on a real PostgreSQL, a database of its own for each test, the refused start opened no connection to it and
 * left no table of Contexa's, also where the application and Contexa share the database. The refusal says what it said.
 * A start that is not refused still starts, and starts as it did; what the check cannot be certain of is refused as before.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@Timeout(300)
class RefusedStartLeavesNothingIntegrationTest {

    private static final String PROBLEM_BEFORE = "Contexa owns the sign-in of this application, but the application declares its own"
            + " security chain(s) [";
    private static final String PROBLEM_AFTER = "]. Contexa's chain takes every request first, so they would never run and what"
            + " they protect would be open.";
    private static final String ACTION = "For an application that keeps its sign-in, use @EnableAISecurity without mode = FULL."
            + " For a new application whose sign-in Contexa owns, remove those chains.";
    private static final String CHECK = "contexaOwnedChainDefinitionCheck";
    private static final String WITHOUT_THE_CHECK = "withoutTheDefinitionCheck";

    private String database;
    private final List<String> dataSources = new CopyOnWriteArrayList<>();

    @BeforeEach
    void aDatabaseOfItsOwn() throws SQLException {
        database = "fx7_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        try (Connection admin = admin(); Statement statement = admin.createStatement()) {
            statement.execute("create database " + database);
        }
    }

    @AfterEach
    void dropIt() throws SQLException {
        try (Connection admin = admin(); Statement statement = admin.createStatement()) {
            statement.execute("drop database if exists " + database + " with (force)");
        }
    }

    @Test
    void aChainOfTheApplicationClassIsRefusedBeforeTheDatabase() throws Exception {
        assertRefusedBeforeTheDatabase(start(ChainInTheApplicationClass.class), "hostChain");
    }

    @Test
    void aChainBuiltStatementByStatementIsRefusedBeforeTheDatabase() throws Exception {
        assertRefusedBeforeTheDatabase(start(ChainBuiltStatementByStatement.class), "hostChain");
    }

    @Test
    void aChainOnlyWhenMissingIsRefusedBeforeTheDatabase() throws Exception {
        assertRefusedBeforeTheDatabase(start(ChainOnlyWhenMissing.class), "hostChain");
    }

    @Test
    void anImportedChainIsRefusedBeforeTheDatabase() throws Exception {
        assertRefusedBeforeTheDatabase(start(ChainImported.class), "importedChain");
    }

    @Test
    void aChainOfAnotherConfigurationIsRefusedBeforeTheDatabase() throws Exception {
        assertRefusedBeforeTheDatabase(start(List.of(ContexaOwnedApplication.class, AnotherSecurityConfiguration.class), List.of()),
                "anotherChain");
    }

    @Test
    void anInheritedChainIsRefusedBeforeTheDatabase() throws Exception {
        assertRefusedBeforeTheDatabase(start(ChainInherited.class), "inheritedChain");
    }

    /** The database the application and Contexa share: Contexa's database serves the application, as without a chain. */
    @Test
    void theSharedDatabaseOfTheApplicationKeepsNoTable() throws Exception {
        assertRefusedBeforeTheDatabase(start(ChainInTheApplicationClass.class, "spring.datasource.url=" + url(database),
                "spring.datasource.username=" + user(), "spring.datasource.password=" + password()), "hostChain");
    }

    /** The application keeps a data source of its own on the database Contexa shares, as an approved trial does. */
    @Test
    void theSharedDatabaseOfTheApplicationsOwnDataSourceKeepsNoTable() throws Exception {
        assertRefusedBeforeTheDatabase(start(ChainInTheApplicationClass.class, "spring.datasource.url=" + url(database),
                "spring.datasource.username=" + user(), "spring.datasource.password=" + password(),
                "contexa.datasource.isolation.contexa-owned-application=false",
                "contexa.datasource.isolation.allow-shared-application-datasource=true",
                "contexa.datasource.isolation.shared-application-datasource-risk-accepted=true"), "hostChain");
    }

    /** The same start before: refused once every bean exists, after the schema was installed, with the same words. */
    @Test
    void beforeTheSameStartWasRefusedAfterTheSchemaWithTheSameWords() throws Exception {
        Throwable before = start(List.of(ChainInTheApplicationClass.class), List.of(withoutTheDefinitionCheck()));
        ContexaOperatingProfileException refused = refusal(before);

        assertThat(refused.getMessage()).isEqualTo(PROBLEM_BEFORE + "any request" + PROBLEM_AFTER);
        assertThat(refused.action()).isEqualTo(ACTION);
        assertThat(sessionsOfTheStart()).isPositive();
        assertThat(dataSources).isNotEmpty();
        assertThat(contexaTables()).isEqualTo(152);
    }

    /** Registered in code, the chain says nothing of what it builds: it is refused as before, once it is built. */
    @Test
    void aChainRegisteredInCodeIsRefusedAsBefore() throws Exception {
        ApplicationContextInitializer<ConfigurableApplicationContext> inCode = context -> ((GenericApplicationContext) context)
                .registerBean("codeChain", SecurityFilterChain.class, () -> {
                    try {
                        return context.getBean(HttpSecurity.class).authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                                .build();
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                });
        assertRefusedAsBefore(start(List.of(ContexaOwnedApplication.class), List.of(inCode)));
    }

    /** A chain returned on a condition may hold no filter, and such a chain is not refused: this one has filters. */
    @Test
    void aChainReturnedOnAConditionIsRefusedAsBeforeWhenItHasFilters() throws Exception {
        assertRefusedAsBefore(start(ChainOnACondition.class, "host.security.enabled=true"));
    }

    @Test
    void anApplicationWithACustomizerIsRefusedBeforeTheDatabase() throws Exception {
        assertRefusedBeforeTheDatabase(start(ChainWithACustomizer.class), "hostChain");
    }

    /** The debug filter of Spring Security is around its chain proxy, and the composite around both still gives the chains. */
    @Test
    void anApplicationWithTheDebugFilterIsRefusedBeforeTheDatabase() throws Exception {
        assertRefusedBeforeTheDatabase(start(ChainWithTheDebugFilter.class), "hostChain");
    }

    /** Before, the debug filter did not hide the chain from the later refusal either: the verdict is the one it was. */
    @Test
    void beforeTheDebugFilterHidNoChainFromTheLaterRefusal() throws Exception {
        assertRefusedAsBefore(start(List.of(ChainWithTheDebugFilter.class), List.of(withoutTheDefinitionCheck())));
    }

    /** The chain of the condition without filters signs nobody in: the start goes on, as it did, and Contexa is installed. */
    @Test
    void aChainWithoutFiltersStillStarts() throws Exception {
        try (ConfigurableApplicationContext context = run(List.of(ChainOnACondition.class), List.of(), "host.security.enabled=false")) {
            assertThat(context.containsBeanDefinition(CHECK)).isTrue();
            assertThat(contexaTables()).isEqualTo(152);
        }
    }

    /** No chain of the application: the start goes on, and the same request is answered as it was without the check. */
    @Test
    void anApplicationWithoutAChainStartsAsItDid() throws Exception {
        Answer after;
        Set<String> beansAfter;
        try (ConfigurableApplicationContext context = run(List.of(ContexaOwnedApplication.class), List.of())) {
            assertThat(context.containsBeanDefinition(CHECK)).isTrue();
            after = answer(context, "/host/ping");
            beansAfter = beanNames(context);
        }
        assertThat(contexaTables()).isEqualTo(152);
        dropIt();
        aDatabaseOfItsOwn();
        Answer before;
        Set<String> beansBefore;
        try (ConfigurableApplicationContext context = run(List.of(ContexaOwnedApplication.class), List.of(withoutTheDefinitionCheck()))) {
            assertThat(context.containsBeanDefinition(CHECK)).isFalse();
            before = answer(context, "/host/ping");
            beansBefore = beanNames(context);
        }
        beansAfter.remove(CHECK);
        beansBefore.remove(WITHOUT_THE_CHECK);

        assertThat(after).isEqualTo(before);
        assertThat(beansAfter).isEqualTo(beansBefore);
    }

    /** Where the application keeps its sign-in nothing of the check is there: the application's chain answers, as before. */
    @Test
    void anApplicationThatKeepsItsSignInStartsWithoutTheCheck() throws Exception {
        try (ConfigurableApplicationContext context = run(List.of(HostOwnedApplication.class), List.of(),
                "contexa.datasource.isolation.contexa-owned-application=true")) {
            assertThat(context.containsBeanDefinition(CHECK)).isFalse();
            Answer answer = answer(context, "/host/ping");
            assertThat(answer.status()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo("the application answers");
        }
        assertThat(contexaTables()).isEqualTo(152);
    }

    private void assertRefusedBeforeTheDatabase(Throwable failure, String chain) throws Exception {
        ContexaOperatingProfileException refused = refusal(failure);
        assertThat(refused.getMessage()).isEqualTo(PROBLEM_BEFORE + chain + PROBLEM_AFTER);
        assertThat(refused.action()).isEqualTo(ACTION);
        assertThat(sessionsOfTheStart()).isZero();
        assertThat(dataSources).isEmpty();
        assertThat(contexaTables()).isZero();
    }

    private void assertRefusedAsBefore(Throwable failure) throws Exception {
        ContexaOperatingProfileException refused = refusal(failure);
        assertThat(refused.getMessage()).isEqualTo(PROBLEM_BEFORE + "any request" + PROBLEM_AFTER);
        assertThat(refused.action()).isEqualTo(ACTION);
        assertThat(dataSources).isNotEmpty();
    }

    private static ContexaOperatingProfileException refusal(Throwable failure) {
        assertThat(failure).isNotNull();
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof ContexaOperatingProfileException refused) {
                return refused;
            }
        }
        throw new AssertionError("the start was not refused for its chain", failure);
    }

    private Throwable start(Class<?> application, String... settings) {
        return start(List.of(application), List.of(), settings);
    }

    private Throwable start(List<Class<?>> sources, List<ApplicationContextInitializer<ConfigurableApplicationContext>> initializers,
                            String... settings) {
        return catchThrowable(() -> run(sources, initializers, settings).close());
    }

    private ConfigurableApplicationContext run(List<Class<?>> sources,
                                               List<ApplicationContextInitializer<ConfigurableApplicationContext>> initializers,
                                               String... settings) {
        List<String> properties = new ArrayList<>(List.of("spring.main.banner-mode=off", "server.port=0",
                "contexa.datasource.url=" + url(database), "contexa.datasource.username=" + user(),
                "contexa.datasource.password=" + password(),
                // no model in these tests: the capability check reports it instead of stopping the start once every bean exists
                "contexa.capability.mode=WARN"));
        properties.addAll(Arrays.asList(settings));
        List<ApplicationContextInitializer<?>> all = new ArrayList<>(initializers);
        all.add(recorder());
        return new SpringApplicationBuilder(sources.toArray(new Class<?>[0]))
                .web(WebApplicationType.SERVLET)
                .initializers(all.toArray(new ApplicationContextInitializer<?>[0]))
                .properties(properties.toArray(new String[0]))
                .run();
    }

    /** Every data source the start creates, whether Contexa's or the application's. */
    private ApplicationContextInitializer<ConfigurableApplicationContext> recorder() {
        return context -> context.getBeanFactory().addBeanPostProcessor(new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (bean instanceof DataSource) {
                    dataSources.add(beanName);
                }
                return bean;
            }
        });
    }

    /** The start as it was before the check: its definition taken out once the configuration has been read. */
    private static ApplicationContextInitializer<ConfigurableApplicationContext> withoutTheDefinitionCheck() {
        return context -> ((GenericApplicationContext) context).registerBean(WITHOUT_THE_CHECK, WithoutTheCheck.class);
    }

    static class WithoutTheCheck implements BeanDefinitionRegistryPostProcessor {

        @Override
        public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
            if (registry.containsBeanDefinition(CHECK)) {
                registry.removeBeanDefinition(CHECK);
            }
        }

        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
        }
    }

    private record Answer(int status, String location, String body) {
    }

    private static Answer answer(ConfigurableApplicationContext context, String path) throws Exception {
        int port = ((ServletWebServerApplicationContext) context).getWebServer().getPort();
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        String location = response.headers().firstValue("Location").orElse("")
                .replaceAll("^http://127\\.0\\.0\\.1:\\d+", "").replaceAll(";jsessionid=[^?]*", "");
        return new Answer(response.statusCode(), location, response.statusCode() == 200 ? response.body() : "");
    }

    private static Set<String> beanNames(ConfigurableApplicationContext context) {
        return new TreeSet<>(Arrays.asList(context.getBeanDefinitionNames()));
    }

    private int contexaTables() throws SQLException {
        try (Connection connection = DriverManager.getConnection(url(database), user(), password());
             Statement statement = connection.createStatement();
             ResultSet count = statement.executeQuery(
                     "select count(*) from information_schema.tables where table_name like 'ctxa\\_%'")) {
            count.next();
            return count.getInt(1);
        }
    }

    /**
     * The sessions the start opened on the test's database, as the server counted them. A session is counted by the time
     * its process has ended, so the count is read until it stays the same; then one session of this method's own must add
     * one, which shows that the server counts sessions on this database at all.
     */
    private long sessionsOfTheStart() throws Exception {
        long counted = settledSessions();
        try (Connection own = DriverManager.getConnection(url(database), user(), password())) {
            assertThat(own.isValid(5)).isTrue();
        }
        long deadline = System.nanoTime() + 20_000_000_000L;
        while (sessions() <= counted && System.nanoTime() < deadline) {
            Thread.sleep(200);
        }
        assertThat(settledSessions()).as("the server counted this test's own session").isEqualTo(counted + 1);
        return counted;
    }

    private long settledSessions() throws Exception {
        long deadline = System.nanoTime() + 20_000_000_000L;
        long last = sessions();
        int unchanged = 0;
        while (unchanged < 8 && System.nanoTime() < deadline) {
            Thread.sleep(250);
            long now = sessions();
            unchanged = now == last ? unchanged + 1 : 0;
            last = now;
        }
        return last;
    }

    private long sessions() throws SQLException {
        try (Connection admin = admin();
             PreparedStatement statement = admin.prepareStatement("select sessions from pg_stat_database where datname = ?")) {
            statement.setString(1, database);
            try (ResultSet row = statement.executeQuery()) {
                return row.next() ? row.getLong(1) : 0L;
            }
        }
    }

    private static Connection admin() throws SQLException {
        return DriverManager.getConnection(System.getenv("CONTEXA_TEST_DB_URL"), user(), password());
    }

    private static String user() {
        return System.getenv("CONTEXA_TEST_DB_USERNAME");
    }

    private static String password() {
        return System.getenv("CONTEXA_TEST_DB_PASSWORD");
    }

    private static String url(String name) {
        String server = System.getenv("CONTEXA_TEST_DB_URL");
        int query = server.indexOf('?');
        String base = query >= 0 ? server.substring(0, query) : server;
        return base.substring(0, base.lastIndexOf('/') + 1) + name + (query >= 0 ? server.substring(query) : "");
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    @Import(HostController.class)
    static class ContexaOwnedApplication {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class ChainInTheApplicationClass {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated()).build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class ChainBuiltStatementByStatement {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            http.csrf(Customizer.withDefaults());
            http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated());
            http.formLogin(Customizer.withDefaults());
            return http.build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class ChainOnlyWhenMissing {

        @Bean
        @ConditionalOnMissingBean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated()).build();
        }
    }

    /** The imported class is the application's, outside Contexa's packages, as in an application. */
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    @Import(ImportedHostSecurity.class)
    static class ChainImported {
    }

    @Configuration(proxyBeanMethods = false)
    static class AnotherSecurityConfiguration {

        @Bean
        SecurityFilterChain anotherChain(HttpSecurity http) throws Exception {
            return http.httpBasic(Customizer.withDefaults()).build();
        }
    }

    abstract static class InheritedSecurity {

        @Bean
        SecurityFilterChain inheritedChain(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll()).build();
        }
    }

    @Configuration
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class ChainInherited extends InheritedSecurity {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class ChainOnACondition {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http, @Value("${host.security.enabled}") boolean enabled) throws Exception {
            if (enabled) {
                return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated()).build();
            }
            return new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE);
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class ChainWithACustomizer {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated()).build();
        }

        @Bean
        WebSecurityCustomizer hostCustomizer() {
            return web -> web.ignoring().requestMatchers("/static/**");
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class ChainWithTheDebugFilter {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated()).build();
        }

        @Bean
        WebSecurityCustomizer hostCustomizer() {
            return web -> web.debug(true);
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    @Import(HostController.class)
    static class HostOwnedApplication {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll()).build();
        }
    }

    @RestController
    static class HostController {

        @GetMapping("/host/ping")
        String ping() {
            return "the application answers";
        }
    }
}

/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.springbootstartercontexa;

import com.legacyshop.importedsecurity.ImportedHostSecurity;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacore.testsupport.TestStores;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
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
import org.springframework.security.web.UnreachableFilterChainException;
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
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * A start refused because the application keeps a chain of its own for every request where Contexa is the main security
 * configuration (mode FULL), however the application declares that chain: in its application class, statement by
 * statement, only when missing, imported, in another configuration, inherited, registered in code, returned on a
 * condition, beside a customizer or the debug filter, also where the application and Contexa share the database. On a
 * real PostgreSQL, a database of its own for each test.
 * <p>
 * Spring Security refuses such a chain while it builds its filter ({@link UnreachableFilterChainException}): Contexa's main
 * chain after it would never run. Spring Boot's failure analysis tells the refusal in Contexa's words, with the
 * application's chain by name and what to change (R-14 of docs/agent/운영모드-정상화-구현계획.md). The refusal comes after
 * Contexa's schema was installed, so the refused start leaves Contexa's complete schema, which the corrected start uses as
 * it is, and it leaves no connection open (judgment J of the plan). A chain narrowed with {@code securityMatcher}, no chain,
 * or mode SANDBOX starts.
 */
@ExtendWith(OutputCaptureExtension.class)
@Timeout(300)
@DisplayName("FULL의 모든 요청 앱 체인: 선언 방식과 상관없이 기동이 거부되고, Contexa 실패 분석이 앱 체인 이름과 바꿀 것을 안내한다")
class FullModeApplicationChainRefusalIntegrationTest {

    /** The tables of Contexa's schema, as a start installs them. */
    private static final int CONTEXA_TABLES = 117;

    private static final String REFUSAL_BEFORE = "With mode FULL Contexa's main chain takes every request, and the application"
            + " declares its own security chain(s) [";
    private static final String REFUSAL_AFTER = "] for every request as well. Spring Security runs no chain after one that"
            + " takes every request, so one of the two would never run.";
    private static final String ACTION = "Narrow the application's chain to the paths it protects, with http.securityMatcher(...):"
            + " it then runs ahead of Contexa's main chain. For an application whose own chain stays its main one, use"
            + " @EnableAISecurity without mode = FULL (SANDBOX).";
    private static final String ANSWER = "the application answers";

    private TestStores.Database server;
    private String database;
    private final List<String> dataSources = new CopyOnWriteArrayList<>();

    @BeforeEach
    void aDatabaseOfItsOwn() throws SQLException {
        server = TestStores.database();
        database = "fx7_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        try (Connection admin = admin(); Statement statement = admin.createStatement()) {
            statement.execute("create database " + database);
        }
    }

    @AfterEach
    void dropIt() throws SQLException {
        if (database == null) {
            return;
        }
        try (Connection admin = admin(); Statement statement = admin.createStatement()) {
            statement.execute("drop database if exists " + database + " with (force)");
        }
    }

    @Test
    @DisplayName("앱 클래스에 선언한 모든 요청 체인: 기동이 거부되고 Contexa 안내가 나온다")
    void aChainOfTheApplicationClassIsRefusedInContexasWords(CapturedOutput output) throws Exception {
        assertRefusedInContexasWords(start(ChainInTheApplicationClass.class), output, "hostChain");
    }

    @Test
    @DisplayName("문장마다 나눠 만든 모든 요청 체인: 기동이 거부되고 Contexa 안내가 나온다")
    void aChainBuiltStatementByStatementIsRefusedInContexasWords(CapturedOutput output) throws Exception {
        assertRefusedInContexasWords(start(ChainBuiltStatementByStatement.class), output, "hostChain");
    }

    @Test
    @DisplayName("@ConditionalOnMissingBean으로 선언한 모든 요청 체인: 기동이 거부되고 Contexa 안내가 나온다")
    void aChainOnlyWhenMissingIsRefusedInContexasWords(CapturedOutput output) throws Exception {
        assertRefusedInContexasWords(start(ChainOnlyWhenMissing.class), output, "hostChain");
    }

    @Test
    @DisplayName("앱이 다른 패키지에서 가져온 체인이 /api/** 로 좁혀져 있으면: 기동하고 그 경로는 앱 체인이 답한다")
    void anImportedNarrowedChainStartsAndAnswersItsOwnPaths() throws Exception {
        try (ConfigurableApplicationContext context = run(List.of(ChainImported.class), List.of())) {
            Answer answer = answer(context, "/api/orders");
            assertThat(answer.status()).isEqualTo(403);
        }
        assertThat(contexaTables()).isEqualTo(CONTEXA_TABLES);
    }

    @Test
    @DisplayName("다른 구성 클래스에 선언한 모든 요청 체인: 기동이 거부되고 Contexa 안내가 나온다")
    void aChainOfAnotherConfigurationIsRefusedInContexasWords(CapturedOutput output) throws Exception {
        assertRefusedInContexasWords(start(List.of(ContexaOwnedApplication.class, AnotherSecurityConfiguration.class),
                List.of()), output, "anotherChain");
    }

    @Test
    @DisplayName("상속한 구성의 모든 요청 체인: 기동이 거부되고 Contexa 안내가 나온다")
    void anInheritedChainIsRefusedInContexasWords(CapturedOutput output) throws Exception {
        assertRefusedInContexasWords(start(ChainInherited.class), output, "inheritedChain");
    }

    /** The database the application and Contexa share: Contexa's database serves the application, as without a chain. */
    @Test
    @DisplayName("앱과 Contexa가 같은 DB를 쓸 때도: 기동이 거부되고 Contexa 안내가 나온다")
    void onTheSharedDatabaseOfTheApplicationTheStartIsRefusedTheSameWay(CapturedOutput output) throws Exception {
        assertRefusedInContexasWords(start(ChainInTheApplicationClass.class, "spring.datasource.url=" + url(database),
                "spring.datasource.username=" + server.username(), "spring.datasource.password=" + server.password()),
                output, "hostChain");
    }

    /** The application keeps a data source of its own on the database Contexa shares, as an approved trial does. */
    @Test
    @DisplayName("앱이 Contexa와 같은 DB에 자기 데이터 소스를 둘 때도: 기동이 거부되고 Contexa 안내가 나온다")
    void onTheSharedDatabaseOfTheApplicationsOwnDataSourceTheStartIsRefusedTheSameWay(CapturedOutput output) throws Exception {
        assertRefusedInContexasWords(start(ChainInTheApplicationClass.class, "spring.datasource.url=" + url(database),
                "spring.datasource.username=" + server.username(), "spring.datasource.password=" + server.password(),
                "contexa.datasource.isolation.contexa-owned-application=false",
                "contexa.datasource.isolation.allow-shared-application-datasource=true",
                "contexa.datasource.isolation.shared-application-datasource-risk-accepted=true"), output, "hostChain");
    }

    /** Judgment J of the plan: the schema a refused start leaves is the one the start of the corrected application uses. */
    @Test
    @DisplayName("거부된 기동이 남긴 표 위에서, 체인을 securityMatcher로 좁힌 기동은 기동하고 그 표를 그대로 쓴다")
    void theCorrectedStartUsesTheSchemaTheRefusedStartLeft(CapturedOutput output) throws Exception {
        assertRefusedInContexasWords(start(ChainInTheApplicationClass.class), output, "hostChain");

        try (ConfigurableApplicationContext context = run(List.of(ChainNarrowed.class), List.of())) {
            Answer answer = answer(context, "/host/ping");
            assertThat(answer.status()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo(ANSWER);
        }
        assertThat(contexaTables()).isEqualTo(CONTEXA_TABLES);
    }

    /** Registered in code, the chain is a bean like any other, and Spring Security gives it by that name. */
    @Test
    @DisplayName("코드로 등록한 모든 요청 체인: 기동이 거부되고 Contexa 안내가 그 빈 이름을 넣는다")
    void aChainRegisteredInCodeIsRefusedInContexasWords(CapturedOutput output) throws Exception {
        ApplicationContextInitializer<ConfigurableApplicationContext> inCode = context -> ((GenericApplicationContext) context)
                .registerBean("codeChain", SecurityFilterChain.class, () -> {
                    try {
                        return context.getBean(HttpSecurity.class).authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                                .build();
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                });
        assertRefusedInContexasWords(start(List.of(ContexaOwnedApplication.class), List.of(inCode)), output, "codeChain");
    }

    @Test
    @DisplayName("조건에 따라 돌려주는 모든 요청 체인(필터 있음): 기동이 거부되고 Contexa 안내가 나온다")
    void aChainReturnedOnAConditionWithFiltersIsRefusedInContexasWords(CapturedOutput output) throws Exception {
        assertRefusedInContexasWords(start(ChainOnACondition.class, "host.security.enabled=true"), output, "hostChain");
    }

    /**
     * A chain for every request without a filter signs nobody in, but it still takes every request first: Contexa's main
     * chain after it would never run, and nothing of Contexa's would protect a request. It is refused as any other.
     */
    @Test
    @DisplayName("필터 없는 모든 요청 체인도 Contexa 주 체인을 가리므로: 기동이 거부되고 Contexa 안내가 나온다")
    void aChainWithoutFiltersIsRefusedInContexasWordsToo(CapturedOutput output) throws Exception {
        assertRefusedInContexasWords(start(ChainOnACondition.class, "host.security.enabled=false"), output, "hostChain");
    }

    @Test
    @DisplayName("WebSecurityCustomizer를 함께 둔 모든 요청 체인: 기동이 거부되고 Contexa 안내가 나온다")
    void anApplicationWithACustomizerIsRefusedInContexasWords(CapturedOutput output) throws Exception {
        assertRefusedInContexasWords(start(ChainWithACustomizer.class), output, "hostChain");
    }

    /** The debug filter of Spring Security is around its chain proxy; the chains are built, and refused, all the same. */
    @Test
    @DisplayName("Spring Security 디버그 필터를 켠 모든 요청 체인: 기동이 거부되고 Contexa 안내가 나온다")
    void anApplicationWithTheDebugFilterIsRefusedInContexasWords(CapturedOutput output) throws Exception {
        assertRefusedInContexasWords(start(ChainWithTheDebugFilter.class), output, "hostChain");
    }

    @Test
    @DisplayName("앱 체인이 없으면 FULL로 기동하고 Contexa 표를 설치한다")
    void anApplicationWithoutAChainStarts() throws Exception {
        try (ConfigurableApplicationContext context = run(List.of(ContexaOwnedApplication.class), List.of())) {
            assertThat(context.isActive()).isTrue();
        }
        assertThat(contexaTables()).isEqualTo(CONTEXA_TABLES);
    }

    /** Where the application keeps its sign-in (mode SANDBOX) its chain for every request stays its main one. */
    @Test
    @DisplayName("SANDBOX에서는 모든 요청 앱 체인이 그대로 앱의 주 체인이고 앱 체인이 답한다")
    void inModeSandboxTheApplicationsChainForEveryRequestStartsAndAnswers() throws Exception {
        try (ConfigurableApplicationContext context = run(List.of(HostOwnedApplication.class), List.of(),
                "contexa.datasource.isolation.contexa-owned-application=true")) {
            Answer answer = answer(context, "/host/ping");
            assertThat(answer.status()).isEqualTo(200);
            assertThat(answer.body()).isEqualTo(ANSWER);
        }
        assertThat(contexaTables()).isEqualTo(CONTEXA_TABLES);
    }

    private void assertRefusedInContexasWords(Throwable failure, CapturedOutput output, String chain) throws Exception {
        assertThat(failure).as("the start was not refused").isNotNull();
        UnreachableFilterChainException unreachable = cause(failure, UnreachableFilterChainException.class);
        assertThat(unreachable).as("Spring Security refused the application's chain").isNotNull();
        assertThat(unreachable.getFilterChain().toString()).contains("defined as '" + chain + "'");
        String reported = output.toString().replace("\r\n", "\n");
        assertThat(reported).contains("APPLICATION FAILED TO START",
                "Description:\n\n" + REFUSAL_BEFORE + chain + REFUSAL_AFTER + "\n", "Action:\n\n" + ACTION + "\n");

        int tables = contexaTables();
        long open = openSessions();
        System.out.println("REFUSED START LEAVES [chain=" + chain + ", ctxa tables=" + tables + ", open sessions=" + open
                + ", data sources created=" + dataSources + "]");
        assertThat(tables).as("the refused start leaves Contexa's complete schema, as judgment J records").isEqualTo(CONTEXA_TABLES);
        assertThat(open).as("the refused start closed every connection it opened").isZero();
    }

    private static <T extends Throwable> T cause(Throwable failure, Class<T> type) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (type.isInstance(cause)) {
                return type.cast(cause);
            }
        }
        return null;
    }

    private Throwable start(Class<?> application, String... settings) {
        return start(List.of(application), List.of(), settings);
    }

    private Throwable start(List<Class<?>> sources, List<ApplicationContextInitializer<ConfigurableApplicationContext>> initializers,
                            String... settings) {
        return catchThrowable(() -> run(sources, initializers, settings).close());
    }

    /**
     * The application on the test's database. No model is configured, so the capability check reports it instead of
     * stopping the start once every bean exists.
     */
    private ConfigurableApplicationContext run(List<Class<?>> sources,
                                               List<ApplicationContextInitializer<ConfigurableApplicationContext>> initializers,
                                               String... settings) {
        List<String> properties = new ArrayList<>(List.of("spring.main.banner-mode=off", "server.port=0",
                "contexa.datasource.url=" + url(database), "contexa.datasource.username=" + server.username(),
                "contexa.datasource.password=" + server.password(), "contexa.capability.mode=WARN"));
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

    private record Answer(int status, String body) {
    }

    private static Answer answer(ConfigurableApplicationContext context, String path) throws Exception {
        int port = ((ServletWebServerApplicationContext) context).getWebServer().getPort();
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return new Answer(response.statusCode(), response.statusCode() == 200 ? response.body() : "");
    }

    private int contexaTables() throws SQLException {
        try (Connection connection = DriverManager.getConnection(url(database), server.username(), server.password());
             Statement statement = connection.createStatement();
             ResultSet count = statement.executeQuery(
                     "select count(*) from information_schema.tables where table_name like 'ctxa\\_%'")) {
            count.next();
            return count.getInt(1);
        }
    }

    /**
     * The connections still open on the test's database, read from the server once they stop going away: a closed pool's
     * connections end a moment after it closes.
     */
    private long openSessions() throws Exception {
        long deadline = System.nanoTime() + 10_000_000_000L;
        long open = sessions();
        while (open > 0 && System.nanoTime() < deadline) {
            Thread.sleep(200);
            open = sessions();
        }
        return open;
    }

    private long sessions() throws SQLException {
        try (Connection admin = admin();
             PreparedStatement statement = admin.prepareStatement("select count(*) from pg_stat_activity where datname = ?")) {
            statement.setString(1, database);
            try (ResultSet row = statement.executeQuery()) {
                return row.next() ? row.getLong(1) : 0L;
            }
        }
    }

    private Connection admin() throws SQLException {
        return DriverManager.getConnection(server.url(), server.username(), server.password());
    }

    private String url(String name) {
        String url = server.url();
        int query = url.indexOf('?');
        String base = query >= 0 ? url.substring(0, query) : url;
        return base.substring(0, base.lastIndexOf('/') + 1) + name + (query >= 0 ? url.substring(query) : "");
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

    /** The application of {@link ChainInTheApplicationClass} with its chain narrowed to its paths, as the refusal asks. */
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    @Import(HostController.class)
    static class ChainNarrowed {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http.securityMatcher("/host/**").authorizeHttpRequests(requests -> requests.anyRequest().permitAll()).build();
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
            return ANSWER;
        }
    }
}

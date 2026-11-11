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
package io.contexa.springbootstartercontexa;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties.EnforcementMode;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsRuntimeApplier;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A protected method called without a signed-in user, on a real application on a real port with Contexa's database on a
 * real PostgreSQL. The application has one Spring Security chain of its own, for its token API under /h/jwt/** only;
 * its other pages are covered by no chain. Next to it runs the same application without Contexa, which says what the
 * application answers.
 * <p>
 * Where the operating mode decides on nobody (OBSERVE, DISABLED) the method runs and every answer is the one the
 * application gives without Contexa. Where it decides (SHADOW, ENFORCE) the call is refused: on a page no chain covers
 * with 401, never the container's 500; on the chain's path with the chain's own answer; where the application's advice
 * answers the refusal, with that answer; and a response the application had already sent stays its own.
 */
@Timeout(600)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class ProtectableCallWithoutAUserIntegrationTest {

    private static final String TOKEN_KEY = "a key of the test to sign its tokens, 256 bits long";
    private static final String REFUSAL_REGISTRATION = "contexaProtectableRefusalFilterRegistration";
    private static final String GUARD_POLICY = "integration-test: Guarded.read() for signed-in users";
    private static final List<String> PAGES = List.of("/h/m/secured", "/h/jwt/secured", "/h/advised", "/h/streamed");

    private static ConfigurableApplicationContext alone;
    private static ConfigurableApplicationContext withContexa;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER).build();

    @BeforeAll
    static void start() throws Exception {
        List<String> applicationDatabase = applicationDatabase();
        List<String> settings = new ArrayList<>(applicationDatabase);
        settings.add("contexa.enabled=false");
        alone = start(settings);
        settings = new ArrayList<>(applicationDatabase);
        settings.addAll(List.of(
                "contexa.datasource.url=" + System.getenv("CONTEXA_TEST_DB_URL"),
                "contexa.datasource.username=" + System.getenv("CONTEXA_TEST_DB_USERNAME"),
                "contexa.datasource.password=" + System.getenv("CONTEXA_TEST_DB_PASSWORD"),
                "contexa.security.zerotrust.mode=DISABLED"));
        withContexa = start(settings);
    }

    /** The application's own database, apart from Contexa's on the same server, as the application has one of its own. */
    private static List<String> applicationDatabase() throws Exception {
        String contexaDatabase = System.getenv("CONTEXA_TEST_DB_URL");
        String user = System.getenv("CONTEXA_TEST_DB_USERNAME");
        String password = System.getenv("CONTEXA_TEST_DB_PASSWORD");
        try (Connection connection = DriverManager.getConnection(contexaDatabase, user, password);
             Statement statement = connection.createStatement()) {
            boolean exists;
            try (ResultSet found = statement.executeQuery("SELECT 1 FROM pg_database WHERE datname = 'host_app'")) {
                exists = found.next();
            }
            if (!exists) {
                statement.execute("CREATE DATABASE host_app");
            }
        }
        int query = contexaDatabase.indexOf('?');
        String address = query < 0 ? contexaDatabase : contexaDatabase.substring(0, query);
        String applicationDatabase = address.substring(0, address.lastIndexOf('/') + 1) + "host_app"
                + (query < 0 ? "" : contexaDatabase.substring(query));
        return List.of("spring.datasource.url=" + applicationDatabase,
                "spring.datasource.username=" + user, "spring.datasource.password=" + password);
    }

    @AfterAll
    static void stop() {
        if (withContexa != null) {
            withContexa.close();
        }
        if (alone != null) {
            alone.close();
        }
    }

    private static ConfigurableApplicationContext start(List<String> settings) {
        List<String> properties = new ArrayList<>(List.of("spring.main.banner-mode=off", "server.port=0"));
        properties.addAll(settings);
        return new SpringApplicationBuilder(TokenApiApplication.class)
                .web(WebApplicationType.SERVLET)
                .properties(properties.toArray(new String[0]))
                .run();
    }

    /** As the system settings screen applies a saved mode. */
    private static void mode(EnforcementMode mode) {
        SecurityZeroTrustProperties properties = withContexa.getBean(SecurityZeroTrustProperties.class);
        SystemSettingsRuntimeApplier.applyZeroTrustSettings(properties, mode);
        assertThat(properties.getMode()).isEqualTo(mode);
    }

    private static int runs(ConfigurableApplicationContext context) {
        return context.getBean(Secured.class).runs();
    }

    /** Before any test changes the mode: the one the application's settings name. */
    @Test
    @Order(1)
    void theModeTheApplicationStartedWithDecidesOnNobody() throws Exception {
        assertThat(withContexa.getBean(SecurityZeroTrustProperties.class).getMode()).isEqualTo(EnforcementMode.DISABLED);

        assertAnsweredAsWithoutContexa();
    }

    /**
     * It runs ahead of the Spring Security filter, so on a path a chain covers that chain answers first, as it always
     * did; the application without Contexa has no such filter.
     */
    @Test
    void theAnswerToARefusalRunsAheadOfSpringSecurity() {
        FilterRegistrationBean<?> answer = withContexa.getBean(REFUSAL_REGISTRATION, FilterRegistrationBean.class);
        DelegatingFilterProxyRegistrationBean security = withContexa.getBean(DelegatingFilterProxyRegistrationBean.class);

        assertThat(answer.isEnabled()).isTrue();
        assertThat(answer.getOrder()).isEqualTo(security.getOrder() - 1);
        assertThat(answer.getUrlPatterns()).containsExactly("/*");
        assertThat(alone.containsBean(REFUSAL_REGISTRATION)).isFalse();
    }

    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"OBSERVE", "DISABLED"})
    void whereTheModeDecidesOnNobodyEveryAnswerIsTheApplicationsOwn(EnforcementMode mode) throws Exception {
        mode(mode);

        assertAnsweredAsWithoutContexa();
    }

    private void assertAnsweredAsWithoutContexa() throws Exception {
        for (String page : PAGES) {
            Answer expected = get(alone, page, null);
            int runs = runs(withContexa);

            Answer answer = get(withContexa, page, null);

            assertThat(expected.status()).as(page).isEqualTo(200);
            assertThat(answer.status()).as(page + ": " + answer.body()).isEqualTo(expected.status());
            assertThat(answer.body()).as(page).isEqualTo(expected.body());
            assertThat(runs(withContexa) - runs).as(page + ": the application's method ran").isEqualTo(1);
        }
    }

    /**
     * The method policies still decide where the mode decides on nobody: a visitor gets nothing a policy keeps from it.
     * The policy is stored in Contexa's database as the console stores one, and read back by Contexa.
     */
    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"OBSERVE", "DISABLED"})
    void theMethodPoliciesStillDecideOnAVisitor(EnforcementMode mode) throws Exception {
        mode(mode);
        keepGuardedForSignedInUsers();
        int runs = withContexa.getBean(Guarded.class).runs();

        Answer bare = get(withContexa, "/h/m/guarded", null);
        Answer chained = get(withContexa, "/h/jwt/guarded", null);
        Answer signedIn = get(withContexa, "/h/jwt/guarded", token("kim"));

        assertThat(bare.status()).as("no user at all for the policy to decide on: " + bare.body()).isEqualTo(401);
        assertThat(chained.status()).as(chained.body()).isEqualTo(401);
        assertThat(chained.wwwAuthenticate()).as("the policy refused the visitor, the chain answered").startsWith("Bearer");
        assertThat(signedIn.status()).isEqualTo(200);
        assertThat(signedIn.body()).isEqualTo("guarded for kim");
        assertThat(withContexa.getBean(Guarded.class).runs() - runs).as("only the signed-in user's call ran").isEqualTo(1);
        assertThat(get(alone, "/h/m/guarded", null).body()).as("without Contexa there is no such policy")
                .isEqualTo("guarded for nobody");
    }

    private static void keepGuardedForSignedInUsers() {
        PolicyRepository policies = withContexa.getBean(PolicyRepository.class);
        if (policies.findByName(GUARD_POLICY).isEmpty()) {
            Policy policy = Policy.builder().name(GUARD_POLICY).effect(Policy.Effect.ALLOW).priority(10)
                    .isActive(true).approvalStatus(Policy.ApprovalStatus.APPROVED).build();
            policy.getTargets().add(PolicyTarget.builder().policy(policy).targetType("METHOD")
                    .targetIdentifier(Guarded.class.getName() + ".read()").targetOrder(1).build());
            PolicyRule rule = PolicyRule.builder().policy(policy).build();
            rule.getConditions().add(PolicyCondition.builder().rule(rule).expression("isAuthenticated()").build());
            policy.getRules().add(rule);
            policies.save(policy);
        }
        withContexa.getBean(PolicyRetrievalPoint.class).clearMethodPoliciesCache();
    }

    /** The user of a token reaches the method as without Contexa: the same name, the same answer. */
    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"OBSERVE", "DISABLED"})
    void aSignedInUserIsTheSameUserInTheMethod(EnforcementMode mode) throws Exception {
        mode(mode);
        String token = token("kim");

        Answer expected = get(alone, "/h/jwt/secured", token);
        Answer answer = get(withContexa, "/h/jwt/secured", token);

        assertThat(expected.status()).isEqualTo(200);
        assertThat(expected.body()).isEqualTo("secured for kim");
        assertThat(answer.status()).isEqualTo(200);
        assertThat(answer.body()).isEqualTo(expected.body());
    }

    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"SHADOW", "ENFORCE"})
    void onAPageNoChainCoversTheRefusalIs401NotTheContainers500(EnforcementMode mode) throws Exception {
        mode(mode);
        int runs = runs(withContexa);

        Answer answer = get(withContexa, "/h/m/secured", null);

        assertThat(answer.status()).as(answer.body()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(answer.body()).as("the application's error answer, as a chain's refusal gets")
                .contains("\"status\":401").doesNotContain("Internal Server Error");
        assertThat(answer.wwwAuthenticate()).isNull();
        assertThat(runs(withContexa) - runs).as("the application's method did not run").isZero();
    }

    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"SHADOW", "ENFORCE"})
    void onTheChainsPathTheChainAnswersAsItAlwaysDid(EnforcementMode mode) throws Exception {
        mode(mode);
        int runs = runs(withContexa);

        Answer answer = get(withContexa, "/h/jwt/secured", null);

        assertThat(answer.status()).as(answer.body()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(answer.wwwAuthenticate()).as("the entry point of the application's token chain")
                .startsWith("Bearer");
        assertThat(runs(withContexa) - runs).isZero();
    }

    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"SHADOW", "ENFORCE"})
    void whereTheApplicationsAdviceAnswersTheRefusalItsAnswerStays(EnforcementMode mode) throws Exception {
        mode(mode);

        Answer answer = get(withContexa, "/h/advised", null);

        assertThat(answer.status()).isEqualTo(HttpStatus.I_AM_A_TEAPOT.value());
        assertThat(answer.body()).isEqualTo("the application answered AuthenticationCredentialsNotFoundException");
    }

    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"SHADOW", "ENFORCE"})
    void aResponseTheApplicationHadSentStaysItsOwn(EnforcementMode mode) throws Exception {
        mode(mode);

        Answer answer = get(withContexa, "/h/streamed", null);

        assertThat(answer.status()).isEqualTo(200);
        assertThat(answer.body()).startsWith("partial").doesNotContain("secured");
    }

    private Answer get(ConfigurableApplicationContext context, String path, String token) throws Exception {
        int port = ((ServletWebServerApplicationContext) context).getWebServer().getPort();
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .header("Accept", "application/json").timeout(Duration.ofSeconds(30)).GET();
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        HttpResponse<InputStream> response = http.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
        return new Answer(response.statusCode(), readWhatArrives(response.body()),
                response.headers().firstValue("WWW-Authenticate").orElse(null));
    }

    /** A response cut after the application had sent a part of it ends without its last chunk: what arrived is kept. */
    private static String readWhatArrives(InputStream body) {
        byte[] buffer = new byte[8192];
        StringBuilder read = new StringBuilder();
        try (body) {
            for (int count = body.read(buffer); count >= 0; count = body.read(buffer)) {
                read.append(new String(buffer, 0, count, StandardCharsets.UTF_8));
            }
        } catch (IOException cut) {
            return read.toString();
        }
        return read.toString();
    }

    private static String token(String subject) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
                .subject(subject).issueTime(new Date()).expirationTime(new Date(System.currentTimeMillis() + 600_000L))
                .build());
        jwt.sign(new MACSigner(TOKEN_KEY.getBytes(StandardCharsets.UTF_8)));
        return jwt.serialize();
    }

    private record Answer(int status, String body, String wwwAuthenticate) {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    static class TokenApiApplication extends HostBeans {
    }

    /** Inherited, not imported: an import of a class under io.contexa goes through Contexa's auto-configuration filter. */
    abstract static class HostBeans {

        /** The application's only chain: its token API. Its pages elsewhere are covered by no chain. */
        @Bean
        SecurityFilterChain tokenChain(HttpSecurity http) throws Exception {
            return http.securityMatcher("/h/jwt/**")
                    .authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
                    .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                    .build();
        }

        @Bean
        JwtDecoder jwtDecoder() {
            return NimbusJwtDecoder.withSecretKey(
                    new SecretKeySpec(TOKEN_KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256")).build();
        }

        @Bean
        Secured secured() {
            return new Secured();
        }

        @Bean
        Guarded guarded() {
            return new Guarded();
        }

        @Bean
        Pages pages(Secured secured, Guarded guarded) {
            return new Pages(secured, guarded);
        }

        @Bean
        AdvisedPages advisedPages(Secured secured) {
            return new AdvisedPages(secured);
        }

        @Bean
        AdvisedPagesAdvice advisedPagesAdvice() {
            return new AdvisedPagesAdvice();
        }
    }

    public static class Secured {

        private final AtomicInteger runs = new AtomicInteger();

        @Protectable
        public String read() {
            runs.incrementAndGet();
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            return "secured for " + (authentication != null ? authentication.getName() : "nobody");
        }

        public int runs() {
            return runs.get();
        }
    }

    /** A method a policy of Contexa's console keeps for signed-in users. */
    public static class Guarded {

        private final AtomicInteger runs = new AtomicInteger();

        @Protectable
        public String read() {
            runs.incrementAndGet();
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            return "guarded for " + (authentication != null ? authentication.getName() : "nobody");
        }

        public int runs() {
            return runs.get();
        }
    }

    @RestController
    static class Pages {

        private final Secured secured;
        private final Guarded guarded;

        Pages(Secured secured, Guarded guarded) {
            this.secured = secured;
            this.guarded = guarded;
        }

        @GetMapping("/h/m/secured")
        String page() {
            return secured.read();
        }

        @GetMapping("/h/jwt/secured")
        String tokenApi() {
            return secured.read();
        }

        @GetMapping("/h/m/guarded")
        String guardedPage() {
            return guarded.read();
        }

        @GetMapping("/h/jwt/guarded")
        String guardedTokenApi() {
            return guarded.read();
        }

        @GetMapping("/h/streamed")
        void streamed(HttpServletResponse response) throws IOException {
            response.setContentType("text/plain");
            response.getWriter().write("partial ");
            response.flushBuffer();
            response.getWriter().write(secured.read());
        }
    }

    @RestController
    static class AdvisedPages {

        private final Secured secured;

        AdvisedPages(Secured secured) {
            this.secured = secured;
        }

        @GetMapping("/h/advised")
        String advised() {
            return secured.read();
        }
    }

    @RestControllerAdvice(assignableTypes = AdvisedPages.class)
    static class AdvisedPagesAdvice {

        @ExceptionHandler(AuthenticationException.class)
        ResponseEntity<String> refused(AuthenticationException refusal) {
            return ResponseEntity.status(HttpStatus.I_AM_A_TEAPOT)
                    .body("the application answered " + refusal.getClass().getSimpleName());
        }
    }
}

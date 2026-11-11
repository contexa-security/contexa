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

import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaiam.admin.web.auth.service.VerificationCoverageService;
import io.contexa.contexaidentity.security.webauthn.PasskeyLibrary;
import io.contexa.contexaidentity.security.zerotrust.stepup.ContexaPasskeyStores;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCose;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An application that keeps its own sign-in (HOST_OWNED) on a real servlet container and a real PostgreSQL, with a mail
 * server of the test's own, on a class path with webauthn4j ({@link HostOwnedPasskeyLibraryIntegrationTest}) and on one
 * without it ({@link HostOwnedWithoutPasskeyLibraryClasspathTest}). The same requests are made on both: what the
 * application answers on its own, and what a user whose only registered way to answer a CHALLENGE is a passkey sees on
 * the step-up page. Without webauthn4j the application starts and says why passkeys are off, Spring MVC does not take
 * CBOR in, the page does not offer a passkey that cannot be verified, and the mailed code answers as before.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@ExtendWith(OutputCaptureExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Timeout(600)
abstract class HostOwnedPasskeyLibraryScenario {

    private static final String HOST_USER = "alice";
    private static final String HOST_PASSWORD = "host-secret";
    private static final String ADDRESS = "alice@corp.example.test";
    private static final Pattern CODE = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final String STEP_UP = "/contexa/step-up";

    private static String database;
    private static String hostDatabase;
    private static FakeSmtpServer mail;
    private static ConfigurableApplicationContext application;
    private static String base;
    private static boolean library;
    private static Users copy;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER).build();

    @BeforeAll
    static void start() throws Exception {
        library = PasskeyLibrary.available(HostOwnedPasskeyLibraryScenario.class.getClassLoader());
        database = "contexa_pk_" + UUID.randomUUID().toString().replace("-", "");
        hostDatabase = database + "_host";
        administer("create database " + database);
        administer("create database " + hostDatabase);
        mail = new FakeSmtpServer();
        application = new SpringApplicationBuilder(Host.class)
                .web(WebApplicationType.SERVLET)
                .properties("spring.main.banner-mode=off", "server.port=0",
                        "contexa.infrastructure.mode=standalone",
                        "contexa.saas.enabled=false",
                        "contexa.security.zerotrust.mode=DISABLED",
                        "spring.datasource.url=" + databaseUrl(hostDatabase),
                        "spring.datasource.username=" + System.getenv("CONTEXA_TEST_DB_USERNAME"),
                        "spring.datasource.password=" + System.getenv("CONTEXA_TEST_DB_PASSWORD"),
                        "contexa.datasource.url=" + databaseUrl(database),
                        "contexa.datasource.username=" + System.getenv("CONTEXA_TEST_DB_USERNAME"),
                        "contexa.datasource.password=" + System.getenv("CONTEXA_TEST_DB_PASSWORD"),
                        "spring.mail.host=127.0.0.1",
                        "spring.mail.port=" + mail.port())
                .run();
        base = "http://127.0.0.1:" + ((ServletWebServerApplicationContext) application).getWebServer().getPort();
    }

    @AfterAll
    static void stop() throws Exception {
        if (application != null) {
            application.close();
        }
        if (mail != null) {
            mail.close();
        }
        if (database != null) {
            administer("drop database if exists " + database + " with (force)");
            administer("drop database if exists " + hostDatabase + " with (force)");
        }
    }

    @Test
    @Order(1)
    void theApplicationStartsAndSaysWhyPasskeysAreOffOnlyWhenTheyAre(CapturedOutput output) {
        assertThat(application.isRunning()).isTrue();
        if (library) {
            assertThat(output.getOut()).doesNotContain("Passkeys are off");
        } else {
            assertThat(output.getOut()).contains("[Contexa] Passkeys are off", PasskeyLibrary.WEBAUTHN4J)
                    .doesNotContain("NoClassDefFoundError");
        }
    }

    @Test
    @Order(2)
    void theHostGetsCborOnlyWhenWebauthn4jBringsIt() throws Exception {
        boolean cborConverter = application.getBean(RequestMappingHandlerAdapter.class).getMessageConverters().stream()
                .anyMatch(converter -> converter.getClass().getSimpleName().contains("Cbor"));
        HttpResponse<String> json = get("/h/data", "application/json");
        HttpResponse<String> cbor = get("/h/data", "application/cbor");

        assertThat(json.statusCode()).as("what the application answers on its own").isEqualTo(200);
        assertThat(json.body()).contains("\"amount\":10");
        assertThat(cborConverter).as("the CBOR converter of Spring MVC").isEqualTo(library);
        assertThat(cbor.statusCode()).as("Accept: application/cbor").isEqualTo(library ? 200 : 406);
    }

    @Test
    @Order(3)
    void aUserWhoseOnlyWayIsAPasskeyIsOfferedItOnlyWhereItCanBeVerified() throws Exception {
        copyOfTheUser("alice@shadow.contexa.local");
        VerificationCoverageService coverage = application.getBean(VerificationCoverageService.class);
        long withoutFactor = coverage.usersWithoutFactor();
        registerPasskey(copy);
        challenge();

        HttpResponse<String> page = get(STEP_UP, "text/html");
        HttpResponse<String> options = post(STEP_UP + "/passkey/options", "", "application/json");

        assertThat(page.statusCode()).as(page.body()).isEqualTo(200);
        assertThat(page.body().contains("id=\"step-up-passkey\"")).as("the passkey button").isEqualTo(library);
        // the paragraph that says no way to verify is available (its text follows the locale, its colour does not)
        assertThat(page.body().contains("color: #fca5a5;")).as("the notice for a user without a way")
                .isEqualTo(!library);
        assertThat(options.statusCode()).as("the passkey challenge: " + options.body()).isEqualTo(library ? 200 : 400);
        // the operator's count of users who cannot answer: a passkey that cannot be verified is no way to answer
        assertThat(coverage.usersWithoutFactor()).as("users who cannot answer a CHALLENGE")
                .isEqualTo(library ? withoutFactor - 1 : withoutFactor);
    }

    @Test
    @Order(4)
    void theMailedCodeAnswersTheChallengeAsBefore() throws Exception {
        copyOfTheUser(ADDRESS);
        challenge();
        int mailed = mail.messages().size();

        HttpResponse<String> sent = post(STEP_UP + "/code", "", "application/json");
        assertThat(sent.statusCode()).as(sent.body()).isEqualTo(200);
        assertThat(sent.body()).contains("\"sent\":true");
        List<String> messages = mail.messages();
        assertThat(messages).hasSizeGreaterThan(mailed);
        Matcher code = CODE.matcher(FakeSmtpServer.body(messages.get(messages.size() - 1)));
        assertThat(code.find()).isTrue();

        HttpResponse<String> wrong = post(STEP_UP + "/code/verify", "code=" + UUID.randomUUID(),
                "application/x-www-form-urlencoded");
        assertThat(wrong.statusCode()).isEqualTo(400);
        assertThat(actionOfTheUser()).as("a wrong code releases nothing").isEqualTo(ZeroTrustAction.CHALLENGE);

        HttpResponse<String> verified = post(STEP_UP + "/code/verify", "code=" + code.group(),
                "application/x-www-form-urlencoded");
        assertThat(verified.statusCode()).as(verified.body()).isEqualTo(200);
        assertThat(verified.body()).contains("\"verified\":true");
        assertThat(actionOfTheUser()).isNotEqualTo(ZeroTrustAction.CHALLENGE);
    }

    // ----- the user and what is held for it -----

    /** The bridge's copy of the application's user, with the address a code goes to (or the one it makes up). */
    private void copyOfTheUser(String address) throws Exception {
        UserRepository users = application.getBean(UserRepository.class);
        get("/h/data", "application/json");
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        List<Users> copies = users.findByExternalSubjectIdAndBridgeManagedTrue(HOST_USER);
        while (copies.isEmpty() && System.nanoTime() < deadline) {
            Thread.sleep(200);
            copies = users.findByExternalSubjectIdAndBridgeManagedTrue(HOST_USER);
        }
        if (copies.isEmpty()) {
            users.saveAndFlush(Users.builder().username("brg_" + HOST_USER).name(HOST_USER).password("x")
                    .email(address).bridgeManaged(true).externalSubjectId(HOST_USER).build());
            copies = users.findByExternalSubjectIdAndBridgeManagedTrue(HOST_USER);
        }
        assertThat(copies).hasSize(1);
        copy = copies.get(0);
        try (Connection connection = DriverManager.getConnection(databaseUrl(database),
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("update ctxa_users set email = '" + address + "' where id = " + copy.getId());
        }
    }

    /** A passkey as the step-up's own registration leaves it in Contexa's tables; nothing here verifies it. */
    private void registerPasskey(Users user) {
        ContexaPasskeyStores stores = application.getBean(ContexaPasskeyStores.class);
        PublicKeyCredentialUserEntity entity = stores.userEntities().findByUsername(user.getUsername());
        if (entity == null) {
            entity = ImmutablePublicKeyCredentialUserEntity.builder().name(user.getUsername()).id(Bytes.random())
                    .displayName(HOST_USER).build();
            stores.userEntities().save(entity);
        }
        if (stores.userCredentials().findByUserId(entity.getId()).isEmpty()) {
            stores.userCredentials().save(ImmutableCredentialRecord.builder()
                    .credentialType(PublicKeyCredentialType.PUBLIC_KEY).credentialId(Bytes.random())
                    .userEntityUserId(entity.getId()).publicKey(new ImmutablePublicKeyCose(new byte[]{1, 2, 3}))
                    .signatureCount(0).label("test key").build());
        }
    }

    private void challenge() {
        application.getBean(ZeroTrustActionRepository.class).saveAction(HOST_USER, ZeroTrustAction.CHALLENGE, Map.of());
    }

    private ZeroTrustAction actionOfTheUser() {
        return application.getBean(ZeroTrustActionRepository.class).getActionFromHash(HOST_USER);
    }

    // ----- HTTP -----

    private HttpResponse<String> get(String path, String accept) throws Exception {
        return send(HttpRequest.newBuilder(URI.create(base + path)).header("Accept", accept)
                .timeout(Duration.ofSeconds(30)).GET());
    }

    private HttpResponse<String> post(String path, String body, String contentType) throws Exception {
        return send(HttpRequest.newBuilder(URI.create(base + path)).header("Accept", "application/json")
                .header("Content-Type", contentType).timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)));
    }

    private HttpResponse<String> send(HttpRequest.Builder request) throws Exception {
        request.header("Authorization", "Basic " + Base64.getEncoder()
                .encodeToString((HOST_USER + ":" + HOST_PASSWORD).getBytes(StandardCharsets.UTF_8)));
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static String databaseUrl(String name) {
        String url = System.getenv("CONTEXA_TEST_DB_URL");
        int query = url.indexOf('?');
        String path = query < 0 ? url : url.substring(0, query);
        return path.substring(0, path.lastIndexOf('/') + 1) + name + (query < 0 ? "" : url.substring(query));
    }

    private static void administer(String sql) throws Exception {
        try (Connection connection = DriverManager.getConnection(databaseUrl("postgres"),
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
             Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    /** The application: its own chain (basic sign-in, no CSRF), one user, one page. Contexa keeps its sign-in. */
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    static class Host {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return http.csrf(csrf -> csrf.disable())
                    .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                    .httpBasic(basic -> { })
                    .build();
        }

        @Bean
        UserDetailsService hostUsers() {
            return new InMemoryUserDetailsManager(User.withUsername(HOST_USER).password("{noop}" + HOST_PASSWORD)
                    .roles("USER").build());
        }

        @Bean
        Page page() {
            return new Page();
        }
    }

    @RestController
    static class Page {

        @GetMapping("/h/data")
        Map<String, Object> data() {
            return Map.of("user", HOST_USER, "amount", 10);
        }
    }
}

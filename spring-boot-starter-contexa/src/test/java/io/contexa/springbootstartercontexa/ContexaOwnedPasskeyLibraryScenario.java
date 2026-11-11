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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexaidentity.security.webauthn.PasskeyLibrary;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.Embedding;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingRequest;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.ai.vectorstore.pgvector.PgVectorStore;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;

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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contexa's own sign-in (FULL) on a real servlet container and a real PostgreSQL, with a mail server of the test's own,
 * on a class path with webauthn4j ({@link ContexaOwnedPasskeyLibraryIntegrationTest}) and on one without it
 * ({@link ContexaOwnedWithoutPasskeyLibraryClasspathTest}). The default MFA flow offers a passkey and a code; the same
 * requests are made on both. Without webauthn4j the application starts and says why passkeys are off, the flow offers
 * the code only, no passkey path answers with a server error, Spring MVC does not take CBOR in, and the password and the
 * mailed code sign in as before.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@ExtendWith(OutputCaptureExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Timeout(600)
abstract class ContexaOwnedPasskeyLibraryScenario {

    private static final String ADMIN = "admin";
    private static final String PASSWORD = "Passkey-Library-Check-2026!";
    private static final String ADDRESS = "admin@passkey-library.test";
    private static final String CODE_PAGE = "/mfa/challenge/ott";
    private static final Pattern CODE = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern CSRF_META = Pattern.compile("<meta name=\"_csrf\" content=\"([^\"]+)\"");
    private static final Pattern CSRF_INPUT = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"");
    private static final ObjectMapper JSON = new ObjectMapper();

    private static String database;
    private static FakeSmtpServer mail;
    private static ConfigurableApplicationContext application;
    private static String base;
    private static boolean library;

    @BeforeAll
    static void start() throws Exception {
        library = PasskeyLibrary.available(ContexaOwnedPasskeyLibraryScenario.class.getClassLoader());
        database = "contexa_pkf_" + UUID.randomUUID().toString().replace("-", "");
        administer("create database " + database);
        mail = new FakeSmtpServer();
        List<String> settings = new ArrayList<>(List.of(
                "spring.main.banner-mode=off",
                "server.port=0",
                "contexa.infrastructure.mode=standalone",
                "contexa.saas.enabled=false",
                "contexa.llm.selection.chat.mode=spring-primary",
                "contexa.llm.selection.embedding.mode=spring-primary",
                "contexa.datasource.url=" + databaseUrl(database),
                "contexa.datasource.username=" + System.getenv("CONTEXA_TEST_DB_USERNAME"),
                "contexa.datasource.password=" + System.getenv("CONTEXA_TEST_DB_PASSWORD"),
                "contexa.iam.seed.admin.username=" + ADMIN,
                "contexa.iam.seed.admin.password=" + PASSWORD,
                "contexa.iam.seed.admin.email=" + ADDRESS,
                "spring.mail.host=127.0.0.1",
                "spring.mail.port=" + mail.port()));
        String redisPort = System.getenv("CONTEXA_TEST_REDIS_PORT");
        if (redisPort != null) {
            settings.add("spring.data.redis.host=127.0.0.1");
            settings.add("spring.data.redis.port=" + redisPort);
        }
        application = new SpringApplicationBuilder(ContexaOwnedApplication.class)
                .web(WebApplicationType.SERVLET)
                .properties(settings.toArray(new String[0]))
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

        assertThat(cborConverter).as("the CBOR converter of Spring MVC").isEqualTo(library);
    }

    @Test
    @Order(3)
    void theFlowOffersThePasskeyOnlyWhereItCanBeVerified() throws Exception {
        Browser browser = new Browser();
        JsonNode signedIn = browser.password();

        // the default flow asks for one factor and offers the passkey first; without it the code is the first
        assertThat(signedIn.path("status").asText()).isEqualTo("MFA_REQUIRED");
        assertThat(signedIn.path("nextFactorType").asText()).as(signedIn.toString())
                .isEqualTo(library ? "MFA_PASSKEY" : "MFA_OTT");
    }

    @Test
    @Order(4)
    void noPasskeyPathEndsInAServerError() throws Exception {
        Browser browser = new Browser();
        browser.password();
        Map<String, Integer> statuses = new LinkedHashMap<>();
        for (String path : List.of("/webauthn/authenticate/options", "/webauthn/register/options",
                "/webauthn/register", "/login/mfa-webauthn")) {
            HttpResponse<String> answer = browser.postJson(path, "{}");
            statuses.put("POST " + path, answer.statusCode());
            assertThat(answer.statusCode()).as("POST " + path + ": " + answer.body()).isLessThan(500);
            if (!library) {
                assertThat(answer.statusCode() / 100).as("POST " + path + " is not served: " + answer.body())
                        .isNotEqualTo(2);
            }
        }
        HttpResponse<String> script = browser.get("/login/webauthn.js", "*/*");
        statuses.put("GET /login/webauthn.js", script.statusCode());
        assertThat(script.statusCode()).as(statuses.toString()).isLessThan(500);
        if (!library) {
            assertThat(script.statusCode() / 100).as(statuses.toString()).isNotEqualTo(2);
        }
    }

    @Test
    @Order(5)
    void thePasswordAndTheMailedCodeSignInAsBefore() throws Exception {
        Browser browser = new Browser();
        browser.password();
        browser.selectCode();
        int mailed = mail.messages().size();

        HttpResponse<String> sent = browser.sendCode();
        assertThat(sent.statusCode()).as(sent.body()).isEqualTo(302);
        assertThat(sent.headers().firstValue("Location")).hasValue(base + CODE_PAGE);
        List<String> messages = mail.messages();
        assertThat(messages).hasSizeGreaterThan(mailed);
        Matcher code = CODE.matcher(FakeSmtpServer.body(messages.get(messages.size() - 1)));
        assertThat(code.find()).isTrue();

        HttpResponse<String> verified = browser.verify(code.group());
        assertThat(verified.statusCode()).as(verified.body()).isEqualTo(200);
        assertThat(JSON.readTree(verified.body()).path("status").asText()).isEqualTo("MFA_COMPLETED");
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

    /** One person's browser through Contexa's sign-in, as contexa-mfa-sdk.js asks: password, the code factor, the code. */
    private static final class Browser {

        private final HttpClient http = HttpClient.newBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        private String csrf = "";
        private String mfaSession;
        private String step;

        JsonNode password() throws Exception {
            page("/mfa/login");
            HttpResponse<String> answer = post("/mfa/login", form(Map.of("username", ADMIN, "password", PASSWORD,
                    "_csrf", csrf)), "application/x-www-form-urlencoded");
            assertThat(answer.statusCode()).as(answer.body()).isEqualTo(200);
            return note(answer);
        }

        JsonNode selectCode() throws Exception {
            page("/mfa/select-factor");
            HttpResponse<String> answer = post("/mfa/select-factor",
                    JSON.writeValueAsString(Map.of("factorType", "MFA_OTT", "username", ADMIN)), "application/json");
            assertThat(answer.statusCode()).as(answer.body()).isEqualTo(200);
            return note(answer);
        }

        HttpResponse<String> sendCode() throws Exception {
            HttpResponse<String> answer = post("/mfa/ott/generate-code", form(Map.of("username", ADMIN)),
                    "application/x-www-form-urlencoded");
            note(answer);
            return answer;
        }

        HttpResponse<String> verify(String code) throws Exception {
            page(CODE_PAGE);
            HttpResponse<String> answer = post("/login/mfa-ott", form(Map.of("username", ADMIN, "token", code,
                    "_csrf", csrf)), "application/x-www-form-urlencoded");
            note(answer);
            return answer;
        }

        HttpResponse<String> get(String path, String accept) throws Exception {
            return http.send(HttpRequest.newBuilder(URI.create(base + path)).header("Accept", accept)
                            .timeout(Duration.ofSeconds(30)).GET().build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        }

        HttpResponse<String> postJson(String path, String body) throws Exception {
            return post(path, body, "application/json");
        }

        private void page(String path) throws Exception {
            HttpResponse<String> page = get(path, "text/html");
            for (Pattern pattern : List.of(CSRF_META, CSRF_INPUT)) {
                Matcher found = pattern.matcher(page.body());
                if (found.find()) {
                    csrf = found.group(1);
                    return;
                }
            }
        }

        private HttpResponse<String> post(String path, String body, String contentType) throws Exception {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                    .header("Accept", "application/json")
                    .header("Content-Type", contentType)
                    .header("X-Device-Id", "passkey-library-device")
                    .header("X-CSRF-TOKEN", csrf)
                    .timeout(Duration.ofSeconds(60))
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
            if (step != null) {
                request.header("X-MFA-Step-Id", step);
            }
            if (mfaSession != null) {
                request.header("X-MFA-Session-Id", mfaSession);
            }
            return http.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        }

        private JsonNode note(HttpResponse<String> answer) {
            JsonNode body;
            try {
                body = JSON.readTree(answer.body());
            } catch (Exception notJson) {
                return JSON.createObjectNode();
            }
            if (body == null || body.isMissingNode()) {
                return JSON.createObjectNode();
            }
            if (body.hasNonNull("mfaSessionId")) {
                mfaSession = body.get("mfaSessionId").asText();
            }
            if (body.hasNonNull("nextStepId")) {
                step = body.get("nextStepId").asText();
            }
            return body;
        }

        private static String form(Map<String, String> fields) {
            return new LinkedHashMap<>(fields).entrySet().stream()
                    .map(field -> URLEncoder.encode(field.getKey(), StandardCharsets.UTF_8) + "="
                            + URLEncoder.encode(field.getValue(), StandardCharsets.UTF_8))
                    .collect(Collectors.joining("&"));
        }
    }

    /**
     * Contexa owns the sign-in. Its decisions need a chat model and its own vector store: the models are the test's own
     * (no model server is called), the vector store is Contexa's real one on the test's PostgreSQL.
     */
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class ContexaOwnedApplication {

        private static final int DIMENSIONS = 384;

        @Bean
        ChatModel testChatModel() {
            return new ChatModel() {
                @Override
                public ChatResponse call(Prompt prompt) {
                    return new ChatResponse(List.of(new Generation(new AssistantMessage("no decision"))));
                }
            };
        }

        @Bean
        EmbeddingModel testEmbeddingModel() {
            return new EmbeddingModel() {
                @Override
                public EmbeddingResponse call(EmbeddingRequest request) {
                    List<Embedding> embeddings = new ArrayList<>();
                    List<String> texts = request.getInstructions();
                    for (int i = 0; i < texts.size(); i++) {
                        embeddings.add(new Embedding(vector(texts.get(i)), i));
                    }
                    return new EmbeddingResponse(embeddings);
                }

                @Override
                public float[] embed(Document document) {
                    return vector(document.getText());
                }

                @Override
                public int dimensions() {
                    return DIMENSIONS;
                }
            };
        }

        @Bean(name = "contexaVectorStore", defaultCandidate = false)
        PgVectorStore contexaVectorStore(@Qualifier("contexaJdbcTemplate") JdbcTemplate contexaJdbcTemplate,
                                         @Qualifier("contexaPrimaryEmbeddingModel") EmbeddingModel embeddingModel) {
            return PgVectorStore.builder(contexaJdbcTemplate, embeddingModel)
                    .dimensions(DIMENSIONS)
                    .initializeSchema(true)
                    .build();
        }

        private static float[] vector(String text) {
            float[] vector = new float[DIMENSIONS];
            vector[Math.floorMod(Objects.hashCode(text), DIMENSIONS)] = 1f;
            return vector;
        }
    }
}

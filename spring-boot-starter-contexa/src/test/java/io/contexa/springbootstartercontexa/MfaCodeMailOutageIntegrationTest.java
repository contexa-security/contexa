/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.springbootstartercontexa;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
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
import java.sql.ResultSet;
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
 * Contexa's own sign-in (FULL) on a real servlet container and a real PostgreSQL, with a mail server of the test's own:
 * a code asked for while the mail server is down, cuts the connection or keeps silent is answered as a service that is
 * unavailable, with what to do, and the flow stays where it was, so the same request sends the code once mail is back
 * and the sign-in ends. Given a throwaway PostgreSQL in CONTEXA_TEST_DB_URL (pgvector image).
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@ExtendWith(OutputCaptureExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Timeout(300)
class MfaCodeMailOutageIntegrationTest {

    private static final String ADMIN = "admin";
    private static final String PASSWORD = "Mail-Outage-Check-2026!";
    private static final String ADDRESS = "admin@mail-outage.test";
    private static final String CODE_PAGE = "/mfa/challenge/ott";
    private static final String NOT_SENT_MESSAGE = "The code could not be sent. Please try again in a moment.";
    // the six digits of an MFA step, or the long code of a sign-in by a code alone
    private static final Pattern CODE = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(?<![0-9])[0-9]{6}(?![0-9])");
    private static final Pattern CSRF_META = Pattern.compile("<meta name=\"_csrf\" content=\"([^\"]+)\"");
    private static final Pattern CSRF_INPUT = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"");
    private static final ObjectMapper JSON = new ObjectMapper();

    private static String database;
    private static FakeSmtpServer mail;
    private static ConfigurableApplicationContext application;
    private static String base;

    @BeforeAll
    static void start() throws Exception {
        database = "contexa_mail_" + UUID.randomUUID().toString().replace("-", "");
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
                "spring.mail.port=" + mail.port(),
                // the application's own limits: without them a silent mail server holds the request as long as it likes
                "spring.mail.properties.mail.smtp.connectiontimeout=2000",
                "spring.mail.properties.mail.smtp.timeout=2000",
                "spring.mail.properties.mail.smtp.writetimeout=2000"));
        String redisPort = System.getenv("CONTEXA_TEST_REDIS_PORT");
        if (redisPort != null) {
            // nothing here uses Redis (standalone); a Redis client made anyway reaches the test's own and no other
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
    void aCodeAskedForWithMailUpIsAnsweredAsBefore(CapturedOutput output) throws Exception {
        mail.mode(FakeSmtpServer.Mode.ANSWERS);
        SignIn signIn = new SignIn();
        signIn.password();
        signIn.selectCode();
        int mailed = mail.messages().size();

        HttpResponse<String> sent = signIn.sendCode();

        assertThat(sent.statusCode()).as(sent.body()).isEqualTo(302);
        assertThat(sent.headers().firstValue("Location")).hasValue(base + CODE_PAGE);
        assertThat(sent.body()).isEmpty();
        String code = codeOf(mail.messages(), mailed);
        HttpResponse<String> verified = signIn.verify(code);
        assertThat(verified.statusCode()).as(verified.body()).isEqualTo(200);
        assertThat(JSON.readTree(verified.body()).path("status").asText()).isEqualTo("MFA_COMPLETED");
        assertThat(output.getOut()).doesNotContain(code);
    }

    @Test
    @Order(2)
    void aCodeAskedForWhileMailIsBrokenIsUnavailableAndTheSameFlowSendsItOnceMailIsBack(CapturedOutput output)
            throws Exception {
        mail.mode(FakeSmtpServer.Mode.ANSWERS);
        SignIn signIn = new SignIn();
        signIn.password();
        JsonNode selected = signIn.selectCode();
        String state = selected.path("currentState").asText();
        int mailedBefore = mail.messages().size();
        List<String> answers = new ArrayList<>();

        mail.mode(FakeSmtpServer.Mode.DOWN);
        assertThat(mail.refuses()).as("the mail server is down").isTrue();
        answers.add(assertNotSent(signIn.sendCode(), state));

        mail.mode(FakeSmtpServer.Mode.CUTS);
        int reached = mail.connections();
        answers.add(assertNotSent(signIn.sendCode(), state));
        assertThat(mail.connections()).as("the mail server was reached and cut the connection").isGreaterThan(reached);

        mail.mode(FakeSmtpServer.Mode.SILENT);
        reached = mail.connections();
        long asked = System.nanoTime();
        answers.add(assertNotSent(signIn.sendCode(), state));
        assertThat(Duration.ofNanos(System.nanoTime() - asked)).as("the application's mail timeout ended the wait")
                .isLessThan(Duration.ofSeconds(30));
        assertThat(mail.connections()).as("the mail server was reached and said nothing").isGreaterThan(reached);
        assertThat(mail.messages()).as("no failed request mailed anything").hasSize(mailedBefore);

        // mail is back: the same flow asks again at once, and the failed requests held back no resend interval
        mail.mode(FakeSmtpServer.Mode.ANSWERS);
        HttpResponse<String> sent = signIn.sendCode();
        assertThat(sent.statusCode()).as(sent.body()).isEqualTo(302);
        assertThat(sent.headers().firstValue("Location")).hasValue(base + CODE_PAGE);
        String code = codeOf(mail.messages(), mailedBefore);
        HttpResponse<String> verified = signIn.verify(code);
        assertThat(verified.statusCode()).as(verified.body()).isEqualTo(200);
        assertThat(JSON.readTree(verified.body()).path("status").asText()).isEqualTo("MFA_COMPLETED");

        List<String> codes = new ArrayList<>(storedCodes());
        assertThat(codes).as("each request that failed left the code it made, unmailed, in the database").hasSize(3);
        codes.add(code);
        for (String secret : codes) {
            assertThat(output.getOut()).as("no code in the log").doesNotContain(secret);
            assertThat(answers).as("no code in an answer").noneMatch(answer -> answer.contains(secret));
        }
    }

    private static String assertNotSent(HttpResponse<String> answer, String state) throws Exception {
        assertThat(answer.statusCode()).as(answer.body()).isEqualTo(503);
        JsonNode body = JSON.readTree(answer.body());
        assertThat(body.path("error").asText()).isEqualTo("OTT_CODE_NOT_SENT");
        assertThat(body.path("message").asText()).isEqualTo(NOT_SENT_MESSAGE);
        assertThat(body.path("success").asBoolean(true)).isFalse();
        assertThat(body.path("currentState").asText()).as("the flow stays where it was").isEqualTo(state);
        assertThat(answer.body()).doesNotContain("Exception", "127.0.0.1:" + mail.port());
        return answer.body();
    }

    /** The code of the newest message, which came after the given number of messages. */
    private static String codeOf(List<String> messages, int before) {
        assertThat(messages).as("a message was mailed").hasSizeGreaterThan(before);
        String body = FakeSmtpServer.body(messages.get(messages.size() - 1));
        Matcher found = CODE.matcher(body);
        assertThat(found.find()).as(body).isTrue();
        return found.group();
    }

    /** Every code the database holds, mailed or not. */
    private static List<String> storedCodes() throws Exception {
        List<String> codes = new ArrayList<>();
        try (Connection connection = DriverManager.getConnection(databaseUrl(database),
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("select token_value from ctxa_one_time_tokens")) {
            while (rows.next()) {
                codes.add(rows.getString(1));
            }
        }
        return codes;
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
    private static final class SignIn {

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

        private void page(String path) throws Exception {
            HttpResponse<String> page = http.send(HttpRequest.newBuilder(URI.create(base + path))
                            .header("Accept", "text/html").timeout(Duration.ofSeconds(30)).GET().build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
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
                    .header("X-Device-Id", "mail-outage-device")
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
     * (no model server is called, and no answer of theirs is a decision), the vector store is Contexa's real one on the
     * test's PostgreSQL. A model or a store has nothing to do with how a code is mailed.
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

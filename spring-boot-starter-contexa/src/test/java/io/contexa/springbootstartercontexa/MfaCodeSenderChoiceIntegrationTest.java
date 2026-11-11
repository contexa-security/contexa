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
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
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
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.ServerSocket;
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
import java.util.TreeSet;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contexa's own sign-in (FULL) on a real servlet container, a real PostgreSQL and a real mail server (Mailpit, whose
 * address is given in CONTEXA_TEST_MAILPIT_API and its SMTP port in CONTEXA_TEST_MAILPIT_SMTP_PORT): the administrator
 * signs in with the password and the code from the mailbox, whether the application has no mail sender, one, or
 * several, and with {@code spring.mail.host} set or not. Given a throwaway PostgreSQL in CONTEXA_TEST_DB_URL (pgvector image).
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@ExtendWith(OutputCaptureExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Timeout(900)
class MfaCodeSenderChoiceIntegrationTest {

    private static final String ADMIN = "admin";
    private static final String PASSWORD = "Sender-Choice-Check-2026!";
    private static final String ADDRESS = "admin@sender-choice.test";
    private static final String CODE_PAGE = "/mfa/challenge/ott";
    private static final String NOT_SENT_MESSAGE = "The code could not be sent. Please try again in a moment.";
    private static final Pattern CODE = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern CSRF_META = Pattern.compile("<meta name=\"_csrf\" content=\"([^\"]+)\"");
    private static final Pattern CSRF_INPUT = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"");
    private static final ObjectMapper JSON = new ObjectMapper();

    /** The port the senders of the application are given: the mail server when they are to be used, a dead one when not. */
    private static int hostSenderPort;

    @Test
    @Order(1)
    @EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_MAILPIT_API", matches = ".+")
    void noSenderOfTheApplicationAndNoMailHostSendsNoCodeAndSaysWhy(CapturedOutput output) throws Exception {
        Mailpit.clear();
        try (Running app = start(0, false)) {
            assertThat(app.senderBeans()).isEmpty();
            SignIn signIn = new SignIn(app.base());
            signIn.password();
            signIn.selectCode();

            HttpResponse<String> sent = signIn.sendCode();

            assertThat(sent.statusCode()).as(sent.body()).isGreaterThanOrEqualTo(400);
            assertThat(Mailpit.messages()).as("nothing was mailed").isEmpty();
            assertThat(output.getAll()).contains("the application has no JavaMailSender and spring.mail.host is not set");
        }
    }

    @Test
    @Order(2)
    @EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_MAILPIT_API", matches = ".+")
    void noSenderOfTheApplicationAndAMailHostSignsInWithBootsSender(CapturedOutput output) throws Exception {
        try (Running app = start(0, true)) {
            assertThat(app.senderBeans()).as("what Spring Boot made from spring.mail.*").containsExactly("mailSender");
            signInWithTheCodeFromTheMailbox(app, output);
        }
    }

    @Test
    @Order(3)
    @EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_MAILPIT_API", matches = ".+")
    void oneSenderOfTheApplicationSignsInWithThatSenderWhetherOrNotAMailHostIsSet(CapturedOutput output) throws Exception {
        // spring.mail.host names a port nothing listens on: a code that went by a sender of Contexa's would not arrive
        try (Running app = start(1, true)) {
            assertThat(app.senderBeans()).containsExactly("hostMail");
            signInWithTheCodeFromTheMailbox(app, output);
            assertThat(app.sends("hostMail")).as("the application's own sender mailed the code").isEqualTo(1);
        }
        try (Running app = start(1, false)) {
            assertThat(app.senderBeans()).containsExactly("hostMail");
            signInWithTheCodeFromTheMailbox(app, output);
            assertThat(app.sends("hostMail")).isEqualTo(1);
        }
    }

    @Test
    @Order(4)
    @EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_MAILPIT_API", matches = ".+")
    void severalSendersOfTheApplicationAndAMailHostSignInWithASenderOfContexasOwn(CapturedOutput output) throws Exception {
        try (Running app = start(2, true)) {
            assertThat(app.senderBeans()).as("Contexa's sender is no bean: the application's types are as they were")
                    .containsExactly("mailA", "mailB");
            signInWithTheCodeFromTheMailbox(app, output);
            assertThat(app.sends("mailA")).as("none of the application's senders was used").isZero();
            assertThat(app.sends("mailB")).isZero();
        }
    }

    @Test
    @Order(5)
    @EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_MAILPIT_API", matches = ".+")
    void severalSendersOfTheApplicationAndNoMailHostSendNoCodeAndSayWhy(CapturedOutput output) throws Exception {
        Mailpit.clear();
        try (Running app = start(2, false)) {
            assertThat(app.senderBeans()).containsExactly("mailA", "mailB");
            SignIn signIn = new SignIn(app.base());
            signIn.password();
            signIn.selectCode();

            HttpResponse<String> sent = signIn.sendCode();

            assertThat(sent.statusCode()).as(sent.body()).isGreaterThanOrEqualTo(400);
            assertThat(Mailpit.messages()).as("nothing was mailed").isEmpty();
            assertThat(app.sends("mailA")).isZero();
            assertThat(app.sends("mailB")).isZero();
            assertThat(output.getAll()).contains("the application has several JavaMailSender beans [mailA, mailB]",
                    "spring.mail.host is not set");
        }
    }

    /**
     * The sender Contexa builds from spring.mail.* fails as the application's own does: a mail server that is down, cuts
     * the connection or keeps silent is answered as a service that is unavailable, within the limits spring.mail.* sets,
     * and the same flow sends the code once mail is back.
     */
    @Test
    @Order(6)
    void aMailServerThatFailsIsAnsweredAsUnavailableAlsoWithASenderOfContexasOwn(CapturedOutput output) throws Exception {
        try (FakeSmtpServer mail = new FakeSmtpServer();
             Running app = start(2, true, mail.port())) {
            SignIn signIn = new SignIn(app.base());
            signIn.password();
            JsonNode selected = signIn.selectCode();
            String state = selected.path("currentState").asText();
            int mailedBefore = mail.messages().size();
            List<String> answers = new ArrayList<>();

            mail.mode(FakeSmtpServer.Mode.DOWN);
            assertThat(mail.refuses()).as("the mail server is down").isTrue();
            answers.add(assertNotSent(signIn.sendCode(), state, mail.port()));

            mail.mode(FakeSmtpServer.Mode.CUTS);
            int reached = mail.connections();
            answers.add(assertNotSent(signIn.sendCode(), state, mail.port()));
            assertThat(mail.connections()).as("the mail server was reached and cut the connection").isGreaterThan(reached);

            mail.mode(FakeSmtpServer.Mode.SILENT);
            reached = mail.connections();
            long asked = System.nanoTime();
            answers.add(assertNotSent(signIn.sendCode(), state, mail.port()));
            assertThat(Duration.ofNanos(System.nanoTime() - asked))
                    .as("the limits of spring.mail.* ended the wait of the request").isLessThan(Duration.ofSeconds(15));
            assertThat(mail.connections()).as("the mail server was reached and said nothing").isGreaterThan(reached);
            assertThat(mail.messages()).as("no failed request mailed anything").hasSize(mailedBefore);
            assertThat(app.sends("mailA")).isZero();
            assertThat(app.sends("mailB")).isZero();

            mail.mode(FakeSmtpServer.Mode.ANSWERS);
            HttpResponse<String> sent = signIn.sendCode();
            assertThat(sent.statusCode()).as(sent.body()).isEqualTo(302);
            assertThat(sent.headers().firstValue("Location")).hasValue(app.base() + CODE_PAGE);
            assertThat(mail.messages()).hasSizeGreaterThan(mailedBefore);
            String body = FakeSmtpServer.body(mail.messages().get(mail.messages().size() - 1));
            Matcher found = CODE.matcher(body);
            assertThat(found.find()).as(body).isTrue();
            String code = found.group();
            HttpResponse<String> verified = signIn.verify(code);
            assertThat(verified.statusCode()).as(verified.body()).isEqualTo(200);
            assertThat(JSON.readTree(verified.body()).path("status").asText()).isEqualTo("MFA_COMPLETED");
            assertThat(output.getOut()).doesNotContain(code);
            assertThat(answers).noneMatch(answer -> answer.contains(code));
        }
    }

    /** Password, the code factor, the code from the mailbox, the code back: the sign-in ends. */
    private static void signInWithTheCodeFromTheMailbox(Running app, CapturedOutput output) throws Exception {
        Mailpit.clear();
        SignIn signIn = new SignIn(app.base());
        signIn.password();
        signIn.selectCode();

        HttpResponse<String> sent = signIn.sendCode();

        assertThat(sent.statusCode()).as(sent.body()).isEqualTo(302);
        assertThat(sent.headers().firstValue("Location")).hasValue(app.base() + CODE_PAGE);
        String code = Mailpit.codeOfTheOnlyMessage(ADDRESS);
        HttpResponse<String> verified = signIn.verify(code);
        assertThat(verified.statusCode()).as(verified.body()).isEqualTo(200);
        assertThat(JSON.readTree(verified.body()).path("status").asText()).isEqualTo("MFA_COMPLETED");
        assertThat(output.getAll()).doesNotContain(code);
    }

    private static String assertNotSent(HttpResponse<String> answer, String state, int mailPort) throws Exception {
        assertThat(answer.statusCode()).as(answer.body()).isEqualTo(503);
        JsonNode body = JSON.readTree(answer.body());
        assertThat(body.path("error").asText()).isEqualTo("OTT_CODE_NOT_SENT");
        assertThat(body.path("message").asText()).isEqualTo(NOT_SENT_MESSAGE);
        assertThat(body.path("success").asBoolean(true)).isFalse();
        assertThat(body.path("currentState").asText()).as("the flow stays where it was").isEqualTo(state);
        assertThat(answer.body()).doesNotContain("Exception", "127.0.0.1:" + mailPort);
        return answer.body();
    }

    /** An application that signs in with Contexa, with this many mail senders of its own and spring.mail.host set or not. */
    private static Running start(int senders, boolean mailHost) throws Exception {
        return start(senders, mailHost, Mailpit.smtpPort());
    }

    /**
     * The sender of the application is told to use the mail server when it is the only one (it is to be used), and a
     * port nothing listens on when there are several (a code mailed by one of them would not arrive). spring.mail.host
     * is the mail server when there are no senders or several, and a port nothing listens on when there is one sender
     * (a code mailed by a sender made of it would not arrive).
     */
    private static Running start(int senders, boolean mailHost, int mailServerPort) throws Exception {
        int deadPort = freePort();
        hostSenderPort = senders == 1 ? mailServerPort : deadPort;
        String database = "contexa_pick_" + UUID.randomUUID().toString().replace("-", "");
        administer("create database " + database);
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
                // the limits a mail setting of an application carries: without them a silent mail server holds the request
                "spring.mail.properties.mail.smtp.connectiontimeout=2000",
                "spring.mail.properties.mail.smtp.timeout=2000",
                "spring.mail.properties.mail.smtp.writetimeout=2000"));
        if (mailHost) {
            settings.add("spring.mail.host=127.0.0.1");
            settings.add("spring.mail.port=" + (senders == 1 ? deadPort : mailServerPort));
        }
        String redisPort = System.getenv("CONTEXA_TEST_REDIS_PORT");
        if (redisPort != null) {
            // nothing here uses Redis (standalone); a Redis client made anyway reaches the test's own and no other
            settings.add("spring.data.redis.host=127.0.0.1");
            settings.add("spring.data.redis.port=" + redisPort);
        }
        List<Class<?>> sources = new ArrayList<>(List.of(ContexaOwnedApplication.class));
        if (senders == 1) {
            sources.add(OneSender.class);
        } else if (senders == 2) {
            sources.add(TwoSenders.class);
        }
        ConfigurableApplicationContext application = new SpringApplicationBuilder(sources.toArray(new Class<?>[0]))
                .web(WebApplicationType.SERVLET)
                .properties(settings.toArray(new String[0]))
                .run();
        return new Running(application, database);
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
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

    /** One application that is up: closed with its database when the case is over. */
    private static final class Running implements AutoCloseable {

        private final ConfigurableApplicationContext application;
        private final String database;

        Running(ConfigurableApplicationContext application, String database) {
            this.application = application;
            this.database = database;
        }

        String base() {
            return "http://127.0.0.1:" + ((ServletWebServerApplicationContext) application).getWebServer().getPort();
        }

        /** The names of the mail senders among the application's beans, which are the application's and Spring Boot's. */
        List<String> senderBeans() {
            return new ArrayList<>(new TreeSet<>(application.getBeansOfType(JavaMailSender.class).keySet()));
        }

        /** How many times the application's sender of this name was asked to send (one message is one call of doSend). */
        int sends(String sender) {
            return (int) Mockito.mockingDetails(application.getBean(sender)).getInvocations().stream()
                    .filter(call -> call.getMethod().getName().equals("doSend")).count();
        }

        @Override
        public void close() throws Exception {
            application.close();
            administer("drop database if exists " + database + " with (force)");
        }
    }

    /** A mail sender of the application, as Spring's own, that remembers what it is asked to send. */
    static JavaMailSenderImpl countingSender(int port) {
        JavaMailSenderImpl sender = new JavaMailSenderImpl();
        sender.setHost("127.0.0.1");
        sender.setPort(port);
        sender.getJavaMailProperties().setProperty("mail.smtp.connectiontimeout", "2000");
        sender.getJavaMailProperties().setProperty("mail.smtp.timeout", "2000");
        sender.getJavaMailProperties().setProperty("mail.smtp.writetimeout", "2000");
        return Mockito.spy(sender);
    }

    /** An application that keeps two mail senders of its own, as one that mails from two accounts does. */
    @Configuration(proxyBeanMethods = false)
    static class TwoSenders {

        @Bean
        JavaMailSenderImpl mailA() {
            return countingSender(hostSenderPort);
        }

        @Bean
        JavaMailSenderImpl mailB() {
            return countingSender(hostSenderPort);
        }
    }

    /** An application that keeps one mail sender of its own. */
    @Configuration(proxyBeanMethods = false)
    static class OneSender {

        @Bean
        JavaMailSenderImpl hostMail() {
            return countingSender(hostSenderPort);
        }
    }

    /** The mail server of the cases: what Mailpit holds, read through its API as a person reads a mailbox. */
    private static final class Mailpit {

        private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

        static String api() {
            return Objects.requireNonNull(System.getenv("CONTEXA_TEST_MAILPIT_API"), "CONTEXA_TEST_MAILPIT_API");
        }

        static int smtpPort() {
            return Integer.parseInt(Objects.requireNonNull(System.getenv("CONTEXA_TEST_MAILPIT_SMTP_PORT"),
                    "CONTEXA_TEST_MAILPIT_SMTP_PORT"));
        }

        static void clear() throws Exception {
            HTTP.send(HttpRequest.newBuilder(URI.create(api() + "/api/v1/messages")).DELETE().build(),
                    HttpResponse.BodyHandlers.discarding());
        }

        static List<JsonNode> messages() throws Exception {
            HttpResponse<String> answer = HTTP.send(HttpRequest.newBuilder(URI.create(api() + "/api/v1/messages")).GET().build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            List<JsonNode> messages = new ArrayList<>();
            JSON.readTree(answer.body()).path("messages").forEach(messages::add);
            return messages;
        }

        /** The code in the one message of the mailbox, which is addressed to the person who signs in. */
        static String codeOfTheOnlyMessage(String to) throws Exception {
            List<JsonNode> messages = List.of();
            for (int waited = 0; waited < 40 && messages.isEmpty(); waited++) {
                messages = messages();
                if (messages.isEmpty()) {
                    Thread.sleep(250);
                }
            }
            assertThat(messages).as("a message reached the mailbox").hasSize(1);
            JsonNode message = messages.get(0);
            assertThat(message.path("To").get(0).path("Address").asText()).isEqualTo(to);
            HttpResponse<String> full = HTTP.send(HttpRequest.newBuilder(
                            URI.create(api() + "/api/v1/message/" + message.path("ID").asText())).GET().build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            JsonNode content = JSON.readTree(full.body());
            String text = content.path("HTML").asText() + content.path("Text").asText();
            Matcher found = CODE.matcher(text);
            assertThat(found.find()).as(text).isTrue();
            return found.group();
        }
    }

    /** One person's browser through Contexa's sign-in, as contexa-mfa-sdk.js asks: password, the code factor, the code. */
    private static final class SignIn {

        private final String base;
        private final HttpClient http = HttpClient.newBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        private String csrf = "";
        private String mfaSession;
        private String step;

        SignIn(String base) {
            this.base = base;
        }

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
                    .header("X-Device-Id", "sender-choice-device")
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

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
package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties.EnforcementMode;
import io.contexa.contexacore.testsupport.TestStores;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
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
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.web.firewall.HttpStatusRequestRejectedHandler;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.firewall.RequestRejectedHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contract test of bridge v2 (G1 as section 1 of docs/agent/bridge-v2-연동표준-초안.md reads after the review of 2026-11-26,
 * docs/agent/bridge-v2-재감사.md W-1, W-2, R-3): Contexa's own code leaves the legacy application's answers as they were;
 * what Spring Security does as its standard, and Contexa's rules of security, are stated, not taken for harm.
 * <p>
 * A legacy application without Spring Security of its own (no chain, no user store) turns Contexa on in mode SANDBOX and
 * runs on a real Tomcat on a port of its own. Next to it the same application runs without Contexa: the same beans, without
 * {@link EnableAISecurity}. Contexa needs Spring Security on the class path, which the legacy application did not have, so
 * the application without Contexa starts with Spring Security hidden from its class loader, as a class path without
 * Spring Security gives: no auto-configuration of Spring Security applies, and no Spring Security filter is in its servlet
 * container. Leaving out the registration of Spring Security's filter would not do: Spring Boot registers the filter bean
 * of {@code @EnableWebSecurity} in the container all the same.
 * <p>
 * The requests are sent as raw bytes on a socket, as a browser or an old client may send them: a session id in the path,
 * a doubled slash, a WebDAV method, raw UTF-8 bytes in a header value and in the path. Spring Security's firewall, which
 * every application with Spring Security has, refuses the first four as its standard: the application with Contexa counts
 * them in its own {@link RequestRejectedHandler}, which answers as Spring Security's default one does. A request the firewall
 * lets through is answered with the status the application gives without Contexa. A protected method called without a
 * signed-in user is refused in zero trust mode SHADOW as in ENFORCE, with 401, and does not run: SHADOW leaves Contexa's
 * decisions unenforced, not this rule.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Timeout(600)
@DisplayName("bridge v2 G1 계약: SANDBOX의 Spring Security 없는 레거시에 Contexa를 켜면 방화벽 밖 요청은 Contexa 없을 때와 같고, 방화벽은 Spring 표준대로 거부하며, SHADOW도 비로그인 보호 메서드를 401로 거부한다")
class SandboxLegacyHarmlessTomcatTest {

    private static final int DIMENSIONS = 1024;
    private static final String KOREAN_PATH = "/legacy/한글";
    private static final String SPRING_SECURITY = "org.springframework.security";

    private TestStores.Database server;
    private String database;
    private ConfigurableApplicationContext alone;
    private ConfigurableApplicationContext withContexa;

    @BeforeAll
    void start() throws SQLException {
        server = TestStores.database();
        database = "contexa_g1_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        try (Connection admin = admin(); Statement statement = admin.createStatement()) {
            statement.execute("create database " + database);
        }
        alone = new SpringApplicationBuilder(LegacyAlone.class)
                .resourceLoader(new DefaultResourceLoader(new FilteredClassLoader(SPRING_SECURITY)))
                .web(WebApplicationType.SERVLET)
                .properties("spring.main.banner-mode=off", "server.port=0")
                .run();
        withContexa = new SpringApplicationBuilder(LegacyWithContexa.class)
                .web(WebApplicationType.SERVLET)
                .properties("spring.main.banner-mode=off", "server.port=0",
                        "contexa.datasource.url=" + url(database),
                        "contexa.datasource.username=" + server.username(),
                        "contexa.datasource.password=" + server.password(),
                        "contexa.llm.selection.chat.mode=spring-primary",
                        "contexa.llm.selection.embedding.mode=spring-primary",
                        "contexa.security.zerotrust.mode=SHADOW")
                .run();
    }

    @AfterAll
    void stop() throws SQLException {
        if (withContexa != null) {
            withContexa.close();
        }
        if (alone != null) {
            alone.close();
        }
        if (database == null) {
            return;
        }
        try (Connection admin = admin(); Statement statement = admin.createStatement()) {
            statement.execute("drop database if exists " + database + " with (force)");
        }
    }

    /** What the comparison stands on: the two applications are the ones described, and a plain request is answered. */
    @Test
    @DisplayName("비교의 전제: Contexa 쪽은 SANDBOX 격리 체인과 SHADOW, Contexa 없는 쪽은 Spring Security 필터 없음, 평범한 GET은 둘 다 200")
    void theTwoApplicationsAreTheOnesCompared() throws Exception {
        assertThat(withContexa.containsBean(SandboxIsolationAutoConfiguration.ISOLATION_CHAIN)).isTrue();
        assertThat(withContexa.getBean(SecurityZeroTrustProperties.class).getMode()).isEqualTo(EnforcementMode.SHADOW);
        assertThat(alone.containsBean("springSecurityFilterChain")).isFalse();
        assertThat(((ServletWebServerApplicationContext) alone).getServletContext().getFilterRegistrations())
                .doesNotContainKey("springSecurityFilterChain");

        assertThat(status(alone, LegacyRequest.PLAIN)).isEqualTo(200);
        assertThat(status(withContexa, LegacyRequest.PLAIN)).isEqualTo(200);
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(value = LegacyRequest.class, names = {"PATH_SESSION_ID", "DOUBLE_SLASH", "WEBDAV_METHOD", "RAW_UTF8_HEADER"})
    @DisplayName("Spring Security 표준 방화벽이 거부하는 원시 요청은 Contexa가 바꾸지 않고 방화벽의 기본 응답 400으로 답한다")
    void theFirewallRefusesAsSpringSecurityDoes(LegacyRequest request) throws Exception {
        CountingRejections rejections = withContexa.getBean(CountingRejections.class);
        int rejected = rejections.count();
        int errorPages = rejections.errorPages();

        int without = status(alone, request);
        int with = status(withContexa, request);
        System.out.println("G1 FIREWALL [" + request + "] without Contexa=" + without + ", with Contexa SANDBOX=" + with
                + ", refused requests=" + (rejections.count() - rejected)
                + ", refused error pages=" + (rejections.errorPages() - errorPages));

        assertThat(rejections.count() - rejected).as(request + " refused by Spring Security's firewall").isEqualTo(1);
        assertThat(with).as(request + ": the answer of Spring Security's default rejection handler").isEqualTo(400);
    }

    @Test
    @DisplayName("방화벽이 통과시키는 원시 요청(원시 UTF-8 경로)은 Contexa가 켜진 레거시도 Contexa 없는 레거시와 같은 상태 코드로 답한다")
    void aRawRequestTheFirewallLetsThroughIsAnsweredAsWithoutContexa() throws Exception {
        CountingRejections rejections = withContexa.getBean(CountingRejections.class);
        int rejected = rejections.count();

        int without = status(alone, LegacyRequest.RAW_UTF8_PATH);
        int with = status(withContexa, LegacyRequest.RAW_UTF8_PATH);
        System.out.println("G1 RAW REQUEST [" + LegacyRequest.RAW_UTF8_PATH + "] without Contexa=" + without
                + ", with Contexa SANDBOX=" + with);

        assertThat(rejections.count() - rejected).as("not refused by Spring Security's firewall").isZero();
        assertThat(with).as("without Contexa " + without + ", with Contexa " + with).isEqualTo(without);
    }

    @Test
    @DisplayName("SHADOW에서도 로그인 사용자 없이 @Protectable 메서드를 부르는 요청은 401로 거부되고 메서드는 실행되지 않는다")
    void inShadowAProtectedMethodCalledWithoutAUserIsRefusedWith401() throws Exception {
        int runs = withContexa.getBean(Secured.class).runs();

        int without = status(alone, LegacyRequest.PROTECTED);
        int with = status(withContexa, LegacyRequest.PROTECTED);
        int ran = withContexa.getBean(Secured.class).runs() - runs;
        System.out.println("G1 SHADOW PROTECTABLE without Contexa=" + without + ", with Contexa SANDBOX SHADOW=" + with
                + ", method runs=" + ran);

        assertThat(without).as("without Contexa nothing protects the method").isEqualTo(200);
        assertThat(with).as("a call without a user is refused in SHADOW as in ENFORCE").isEqualTo(401);
        assertThat(ran).as("the application's method did not run").isZero();
    }

    /** The status of the answer to the request, read from the status line of the raw response. */
    private static int status(ConfigurableApplicationContext context, LegacyRequest request) throws IOException {
        int port = ((ServletWebServerApplicationContext) context).getWebServer().getPort();
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(30_000);
            OutputStream out = socket.getOutputStream();
            out.write(request.bytes(port));
            out.flush();
            String statusLine = firstLine(socket.getInputStream());
            String[] parts = statusLine.split(" ");
            assertThat(parts.length).as("the status line of " + request + ": " + statusLine).isGreaterThanOrEqualTo(2);
            return Integer.parseInt(parts[1]);
        }
    }

    private static String firstLine(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        for (int read = in.read(); read >= 0 && read != '\n'; read = in.read()) {
            if (read != '\r') {
                line.write(read);
            }
        }
        return line.toString(StandardCharsets.ISO_8859_1);
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

    /** The requests a legacy application receives, each as the bytes on the wire. */
    enum LegacyRequest {

        PLAIN("GET", "/legacy/page", null),
        PATH_SESSION_ID("GET", "/legacy/page;jsessionid=abc123", null),
        DOUBLE_SLASH("GET", "//legacy/page", null),
        WEBDAV_METHOD("PROPFIND", "/legacy/page", null),
        RAW_UTF8_HEADER("GET", "/legacy/page", "X-Name: 홍길동"),
        RAW_UTF8_PATH("GET", KOREAN_PATH, null),
        PROTECTED("GET", "/legacy/protected", null);

        private final String method;
        private final String target;
        private final String header;

        LegacyRequest(String method, String target, String header) {
            this.method = method;
            this.target = target;
            this.header = header;
        }

        /** The request in bytes: the target and the header in raw UTF-8, neither percent-encoded nor checked by a client. */
        byte[] bytes(int port) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            bytes.writeBytes((method + " ").getBytes(StandardCharsets.US_ASCII));
            bytes.writeBytes(target.getBytes(StandardCharsets.UTF_8));
            bytes.writeBytes((" HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n").getBytes(StandardCharsets.US_ASCII));
            if (header != null) {
                bytes.writeBytes(header.getBytes(StandardCharsets.UTF_8));
                bytes.writeBytes("\r\n".getBytes(StandardCharsets.US_ASCII));
            }
            bytes.writeBytes("Connection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            return bytes.toByteArray();
        }

        @Override
        public String toString() {
            return method + " " + target + (header != null ? " with header " + header : "");
        }
    }

    /** The legacy application without Contexa, started where Spring Security is hidden from its class loader. */
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    static class LegacyAlone extends LegacyBeans {
    }

    /**
     * The same legacy application with Contexa turned on, in mode SANDBOX, the default. Its one bean more counts the requests
     * Spring Security's firewall refuses and answers them as Spring Security's default handler does.
     */
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    static class LegacyWithContexa extends LegacyBeans {

        @Bean
        CountingRejections countingRejections() {
            return new CountingRejections();
        }
    }

    /**
     * Spring Security's default answer to a request its firewall refuses (400), with a count of them by the dispatch they
     * came in: the request itself, and the error page the container dispatches for the 400, which passes the firewall too.
     */
    static final class CountingRejections implements RequestRejectedHandler {

        private final RequestRejectedHandler standard = new HttpStatusRequestRejectedHandler();
        private final AtomicInteger rejected = new AtomicInteger();
        private final AtomicInteger rejectedErrorPages = new AtomicInteger();

        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response,
                           RequestRejectedException rejection) throws IOException, ServletException {
            if (request.getDispatcherType() == DispatcherType.REQUEST) {
                rejected.incrementAndGet();
            } else if (request.getDispatcherType() == DispatcherType.ERROR) {
                rejectedErrorPages.incrementAndGet();
            }
            standard.handle(request, response, rejection);
        }

        /** The requests themselves the firewall refused. */
        int count() {
            return rejected.get();
        }

        int errorPages() {
            return rejectedErrorPages.get();
        }
    }

    /**
     * The beans of the legacy application, the same in both, the models Contexa needs included. Inherited, not imported: an
     * import of a class under io.contexa goes through Contexa's auto-configuration filter.
     */
    abstract static class LegacyBeans {

        @Bean
        Secured secured() {
            return new Secured();
        }

        @Bean
        LegacyPages legacyPages(Secured secured) {
            return new LegacyPages(secured);
        }

        @Bean
        ChatModel silentChatModel() {
            return new SilentChatModel();
        }

        @Bean
        EmbeddingModel flatEmbeddingModel() {
            return new FlatEmbeddingModel();
        }
    }

    @RestController
    static class LegacyPages {

        private final Secured secured;

        LegacyPages(Secured secured) {
            this.secured = secured;
        }

        /** The legacy page, for every method (WebDAV ones too); it reads the caller's name from its header, as legacy pages do. */
        @RequestMapping("/legacy/page")
        String page(@RequestHeader(name = "X-Name", required = false) String name) {
            return "ok";
        }

        @RequestMapping(KOREAN_PATH)
        String koreanPage() {
            return "ok";
        }

        @GetMapping("/legacy/protected")
        String protectedPage() {
            return secured.read();
        }
    }

    /** A method of the legacy application that Contexa protects once it is turned on. */
    public static class Secured {

        private final AtomicInteger runs = new AtomicInteger();

        @Protectable
        public String read() {
            runs.incrementAndGet();
            return "ok";
        }

        public int runs() {
            return runs.get();
        }
    }

    /** No model is asked anything a test depends on: a model only has to exist for Contexa to start. */
    static final class SilentChatModel implements ChatModel {

        @Override
        public ChatResponse call(Prompt prompt) {
            return new ChatResponse(List.of(new Generation(new AssistantMessage("{}"))));
        }
    }

    static final class FlatEmbeddingModel implements EmbeddingModel {

        @Override
        public EmbeddingResponse call(EmbeddingRequest request) {
            List<Embedding> embeddings = new ArrayList<>();
            for (int index = 0; index < request.getInstructions().size(); index++) {
                embeddings.add(new Embedding(new float[DIMENSIONS], index));
            }
            return new EmbeddingResponse(embeddings);
        }

        @Override
        public float[] embed(Document document) {
            return new float[DIMENSIONS];
        }

        @Override
        public int dimensions() {
            return DIMENSIONS;
        }
    }
}

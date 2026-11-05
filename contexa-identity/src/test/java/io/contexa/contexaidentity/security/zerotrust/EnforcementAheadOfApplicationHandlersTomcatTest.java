/* Copyright 2026 The Contexa Project */
package io.contexa.contexaidentity.security.zerotrust;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.execution.AnomalyDetectedException;
import io.contexa.contexacore.autonomous.execution.RapidProtectableReentryDeniedException;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.execution.ZeroTrustChallengeFlowStarter;
import io.contexa.contexacore.autonomous.execution.ZeroTrustEnforcementExceptionResolver;
import io.contexa.contexacore.autonomous.execution.ZeroTrustExceptionHandler;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.DispatcherServletAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.ServletWebServerFactoryAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Q-9 (PR-47) on a real servlet container: the application here has what legacy applications have, a catch-all handler
 * ahead of every other, a handler inside a controller, a resolver of its own at the top, an advice that rewrites bodies
 * and a global JSON naming. A decision made at a protected method is answered by Contexa all the same; every other
 * exception stays the application's.
 */
@SpringBootTest(classes = EnforcementAheadOfApplicationHandlersTomcatTest.Web.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.jackson.property-naming-strategy=SNAKE_CASE")
class EnforcementAheadOfApplicationHandlersTomcatTest {

    private static final String USER_HEADER = "X-Cut-User";
    private static final String STEP_UP = "/contexa/step-up";
    private static final String MARKER = "__CONTEXA_RESPONSE_BLOCKED__";

    @LocalServerPort
    private int port;

    @Autowired
    private BlockingSignalBroadcaster signals;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER).build();
    private final ObjectMapper json = new ObjectMapper();

    private HttpResponse<String> get(String pathAndQuery, String accept) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + pathAndQuery))
                .header(USER_HEADER, "user-" + UUID.randomUUID()).header("Accept", accept).GET()
                .timeout(Duration.ofSeconds(20)).build();
        return http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private void assertAnsweredByContexa(HttpResponse<String> answer, int status, String code, String action) throws Exception {
        assertThat(answer.statusCode()).as(answer.body()).isEqualTo(status);
        assertThat(answer.body()).doesNotContain("legacy");
        JsonNode body = json.readTree(answer.body());
        assertThat(body.path("status").asInt()).isEqualTo(status);
        assertThat(body.path("code").asText()).isEqualTo(code);
        assertThat(body.path("action").asText()).isEqualTo(action);
        assertThat(body.path("timestamp").asText()).as("as the JSON of every other answer").contains("T").endsWith("Z");
    }

    @Test
    @DisplayName("the measurement: a CHALLENGE in the method is Contexa's 401 with where to continue, not the application's 200")
    void aChallengeIsAnsweredByContexa() throws Exception {
        HttpResponse<String> answer = get("/decided?action=CHALLENGE", "application/json");

        assertAnsweredByContexa(answer, 401, "ZERO_TRUST_CHALLENGE", "CHALLENGE");
        assertThat(json.readTree(answer.body()).path("mfaUrl").asText())
                .as("the name Contexa's browser SDK reads, whatever the application's JSON naming").isEqualTo(STEP_UP);
    }

    @Test
    @DisplayName("the measurement: a BLOCK in the method reaches the client whole, the connection is not cut")
    void aBlockIsAnsweredByContexaAndTheConnectionStays() throws Exception {
        HttpResponse<String> answer = get("/decided?action=BLOCK&signal=true", "application/json");

        assertAnsweredByContexa(answer, 403, "ZERO_TRUST_BLOCK", "BLOCK");
        assertThat(answer.body()).doesNotContain(MARKER);
    }

    @Test
    void aHoldIsAnsweredByContexa() throws Exception {
        assertAnsweredByContexa(get("/decided?action=ESCALATE", "application/json"), 423, "ZERO_TRUST_ESCALATE", "ESCALATE");
    }

    @Test
    void aBrowserIsSentToTheScreenOfTheDecision() throws Exception {
        HttpResponse<String> answer = get("/decided?action=BLOCK", "text/html");

        assertThat(answer.statusCode()).as(answer.body()).isEqualTo(302);
        assertThat(answer.headers().firstValue("Location")).hasValue("/contexa/zero-trust/blocked");
    }

    @Test
    void anAnomalyIsAnsweredByContexa() throws Exception {
        assertAnsweredByContexa(get("/anomaly", "application/json"), 403, "ZERO_TRUST_ANOMALY_DETECTED", "BLOCK");
    }

    @Test
    void aRapidReentryIsAnsweredByContexa() throws Exception {
        assertAnsweredByContexa(get("/reentry", "application/json"), 429, "RAPID_PROTECTABLE_REENTRY", "CHALLENGE");
    }

    @Test
    @DisplayName("a client that accepts nothing Contexa writes still gets the decision, not the application's handler")
    void whatTheClientAcceptsDoesNotOpenAWay() throws Exception {
        assertAnsweredByContexa(get("/decided?action=BLOCK", "text/csv"), 403, "ZERO_TRUST_BLOCK", "BLOCK");
    }

    @Test
    void aHandlerInsideTheControllerDoesNotTakeTheDecision() throws Exception {
        assertAnsweredByContexa(get("/local", "application/json"), 401, "ZERO_TRUST_CHALLENGE", "CHALLENGE");
    }

    @Test
    void aDecisionTheApplicationWrappedIsFoundInside() throws Exception {
        assertAnsweredByContexa(get("/wrapped", "application/json"), 403, "ZERO_TRUST_BLOCK", "BLOCK");
    }

    @Test
    void aControllerThatStartedWritingCharactersDoesNotLoseTheDecision() throws Exception {
        assertAnsweredByContexa(get("/writer", "application/json"), 403, "ZERO_TRUST_BLOCK", "BLOCK");
    }

    @Test
    @DisplayName("everything else stays the application's: its handler answers as it always did")
    void everyOtherExceptionStaysTheApplications() throws Exception {
        HttpResponse<String> answer = get("/ordinary", "application/json");

        assertThat(answer.statusCode()).isEqualTo(200);
        assertThat(answer.body()).contains("legacy", "IllegalStateException");
    }

    @Test
    void aPlainAccessDenialOfTheApplicationStaysTheApplications() throws Exception {
        HttpResponse<String> answer = get("/denied", "application/json");

        assertThat(answer.statusCode()).isEqualTo(200);
        assertThat(answer.body()).contains("legacy", "AccessDeniedException");
    }

    @Test
    void aCallThatFailsNothingIsNotTouched() throws Exception {
        HttpResponse<String> answer = get("/fine", "application/json");

        assertThat(answer.statusCode()).isEqualTo(200);
        assertThat(answer.body()).contains("fine");
    }

    @RestController
    static class Endpoints {

        private final BlockingSignalBroadcaster signals;

        Endpoints(BlockingSignalBroadcaster signals) {
            this.signals = signals;
        }

        /** As a synchronous @Protectable: the decision is made in the request, and a BLOCK has signalled by then. */
        @GetMapping("/decided")
        String decided(@RequestParam("action") String action, @RequestParam(name = "signal", defaultValue = "false") boolean signal,
                       HttpServletRequest request) {
            if (signal) {
                signals.registerBlock(request.getHeader(USER_HEADER));
            }
            throw new ZeroTrustAccessDeniedException(action, "Service.decided", 0.9, "decided by the test");
        }

        @GetMapping("/anomaly")
        String anomaly() {
            throw new AnomalyDetectedException("anomaly");
        }

        @GetMapping("/reentry")
        String reentry() {
            throw new RapidProtectableReentryDeniedException("Service.decided", 5);
        }

        @GetMapping("/wrapped")
        String wrapped() {
            throw new IllegalStateException("the application's own wrapper",
                    ZeroTrustAccessDeniedException.blocked("Service.decided"));
        }

        @GetMapping("/writer")
        void writer(HttpServletResponse response) throws IOException {
            PrintWriter writer = response.getWriter();
            writer.print("partial");
            throw ZeroTrustAccessDeniedException.blocked("Service.decided");
        }

        @GetMapping("/ordinary")
        String ordinary() {
            throw new IllegalStateException("the application's own failure");
        }

        @GetMapping("/denied")
        String denied() {
            throw new AccessDeniedException("the application's own refusal");
        }

        @GetMapping("/fine")
        Map<String, Object> fine() {
            return Map.of("state", "fine");
        }
    }

    @RestController
    static class ControllerWithItsOwnHandler {

        @GetMapping("/local")
        String local() {
            throw ZeroTrustAccessDeniedException.challengeRequired("Service.decided");
        }

        @ExceptionHandler(Exception.class)
        ResponseEntity<Map<String, Object>> everyError(Exception problem) {
            return ResponseEntity.ok(Map.of("legacy", "local", "type", problem.getClass().getSimpleName()));
        }
    }

    /** The classic catch-all of a legacy application, ahead of every other handler: the shape of the measured one. */
    @RestControllerAdvice
    @Order(Ordered.HIGHEST_PRECEDENCE)
    static class EveryError {

        @ExceptionHandler(Exception.class)
        ResponseEntity<Map<String, Object>> everyError(Exception problem) {
            return ResponseEntity.status(HttpStatus.OK).body(Map.of("legacy", "handled", "type", problem.getClass().getSimpleName()));
        }
    }

    /** Wraps every body of the application; an answer of Contexa is not one of them. */
    @RestControllerAdvice
    static class EveryBody implements ResponseBodyAdvice<Object> {

        @Override
        public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
            return true;
        }

        @Override
        public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
                                      Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                      ServerHttpRequest request, ServerHttpResponse response) {
            return Map.of("legacyEnvelope", body == null ? "" : body);
        }
    }

    /** A resolver of the application at the top: at the same order it would come first by bean order. */
    static class ApplicationResolver implements HandlerExceptionResolver, Ordered {

        @Override
        public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object handler,
                                             Exception exception) {
            if (!(exception instanceof ZeroTrustAccessDeniedException)) {
                return null;
            }
            try {
                response.setStatus(200);
                response.getWriter().write("{\"legacy\":\"resolver\"}");
            } catch (IOException | IllegalStateException failed) {
                throw new IllegalStateException(failed);
            }
            return new ModelAndView();
        }

        @Override
        public int getOrder() {
            return Ordered.HIGHEST_PRECEDENCE;
        }
    }

    /** Signs the request in as the user named by the header, as the security filter chain would. */
    static final class SignIn extends OncePerRequestFilter {

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            SecurityContextHolder.setContext(new SecurityContextImpl(
                    UsernamePasswordAuthenticationToken.authenticated(request.getHeader(USER_HEADER), null, List.of())));
            try {
                chain.doFilter(request, response);
            } finally {
                SecurityContextHolder.clearContext();
            }
        }
    }

    @SpringBootConfiguration
    @ImportAutoConfiguration({ServletWebServerFactoryAutoConfiguration.class, DispatcherServletAutoConfiguration.class,
            WebMvcAutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class, JacksonAutoConfiguration.class})
    static class Web {

        @Bean
        ApplicationResolver applicationResolver() {
            return new ApplicationResolver();
        }

        @Bean
        EveryError everyError() {
            return new EveryError();
        }

        @Bean
        EveryBody everyBody() {
            return new EveryBody();
        }

        @Bean
        Endpoints endpoints(BlockingSignalBroadcaster signals) {
            return new Endpoints(signals);
        }

        @Bean
        ControllerWithItsOwnHandler controllerWithItsOwnHandler() {
            return new ControllerWithItsOwnHandler();
        }

        @Bean
        ZeroTrustExceptionHandler zeroTrustExceptionHandler() {
            return new ZeroTrustExceptionHandler(new ZeroTrustChallengeFlowStarter() {
                @Override
                public Optional<String> start(HttpServletRequest request, HttpServletResponse response) {
                    return Optional.of(STEP_UP);
                }
            });
        }

        @Bean
        ZeroTrustEnforcementExceptionResolver zeroTrustEnforcementExceptionResolver(ZeroTrustExceptionHandler handler) {
            return new ZeroTrustEnforcementExceptionResolver(handler);
        }

        @Bean
        InMemoryZeroTrustActionRepository decisions() {
            return new InMemoryZeroTrustActionRepository();
        }

        @Bean
        BlockingSignalBroadcaster signals(ZeroTrustActionRepository decisions) {
            return new InMemoryBlockingSignalBroadcaster(
                    userId -> decisions.getCurrentAction(userId, null) == ZeroTrustAction.BLOCK, Duration.ofMillis(500));
        }

        @Bean
        FilterRegistrationBean<SignIn> signIn() {
            FilterRegistrationBean<SignIn> registration = new FilterRegistrationBean<>(new SignIn());
            registration.setOrder(1);
            return registration;
        }

        @Bean
        FilterRegistrationBean<ZeroTrustAccessControlFilter> zeroTrust(ZeroTrustActionRepository decisions,
                                                                       BlockingSignalBroadcaster signals) {
            FilterRegistrationBean<ZeroTrustAccessControlFilter> registration = new FilterRegistrationBean<>(
                    new ZeroTrustAccessControlFilter(decisions, mock(AuthResponseWriter.class), null, null, null, signals, 2));
            registration.setOrder(2);
            return registration;
        }
    }
}

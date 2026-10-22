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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.execution.ZeroTrustExceptionHandler;
import io.contexa.contexacore.autonomous.handler.handler.SecurityDecisionEnforcementHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
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
import org.springframework.boot.autoconfigure.task.TaskExecutionAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.DispatcherServletAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.ServletWebServerFactoryAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Responses cut on a real servlet container (embedded Tomcat on a random port) through the access filter, with the
 * BLOCK made by the decision enforcement itself (docs/showcase/응답차단-수정계획.md RT-6): a synchronous stream, an
 * asynchronous {@link StreamingResponseBody} and a character stream are cut right after the BLOCK, a response cut before
 * its commit sends 403 and the marker only, two responses of the user in flight are both cut, and a signal left from an
 * earlier block does not cut a new response. Subclasses give the decision store and the broadcaster (memory, Redis).
 */
abstract class ResponseCutTomcatTestSupport {

    static final String USER_HEADER = "X-Cut-User";
    static final String MARKER = "__CONTEXA_RESPONSE_BLOCKED__:BLOCK";
    private static final SecurityContextDataStore PROCESSING = new InMemorySecurityContextDataStore();

    @LocalServerPort
    private int port;

    @Autowired
    protected ZeroTrustActionRepository decisions;

    @Autowired
    protected BlockingSignalBroadcaster signals;

    @Autowired
    private CutEndpoints endpoints;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    protected static String newUser() {
        return "cut-" + UUID.randomUUID();
    }

    /** Applies a BLOCK decision for the user the way the engine does, through the decision enforcement. */
    protected static void decideBlock(ZeroTrustActionRepository decisions, BlockingSignalBroadcaster signals,
                                      String user) {
        AiSecurityDecisionObservationWriter observations = mock(AiSecurityDecisionObservationWriter.class);
        when(observations.recordDecision(any(), any(), any())).thenReturn("observation-" + UUID.randomUUID());
        when(observations.isStoreConfigured()).thenReturn(true);
        SecurityDecisionEnforcementHandler enforcement = new SecurityDecisionEnforcementHandler(decisions,
                mock(SecurityLearningService.class), null, signals, null, Runnable::run, () -> observations,
                PROCESSING, null);
        SecurityEvent event = SecurityEvent.builder().eventId(UUID.randomUUID().toString()).userId(user)
                .sourceIp("127.0.0.1").userAgent("cut-test").build();
        // As SecurityPlaneAgent claims the event before its analysis: the lease's owner token is the processing
        // generation the decision store's final write requires.
        SecurityContextDataStore.EventProcessingLease lease = PROCESSING.claimEventProcessingLease(event.getEventId());
        event.addMetadata(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY, event.getEventId());
        event.addMetadata(SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN, lease.ownerToken());
        SecurityEventContext context = SecurityEventContext.builder().securityEvent(event).build();
        context.addMetadata("processingResult", ProcessingResult.builder().success(true)
                .action(ZeroTrustAction.BLOCK.name()).riskScore(0.99).confidence(0.95)
                .reasoning("BLOCK made by the test").build());
        assertThat(enforcement.handle(context)).as("the BLOCK decision is enforced").isTrue();
        assertThat(decisions.getCurrentAction(user, null)).isEqualTo(ZeroTrustAction.BLOCK);
    }

    protected void decideBlock(String user) {
        decideBlock(decisions, signals, user);
    }

    protected Progress progressOf(String id) {
        return endpoints.progress(id);
    }

    /**
     * R-12 (real server, 2026-10-20 07:46, A3 run-600d38a0d9dd): a BLOCK decided in the request, before any response,
     * is answered by the engine's own deny response (ZeroTrustExceptionHandler); it reaches the client whole.
     */
    @Test
    @DisplayName("a synchronous BLOCK's own deny response reaches the client whole")
    void aSynchronousBlocksOwnDenyResponseReachesTheClientWhole() throws Exception {
        String user = newUser();
        String id = UUID.randomUUID().toString();
        endpoints.onEntry(id, () -> decideBlock(user));

        Reading denied = read(user, "/cut/deny?id=" + id, null);

        assertThat(denied.status()).isEqualTo(403);
        assertThat(denied.broken()).as("the response ends as the handler wrote it").isFalse();
        assertThat(String.join("\n", denied.lines())).contains("\"action\":\"BLOCK\"").doesNotContain(MARKER);
    }

    // ---- the scenarios ----

    @Test
    @DisplayName("a synchronous stream is cut right after the BLOCK: the marker, then nothing")
    void aSynchronousStreamIsCut() throws Exception {
        assertCutRightAfterTheBlock("/cut/sync");
    }

    @Test
    @DisplayName("an asynchronous StreamingResponseBody is cut right after the BLOCK: the marker, then nothing")
    void anAsynchronousStreamIsCut() throws Exception {
        assertCutRightAfterTheBlock("/cut/async");
    }

    @Test
    @DisplayName("a character stream is cut right after the BLOCK: the marker, then nothing")
    void aCharacterStreamIsCut() throws Exception {
        assertCutRightAfterTheBlock("/cut/writer");
    }

    @Test
    @DisplayName("a synchronous response cut before its commit sends 403 and the marker only")
    void aSynchronousResponseCutBeforeItsCommit() throws Exception {
        assertCutBeforeTheCommit(false);
    }

    @Test
    @DisplayName("an asynchronous response cut before its commit sends 403 and the marker only")
    void anAsynchronousResponseCutBeforeItsCommit() throws Exception {
        assertCutBeforeTheCommit(true);
    }

    @Test
    @DisplayName("two synchronous responses of the user in flight are both cut")
    void twoResponsesInFlightAreBothCut() throws Exception {
        String user = newUser();
        String fast = UUID.randomUUID().toString();
        String slow = UUID.randomUUID().toString();
        CountDownLatch bothStarted = new CountDownLatch(2);
        CompletableFuture<Reading> first = CompletableFuture.supplyAsync(
                () -> read(user, "/cut/sync?rows=400&everyMs=20&id=" + fast, bothStarted));
        CompletableFuture<Reading> second = CompletableFuture.supplyAsync(
                () -> read(user, "/cut/sync?rows=40&everyMs=400&id=" + slow, bothStarted));
        assertThat(bothStarted.await(10, TimeUnit.SECONDS)).isTrue();

        decideBlock(user);
        long blockedAt = System.nanoTime();

        Reading fastReading = first.get(20, TimeUnit.SECONDS);
        Reading slowReading = second.get(20, TimeUnit.SECONDS);
        assertCut(fastReading, endpoints.progress(fast), blockedAt);
        assertCut(slowReading, endpoints.progress(slow), blockedAt);
    }

    @Test
    @DisplayName("a signal left from an earlier block does not cut a new response once the user is no longer blocked")
    void aSignalLeftFromAnEarlierBlockDoesNotCutANewResponse() throws Exception {
        String user = newUser();
        decideBlock(user);
        // The decision is lifted in the store only; the signal stays, as when no release path cleared it.
        decisions.removeAllUserData(user);
        assertThat(decisions.getCurrentAction(user, null)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        String id = UUID.randomUUID().toString();

        Reading reading = read(user, "/cut/sync?rows=12&everyMs=100&id=" + id, null);

        assertThat(reading.status()).isEqualTo(200);
        assertThat(reading.lines()).doesNotContain(MARKER);
        assertThat(reading.dataLines()).isEqualTo(12);
        assertThat(reading.broken()).isFalse();
    }

    @Test
    @DisplayName("a BLOCK written to the store without a signal (administrator, promotion) cuts the stream within 1 s")
    void aBlockWithoutItsSignalCutsWithinOneSecond() throws Exception {
        String user = newUser();
        String id = UUID.randomUUID().toString();
        CountDownLatch started = new CountDownLatch(1);
        CompletableFuture<Reading> reading = CompletableFuture.supplyAsync(
                () -> read(user, "/cut/async?rows=400&everyMs=20&id=" + id, started));
        assertThat(started.await(10, TimeUnit.SECONDS)).isTrue();

        // As AdminOverrideService and the ESCALATE promotion write a BLOCK: the store only, no signal.
        decisions.saveAction(user, ZeroTrustAction.BLOCK, Map.of());
        decisions.setBlockedFlag(user);
        long blockedAt = System.nanoTime();

        assertCut(reading.get(20, TimeUnit.SECONDS), endpoints.progress(id),
                blockedAt + TimeUnit.SECONDS.toNanos(1));
    }

    @Test
    @DisplayName("a released user is not cut")
    void aReleasedUserIsNotCut() throws Exception {
        String user = newUser();
        decideBlock(user);
        decisions.removeAllUserData(user);
        signals.registerUnblock(user);
        await().atMost(Duration.ofSeconds(2)).until(() -> !signals.isBlocked(user));

        Reading reading = read(user, "/cut/async?rows=5&everyMs=20&id=" + UUID.randomUUID(), null);

        assertThat(reading.status()).isEqualTo(200);
        assertThat(reading.dataLines()).isEqualTo(5);
        assertThat(reading.broken()).isFalse();
    }

    // ---- assertions ----

    private void assertCutRightAfterTheBlock(String path) throws Exception {
        String user = newUser();
        String id = UUID.randomUUID().toString();
        CountDownLatch started = new CountDownLatch(1);
        CompletableFuture<Reading> reading = CompletableFuture.supplyAsync(
                () -> read(user, path + "?rows=400&everyMs=20&id=" + id, started));
        assertThat(started.await(10, TimeUnit.SECONDS)).isTrue();
        await().atMost(Duration.ofSeconds(5)).until(() -> endpoints.progress(id).written.size() >= 3);

        decideBlock(user);
        long blockedAt = System.nanoTime();

        assertCut(reading.get(20, TimeUnit.SECONDS), endpoints.progress(id), blockedAt);
    }

    /** Thrown away before the commit: the rows written before the BLOCK never reach the client. */
    private void assertCutBeforeTheCommit(boolean async) throws Exception {
        String user = newUser();
        String id = UUID.randomUUID().toString();
        CompletableFuture<Reading> reading = CompletableFuture.supplyAsync(
                () -> read(user, "/cut/held?async=" + async + "&id=" + id, null));
        await().atMost(Duration.ofSeconds(5)).until(() -> endpoints.progress(id).holding);

        decideBlock(user);
        endpoints.progress(id).release.countDown();

        Reading cut = reading.get(20, TimeUnit.SECONDS);
        assertThat(cut.status()).isEqualTo(403);
        assertThat(cut.monitored()).isTrue();
        assertThat(cut.dataLines()).as("rows written before the BLOCK, still in the buffer").isZero();
        assertThat(cut.lines()).contains(MARKER);
        assertThat(endpoints.progress(id).written).as("the rows the application wrote into the buffer").hasSize(2);
        assertThat(endpoints.progress(id).failed).as("the write after the BLOCK failed").isTrue();
    }

    static void assertCut(Reading reading, Progress progress, long blockedAt) {
        assertThat(reading.status()).isEqualTo(200);
        assertThat(reading.monitored()).isTrue();
        assertThat(reading.lines()).as("the marker reaches the client").contains(MARKER);
        int marker = reading.lines().indexOf(MARKER);
        assertThat(reading.lines().subList(marker + 1, reading.lines().size()))
                .as("nothing after the marker").allMatch(String::isBlank);
        // Whether the container then closes the connection or ends the chunked body is its own error handling; the
        // cut is the marker and nothing after it (the SDK acts on the marker only).
        assertThat(progress.failed).as("the application's next write failed").isTrue();
        assertThat(progress.writtenAfter(blockedAt)).as("writes started after the BLOCK that went out").isZero();
        assertThat(reading.dataLines()).as("every row the server wrote reached the client, no more")
                .isEqualTo(progress.written.size());
    }

    // ---- client ----

    record Reading(int status, boolean monitored, List<String> lines, boolean broken) {

        long dataLines() {
            return lines.stream().filter(line -> line.startsWith("{\"row\":") || line.startsWith("<p>row")).count();
        }
    }

    Reading read(String user, String pathAndQuery, CountDownLatch firstLine) {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + pathAndQuery))
                .header(USER_HEADER, user).header("Accept", "application/x-ndjson, text/plain, */*").GET()
                .timeout(Duration.ofSeconds(30)).build();
        try {
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            boolean monitored = response.headers().firstValue("X-Contexa-Monitored").map("true"::equals)
                    .orElse(false);
            List<String> lines = new ArrayList<>();
            boolean broken = false;
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(response.body(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    lines.add(line);
                    if (firstLine != null && lines.size() == 1) {
                        firstLine.countDown();
                    }
                }
            } catch (IOException e) {
                broken = true;
            }
            if (firstLine != null && lines.isEmpty()) {
                firstLine.countDown();
            }
            return new Reading(response.statusCode(), monitored, lines, broken);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    // ---- the application ----

    /** What the application wrote: when each successful write started, and whether a write failed. */
    static final class Progress {

        final List<Long> written = new CopyOnWriteArrayList<>();
        final CountDownLatch release = new CountDownLatch(1);
        volatile boolean failed;
        volatile boolean holding;

        long writtenAfter(long nanos) {
            return written.stream().filter(start -> start - nanos > 0).count();
        }
    }

    @RestController
    static class CutEndpoints {

        private final Map<String, Progress> progress = new ConcurrentHashMap<>();
        private final Map<String, Runnable> onEntry = new ConcurrentHashMap<>();

        void onEntry(String id, Runnable decision) {
            onEntry.put(id, decision);
        }

        /** As a synchronous @Protectable: the decision is made in the request and its BLOCK denies the request. */
        @GetMapping(value = "/cut/deny", produces = MediaType.APPLICATION_JSON_VALUE)
        String deny(@RequestParam("id") String id) {
            onEntry.getOrDefault(id, () -> {
            }).run();
            throw new ZeroTrustAccessDeniedException(ZeroTrustAction.BLOCK.name(), "cut.deny", 0.99,
                    "BLOCK made by the test");
        }

        Progress progress(String id) {
            return progress.computeIfAbsent(id, key -> new Progress());
        }

        private static byte[] row(int n) {
            return ("{\"row\":" + n + "}\n").getBytes(StandardCharsets.UTF_8);
        }

        private static void pause(long millis) throws IOException {
            try {
                Thread.sleep(millis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted", e);
            }
        }

        private static void rows(OutputStream out, int rows, long everyMs, Progress progress) throws IOException {
            for (int n = 1; n <= rows; n++) {
                long start = System.nanoTime();
                try {
                    out.write(row(n));
                    out.flush();
                } catch (IOException e) {
                    progress.failed = true;
                    throw e;
                }
                progress.written.add(start);
                pause(everyMs);
            }
        }

        @GetMapping(value = "/cut/sync", produces = MediaType.APPLICATION_NDJSON_VALUE)
        void sync(@RequestParam("rows") int rows, @RequestParam("everyMs") long everyMs, @RequestParam("id") String id,
                  HttpServletResponse response) throws IOException {
            response.setContentType(MediaType.APPLICATION_NDJSON_VALUE);
            rows(response.getOutputStream(), rows, everyMs, progress(id));
        }

        @GetMapping(value = "/cut/async", produces = MediaType.APPLICATION_NDJSON_VALUE)
        ResponseEntity<StreamingResponseBody> async(@RequestParam("rows") int rows, @RequestParam("everyMs") long everyMs,
                                                    @RequestParam("id") String id) {
            Progress written = progress(id);
            StreamingResponseBody body = out -> rows(out, rows, everyMs, written);
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_NDJSON).body(body);
        }

        @GetMapping(value = "/cut/writer", produces = MediaType.TEXT_PLAIN_VALUE)
        void writer(@RequestParam("rows") int rows, @RequestParam("everyMs") long everyMs, @RequestParam("id") String id,
                    HttpServletResponse response) throws IOException {
            response.setContentType(MediaType.TEXT_PLAIN_VALUE);
            PrintWriter writer = response.getWriter();
            Progress written = progress(id);
            for (int n = 1; n <= rows; n++) {
                long start = System.nanoTime();
                try {
                    writer.println("<p>row " + n + "</p>");
                    writer.flush();
                } catch (RuntimeException e) {
                    written.failed = true;
                    throw e;
                }
                written.written.add(start);
                pause(everyMs);
            }
        }

        /** Writes two rows into the buffer without flushing, waits for the test, then writes the third. */
        @GetMapping(value = "/cut/held", produces = MediaType.APPLICATION_NDJSON_VALUE)
        ResponseEntity<StreamingResponseBody> held(@RequestParam("async") boolean async, @RequestParam("id") String id,
                                                   HttpServletResponse response) throws IOException {
            Progress written = progress(id);
            StreamingResponseBody body = out -> {
                for (int n = 1; n <= 2; n++) {
                    written.written.add(System.nanoTime());
                    out.write(row(n));
                }
                written.holding = true;
                try {
                    if (!written.release.await(10, TimeUnit.SECONDS)) {
                        throw new IOException("not released");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted", e);
                }
                try {
                    out.write(row(3));
                    out.flush();
                } catch (IOException e) {
                    written.failed = true;
                    throw e;
                }
            };
            if (async) {
                return ResponseEntity.ok().contentType(MediaType.APPLICATION_NDJSON).body(body);
            }
            response.setContentType(MediaType.APPLICATION_NDJSON_VALUE);
            body.writeTo(response.getOutputStream());
            return null;
        }
    }

    /** Signs the request in as the user named by the header, as the security filter chain would. */
    static final class SignIn extends OncePerRequestFilter {

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String user = request.getHeader(USER_HEADER);
            if (user == null) {
                chain.doFilter(request, response);
                return;
            }
            SecurityContextHolder.setContext(new SecurityContextImpl(
                    UsernamePasswordAuthenticationToken.authenticated(user, null, List.of())));
            try {
                chain.doFilter(request, response);
            } finally {
                SecurityContextHolder.clearContext();
            }
        }
    }

    @SpringBootConfiguration
    @ImportAutoConfiguration({ServletWebServerFactoryAutoConfiguration.class, DispatcherServletAutoConfiguration.class,
            WebMvcAutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class, JacksonAutoConfiguration.class,
            TaskExecutionAutoConfiguration.class})
    static class Web {

        @Bean
        CutEndpoints cutEndpoints() {
            return new CutEndpoints();
        }

        @Bean
        ZeroTrustExceptionHandler zeroTrustExceptionHandler() {
            return new ZeroTrustExceptionHandler();
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
                    new ZeroTrustAccessControlFilter(decisions, mock(AuthResponseWriter.class), null, null, null,
                            signals, 2));
            registration.setOrder(2);
            return registration;
        }
    }
}

package io.contexa.showcase.workload.contexa.probe;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.context.OfficialContextField;
import io.contexa.contexacommon.security.context.RequestSecurityContextAttributes;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.showcase.business.internal.InternalContextAttributes;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.workload.contexa.ContexaWorkloadApplication;
import io.contexa.showcase.workload.contexa.inbox.DemoInboxEmailService;
import io.contexa.showcase.workload.contexa.probe.ProbeClient.RunIdentity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.UncheckedIOException;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Connection contract between the portal orchestrator and control D (docs/showcase/연결계약.md). Every probe runs
 * with its own fresh principal, the isolation unit of the showcase, against the real engine, the real login and
 * one-time code flow and the real enforcement filters. Skipped when Docker is unavailable.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = {ContexaWorkloadApplication.class, ProbeEndpoints.class, AnalysisHandOffRecording.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ConnectionContractProbeTest {

    private static final String SIGNING_KEY = ProbeDatabase.randomKey();
    private static final ObjectMapper JSON = ProbeRuns.JSON;
    private static final String BLOCK_MARKER = "__CONTEXA_RESPONSE_BLOCKED__:BLOCK";
    private static final String SESSION_COOKIE = "SHOWCASE_CONTEXA_SESSION";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        ProbeDatabase.register(registry, SIGNING_KEY);
        // The model client is constructed but never called: analysis hand-off is recorded instead (AnalysisHandOffRecording).
        registry.add("spring.ai.openai.api-key", () -> "probe-key-never-used");
    }

    @LocalServerPort
    private int port;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private DemoInboxEmailService inbox;

    @Autowired
    private ZeroTrustActionRepository actions;

    @Autowired
    private BlockingSignalBroadcaster blockingSignals;

    @Autowired
    private InternalContextSigner signer;

    @Autowired
    private ProbeEndpoints.ProtectableEventRecorder events;

    @Autowired
    private AnalysisHandOffRecording.AnalysisHandOffRecorder analysis;

    @Autowired
    private SecurityContextDataStore contextStore;

    @Autowired
    private UserManagementService userManagementService;

    @Test
    void probe1LoginCompletesTheEngineOneTimeCodeThroughTheDemoInbox() throws Exception {
        ProbeClient client = newRun();

        List<String> trail = signIn(client);

        assertThat(inbox.take(client.run().email())).as("the code is consumed once").isEmpty();
        HttpResponse<String> document = client.getJson("/probe/documents/p1");
        assertThat(document.statusCode()).as(trail + " then " + document.body()).isEqualTo(200);
    }

    @Test
    void probe2ObservedAtBecomesTheEngineEventTime() throws Exception {
        assertThat(InternalContextAttributes.OBSERVED_AT)
                .isEqualTo(RequestSecurityContextAttributes.Field.OBSERVED_AT.canonicalAttributeKey());
        ProbeClient client = newRun();
        signIn(client);
        Instant observedAt = Instant.parse("2026-09-28T23:40:00Z");

        ProbeClient.Call past = client.call("GET", "/probe/documents/p2-past").observedAt(observedAt);
        assertThat(past.send().statusCode()).isEqualTo(200);
        ProbeClient.Call now = client.call("GET", "/probe/documents/p2-now");
        Instant sentAt = Instant.now();
        assertThat(now.send().statusCode()).isEqualTo(200);

        assertThat(event(past.requestId()).getEventTimestamp()).isEqualTo(observedAt);
        assertThat(event(now.requestId()).getEventTimestamp())
                .isBetween(sentAt.minusSeconds(5), Instant.now().plusSeconds(5));
    }

    @Test
    void probe3RunScopeAndClientReachTheEngineOnlyThroughTheSignatureAndStayPerRun() throws Exception {
        assertThat(InternalContextAttributes.ORGANIZATION_ID)
                .isEqualTo(OfficialContextField.ORGANIZATION_ID.canonicalAttributeKey());
        assertThat(InternalContextAttributes.TENANT_ID)
                .isEqualTo(OfficialContextField.TENANT_ID.canonicalAttributeKey());
        ProbeClient first = newRun();
        ProbeClient second = newRun();
        signIn(first);
        signIn(second);

        ProbeClient.Call firstCall = first.call("GET", "/probe/documents/p3-first");
        ProbeClient.Call secondCall = second.call("GET", "/probe/documents/p3-second");
        assertThat(firstCall.send().statusCode()).isEqualTo(200);
        assertThat(secondCall.send().statusCode()).isEqualTo(200);
        assertRunContext(event(firstCall.requestId()), first.run(), firstCall.requestId());
        assertRunContext(event(secondCall.requestId()), second.run(), secondCall.requestId());

        ProbeClient.Call forged = first.call("GET", "/probe/documents/p3-forged")
                .signedWith(new InternalContextSigner(ProbeDatabase.randomKey()))
                .header("X-Request-ID", "client-chosen")
                .header("X-Forwarded-For", "198.51.100.7");
        assertThat(forged.send().statusCode()).isEqualTo(200);
        Map<String, Object> forgedPayload = events.byUser(first.run().username()).stream()
                .filter(event -> String.valueOf(event.getPayload().get("requestUri")).endsWith("/p3-forged"))
                .findFirst().orElseThrow().getPayload();
        assertThat(forgedPayload.get("requestId")).isNotIn("client-chosen", forged.requestId());
        assertThat(forgedPayload.get("clientIp")).isEqualTo("127.0.0.1");
        assertThat(forgedPayload.get("organizationId")).isNotEqualTo(first.run().organization());
        assertThat(forgedPayload.get("tenantId")).isNotEqualTo(first.run().tenant());

        actions.setBlockedFlag(first.run().username());
        HttpResponse<String> blocked = first.getJson("/probe/documents/p3-after-block");
        HttpResponse<String> untouched = second.getJson("/probe/documents/p3-other-run");
        assertThat(blocked.statusCode()).as(blocked.body()).isEqualTo(403);
        assertThat(untouched.statusCode()).as(untouched.body()).isEqualTo(200);
    }

    @Test
    void probe4ChallengeIsAnsweredWithTheInboxCodeAndTheReissuedRequestRunsUnderTheMfaAllow() throws Exception {
        ProbeClient client = newRun();
        signIn(client);
        RunIdentity run = client.run();
        actions.saveAction(run.username(), ZeroTrustAction.CHALLENGE, Map.of());
        String sessionBeforeMfa = client.cookie(SESSION_COOKIE);

        HttpResponse<String> challenged = client.getJson("/probe/documents/p4");
        Instant challengedAt = Instant.now();
        assertThat(challenged.statusCode()).as(challenged.body()).isEqualTo(401);
        assertThat(JSON.readTree(challenged.body()).path("error").asText()).isEqualTo("MFA_CHALLENGE_REQUIRED");

        List<String> trail = new ArrayList<>();
        completeOneTimeCode(client, trail);
        String sessionAfterMfa = client.cookie(SESSION_COOKIE);
        ProbeClient.Call reissue = client.call("GET", "/probe/documents/p4");
        HttpResponse<String> reissued = reissue.send();

        assertThat(reissued.statusCode()).as(trail + " then " + reissued.body()).isEqualTo(200);
        assertThat(Duration.between(challengedAt, Instant.now())).isLessThan(Duration.ofSeconds(15));
        assertThat(actions.getActionFromHash(run.username())).isEqualTo(ZeroTrustAction.ALLOW);
        // Finding F-2 (fixed in core): the MFA success rotates the session id (changeSessionId) and binds its ALLOW to
        // the rotated session, so the re-issued request runs under that ALLOW instead of being analysed again.
        String rotatedSessionHash = SessionFingerprintUtil.generateContextBindingHash(
                sessionAfterMfa, run.clientIp(), run.device());
        assertThat(sessionAfterMfa).isNotEqualTo(sessionBeforeMfa);
        assertThat(actions.getAnalysisData(run.username()).contextBindingHash()).isEqualTo(rotatedSessionHash);
        assertThat(event(reissue.requestId()).getPayload().get("contextBindingHash")).isEqualTo(rotatedSessionHash);
        assertThat(analysis.handedOff(reissue.requestId())).isFalse();
    }

    @Test
    void probe5EscalateAnswers423WithRetryAfterAndStaysUnderReview() throws Exception {
        ProbeClient client = newRun();
        signIn(client);
        actions.saveAction(client.run().username(), ZeroTrustAction.ESCALATE, Map.of());

        HttpResponse<String> first = client.getJson("/probe/documents/p5-first");
        HttpResponse<String> second = client.getJson("/probe/documents/p5-second");

        for (HttpResponse<String> response : List.of(first, second)) {
            assertThat(response.statusCode()).as(response.body()).isEqualTo(423);
            assertThat(response.headers().firstValue("Retry-After")).hasValue("30");
            assertThat(JSON.readTree(response.body()).path("error").asText()).isEqualTo("SECURITY_REVIEW_IN_PROGRESS");
        }
        // No reviewer API exists and the stored ESCALATE expires to PENDING_ANALYSIS after its TTL; it is not
        // promoted to BLOCK (finding recorded in docs/showcase/P0-검수.md).
        assertThat(actions.getCurrentAction(client.run().username())).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(ZeroTrustAction.ESCALATE.getDefaultTtl()).isEqualTo(Duration.ofMinutes(5));
    }

    @Test
    void probe6PendingAnalysisWrapsTheAsyncStreamAndABlockDecisionCutsItMidway() throws Exception {
        ProbeClient client = newRun();
        signIn(client);
        String user = client.run().username();
        awaitAction(user, ZeroTrustAction.PENDING_ANALYSIS, Duration.ofSeconds(25));

        HttpResponse<Stream<String>> response = client.call("GET", "/probe/stream?rows=50")
                .accept("application/x-ndjson").sendStreaming();
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("X-Contexa-Monitored")).hasValue("true");

        List<String> lines = new ArrayList<>();
        Iterator<String> reader = response.body().iterator();
        try {
            while (reader.hasNext()) {
                lines.add(reader.next());
                if (lines.size() == 3) {
                    // Same order as SecurityDecisionEnforcementHandler applies a BLOCK decision.
                    actions.setBlockedFlag(user);
                    blockingSignals.registerBlockAndAwait(user);
                }
            }
        } catch (UncheckedIOException expected) {
            // The engine aborts the response after the marker; the stream ends without a final chunk.
        }

        assertThat(lines).as("stream lines").contains(BLOCK_MARKER);
        long rows = lines.stream().filter(line -> line.startsWith("{\"row\":")).count();
        assertThat(rows).as("rows delivered before the cut").isBetween(3L, 49L);
    }

    @Test
    void probe7DeletingAnAccountPurgesItsEngineStateBeforeTheNameIsReused() throws Exception {
        ProbeClient client = newRun();
        signIn(client);
        RunIdentity run = client.run();
        actions.setBlockedFlag(run.username());
        contextStore.markMfaVerified(run.username());
        HttpResponse<String> blocked = client.getJson("/probe/documents/p7-blocked");
        assertThat(blocked.statusCode()).as(blocked.body()).isEqualTo(403);

        Long accountId = users.findByUsername(run.username()).orElseThrow().getId();
        asAdministrator(() -> userManagementService.deleteUser(accountId));

        assertThat(users.findByUsername(run.username())).isEmpty();
        assertThat(actions.getCurrentAction(run.username())).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(contextStore.isMfaVerified(run.username())).isFalse();
        ProbeClient reused = runs().recreate(run);
        signIn(reused);
        HttpResponse<String> fresh = reused.getJson("/probe/documents/p7-reused");
        assertThat(fresh.statusCode()).as("a new account with the same name starts clean: " + fresh.body())
                .isEqualTo(200);
    }

    private static void asAdministrator(Runnable action) {
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                "probe-administrator", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));
        try {
            action.run();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private ProbeRuns runs() {
        return new ProbeRuns(users, passwordEncoder, inbox, signer, port);
    }

    private ProbeClient newRun() {
        return runs().newRun();
    }

    private List<String> signIn(ProbeClient client) throws Exception {
        return runs().signIn(client);
    }

    private void completeOneTimeCode(ProbeClient client, List<String> trail) throws Exception {
        runs().completeOneTimeCode(client, trail);
    }

    private ZeroTrustSpringEvent event(String requestId) {
        return events.byRequestId(requestId)
                .orElseThrow(() -> new AssertionError("no engine event for request " + requestId));
    }

    private static void assertRunContext(ZeroTrustSpringEvent event, RunIdentity run, String requestId) {
        assertThat(event.getUserId()).isEqualTo(run.username());
        assertThat(event.getPayload())
                .containsEntry("requestId", requestId)
                .containsEntry("organizationId", run.organization())
                .containsEntry("tenantId", run.tenant())
                .containsEntry("clientIp", run.clientIp())
                .containsEntry("userAgent", run.device());
    }

    private void awaitAction(String user, ZeroTrustAction expected, Duration timeout) throws InterruptedException {
        Instant deadline = Instant.now().plus(timeout);
        while (actions.getCurrentAction(user) != expected && Instant.now().isBefore(deadline)) {
            Thread.sleep(250);
        }
        assertThat(actions.getCurrentAction(user)).isEqualTo(expected);
    }

}

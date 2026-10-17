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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.context.collector.DefaultProtectableWorkProfileCollector;
import io.contexa.contexacore.autonomous.context.collector.DefaultSessionNarrativeCollector;
import io.contexa.contexacore.autonomous.context.collector.SessionNarrativeSnapshot;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/**
 * N-SES-1: a request answered by the decision already in force (an ALLOW still valid, a stored restriction, the
 * request sent again after a passed step-up) is not analysed, yet it is part of what its session did. N-LRN-3: of
 * those, only the first request sent again after a passed step-up of the ones a filter stopped is learned.
 */
class UnanalysedRequestRecorderTest {

    private static final String SESSION = "session-1";
    private static final String EXPORTS = "/api/projects/GB-500/exports";
    private static final String CUSTOMER = "/api/customers/CUS-0012";
    private static final Authentication ALICE = new UsernamePasswordAuthenticationToken("alice", "n/a", List.of());

    private InMemorySecurityContextDataStore store;
    private ContextObservationRecorder recorder;
    private DefaultSessionNarrativeCollector collector;
    private UnanalysedRequestRecorder unanalysed;

    @BeforeEach
    void setUp() {
        store = new InMemorySecurityContextDataStore();
        recorder = new ContextObservationRecorder(store);
        collector = new DefaultSessionNarrativeCollector(store, recorder);
        unanalysed = new UnanalysedRequestRecorder(collector, recorder, null, null);
    }

    @Test
    void anUnanalysedRequestIsLearnedOnlyAsTheFirstOneSentAgainOfTheRequestsAStepUpVerified() {
        // N-LRN-3 changes this test (P2 W5-2 design 1): a request a filter stopped under a CHALLENGE was kept as a fact
        // of its session only, because a stopped request carries no method facts (P2-CHANGE-24). Sent again after the
        // user passed the step-up, it reaches the protected method with them and is the verified user's request, so
        // the first one sent again is learned as the challenged request is. Any other request answered by the decision
        // in force is still not learned, and what is staged for it later is never committed (W5-3 D4).
        SecurityLearningService learning = mock(SecurityLearningService.class);
        VerificationLearningService verification = verification(learning);
        UnanalysedRequestRecorder learningRecorder = learningRecorder(verification);
        learningRecorder.recordRequest(ALICE, ZeroTrustAction.CHALLENGE);
        verification.learnStepUp("alice", "request-challenged");

        ZeroTrustSpringEvent resent = event("request-resent", "2026-09-30T03:19:00Z", 20);
        learningRecorder.record(read("request-read", "2026-09-30T03:18:55Z"), ZeroTrustAction.ALLOW);
        learningRecorder.record(resent, ZeroTrustAction.ALLOW);
        learningRecorder.record(event("request-again", "2026-09-30T03:19:05Z", 20), ZeroTrustAction.ALLOW);

        ArgumentCaptor<SecurityEvent> learned = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(learning).learnVerifiedResend(eq("alice"), any(SecurityDecision.class), learned.capture());
        verifyNoMoreInteractions(learning);
        assertThat(learned.getValue().getMetadata())
                .containsEntry("requestId", "request-resent")
                .containsEntry("requestItems", 20)
                .containsEntry("verifiedBy", "STEP_UP")
                .containsEntry("verificationWeight", 0.5);
        // The work profile learns it with its item count at the reduced weight, as the challenged request.
        assertThat(store.getRecentWorkProfileObservations(null, "alice", 10)).singleElement().satisfies(line -> {
            String[] fields = line.split("\\|", -1);
            assertThat(new String(Base64.getUrlDecoder().decode(fields[21]), StandardCharsets.UTF_8)).isEqualTo("20");
            assertThat(fields[22]).isEqualTo("0.5");
        });

        SecurityEvent request = ZeroTrustSecurityEventConverter.convert(resent);
        List<Boolean> staged = new ArrayList<>();
        recorder.stage(request, ContextObservationRecorder.WORK_PROFILE, null,
                commit -> staged.add(commit.learnable()));
        recorder.commit(request, ZeroTrustAction.ALLOW.name(), true);

        assertThat(recorder.committed(request)).isTrue();
        assertThat(staged).isEmpty();
    }

    @Test
    void aRequestStoppedUnderABlockOrSentAgainBeforeTheStepUpIsNotLearned() {
        // N-LRN-3: only the step-up a CHALLENGE asks for verifies the request a filter stopped, and only once passed.
        SecurityLearningService learning = mock(SecurityLearningService.class);
        VerificationLearningService verification = verification(learning);
        UnanalysedRequestRecorder learningRecorder = learningRecorder(verification);

        learningRecorder.recordRequest(ALICE, ZeroTrustAction.BLOCK);
        verification.learnStepUp("alice", "request-blocked");
        learningRecorder.record(event("request-after-block", "2026-09-30T03:19:00Z", 20), ZeroTrustAction.ALLOW);
        learningRecorder.recordRequest(ALICE, ZeroTrustAction.CHALLENGE);
        learningRecorder.record(event("request-before-step-up", "2026-09-30T03:20:00Z", 20), ZeroTrustAction.ALLOW);

        verify(learning, never()).learnVerifiedResend(any(), any(), any());
        assertThat(store.getRecentWorkProfileObservations(null, "alice", 10)).isEmpty();
    }

    @Test
    void anAllowedRequestThatWasNotAnalysedIsRecordedInItsSessionOnce() {
        ZeroTrustSpringEvent event = event("request-1", "2026-09-30T03:17:00Z", 300);

        unanalysed.record(event, ZeroTrustAction.ALLOW);
        unanalysed.record(event, ZeroTrustAction.ALLOW);

        assertThat(store.getRecentSessionDecisions(SESSION, 10)).singleElement().satisfies(line -> {
            SessionDecisionRecord decision = SessionDecisionRecord.decode(line);
            assertThat(decision.outcome()).isEqualTo("ALLOW");
            assertThat(decision.path()).isEqualTo(EXPORTS);
            assertThat(decision.items()).isEqualTo(300);
        });
        assertThat(store.getRecentSessionProtectableAccesses(SESSION, 10)).containsExactly(EXPORTS);
        assertThat(store.getSessionLastRequestTime(SESSION))
                .isEqualTo(Instant.parse("2026-09-30T03:17:00Z").toEpochMilli());
    }

    @Test
    void aRestrictedRequestIsRecordedUnderTheRestrictionInForce() {
        unanalysed.record(event("request-1", "2026-09-30T03:17:00Z", 300), ZeroTrustAction.ALLOW);
        unanalysed.record(event("request-2", "2026-09-30T03:18:00Z", 200), ZeroTrustAction.CHALLENGE);

        assertThat(store.getRecentSessionDecisions(SESSION, 10))
                .extracting(line -> SessionDecisionRecord.decode(line).outcome())
                .containsExactly("ALLOW", "CHALLENGE");
        assertThat(store.getRecentSessionProtectableAccesses(SESSION, 10)).containsExactly(EXPORTS, EXPORTS);
    }

    @Test
    void noDecisionInForceRecordsNothingSinceTheRequestIsAnalysed() {
        unanalysed.record(event("request-1", "2026-09-30T03:17:00Z", 300), ZeroTrustAction.PENDING_ANALYSIS);
        unanalysed.record(event("request-2", "2026-09-30T03:18:00Z", 300), null);
        unanalysed.record(null, ZeroTrustAction.ALLOW);

        assertThat(store.getRecentSessionDecisions(SESSION, 10)).isEmpty();
        assertThat(store.getRecentSessionProtectableAccesses(SESSION, 10)).isEmpty();
        assertThat(store.getSessionLastRequestTime(SESSION)).isNull();
    }

    @Test
    void aRequestItsAnalysisAlreadyRecordedIsNotRecordedAgain() {
        ZeroTrustSpringEvent event = event("request-1", "2026-09-30T03:17:00Z", 300);
        recorder.commit(ZeroTrustSecurityEventConverter.convert(event), "BLOCK", true);

        unanalysed.record(event, ZeroTrustAction.ALLOW);

        assertThat(store.getRecentSessionDecisions(SESSION, 10)).singleElement()
                .satisfies(line -> assertThat(SessionDecisionRecord.decode(line).outcome()).isEqualTo("BLOCK"));
    }

    @Test
    void theNextAnalysedRequestSeesWhatTheSessionAlreadyExportedUnderTheDecisionInForce() {
        unanalysed.record(event("request-1", "2026-09-30T03:17:00Z", 300), ZeroTrustAction.ALLOW);

        SecurityEvent next = ZeroTrustSecurityEventConverter.convert(event("request-2", "2026-09-30T03:17:20Z", 200));
        SessionNarrativeSnapshot snapshot = collector.collect(next).orElseThrow();

        List<SessionDecisionRecord> decisions = snapshot.getSessionDecisions();
        assertThat(decisions).singleElement().satisfies(decision -> {
            assertThat(decision.outcome()).isEqualTo("ALLOW");
            assertThat(decision.items()).isEqualTo(300);
            assertThat(decision.target()).isNotNull();
        });
        assertThat(snapshot.getSessionProtectableSequence()).containsExactly(EXPORTS, EXPORTS);
        assertThat(snapshot.getLastRequestIntervalMs()).isEqualTo(20_000L);
    }

    @Test
    void aRequestAWebFilterStoppedIsRecordedUnderTheActionInForce() {
        ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
        Authentication authentication = new UsernamePasswordAuthenticationToken("alice", "n/a", List.of());
        Map<String, Object> payload = new HashMap<>();
        payload.put("requestId", "request-9");
        payload.put("httpMethod", "GET");
        payload.put("requestPath", "/api/customers/CUS-0012");
        payload.put("granted", false);
        payload.put("authorizationCheck", "URL_POLICY");
        ZeroTrustSpringEvent stopped = ZeroTrustSpringEvent.builder(UnanalysedRequestRecorderTest.class)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId("alice")
                .sessionId(SESSION)
                .resource("/api/customers/CUS-0012")
                .eventTimestamp(Instant.parse("2026-09-30T03:18:00Z"))
                .payload(payload)
                .build();
        when(publisher.buildRequestAuthorizationEvent(authentication, false, "CHALLENGE")).thenReturn(stopped);
        UnanalysedRequestRecorder withPublisher = new UnanalysedRequestRecorder(collector, recorder, null, publisher);

        withPublisher.recordRequest(authentication, ZeroTrustAction.CHALLENGE);
        withPublisher.recordRequest(authentication, ZeroTrustAction.PENDING_ANALYSIS);
        withPublisher.recordRequest(null, ZeroTrustAction.CHALLENGE);

        assertThat(store.getRecentSessionDecisions(SESSION, 10)).singleElement().satisfies(line -> {
            SessionDecisionRecord decision = SessionDecisionRecord.decode(line);
            assertThat(decision.outcome()).isEqualTo("CHALLENGE");
            assertThat(decision.path()).isEqualTo("/api/customers/CUS-0012");
        });
        assertThat(store.getSessionLastRequestTime(SESSION))
                .isEqualTo(Instant.parse("2026-09-30T03:18:00Z").toEpochMilli());
    }

    private VerificationLearningService verification(SecurityLearningService learning) {
        return new VerificationLearningService(store, learning, new DefaultProtectableWorkProfileCollector(store),
                null);
    }

    /** A recorder whose web filter stops the user's export under the action in force, before the step-up. */
    private UnanalysedRequestRecorder learningRecorder(VerificationLearningService verification) {
        ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
        when(publisher.buildRequestAuthorizationEvent(eq(ALICE), eq(false), anyString())).thenReturn(stoppedExport());
        UnanalysedRequestRecorder stopping = new UnanalysedRequestRecorder(collector, recorder, null, publisher);
        stopping.setVerificationLearningService(verification);
        return stopping;
    }

    /** The export as the filter stopped it: its method and URI, no method facts, in the session before the step-up. */
    private static ZeroTrustSpringEvent stoppedExport() {
        Map<String, Object> payload = new HashMap<>();
        payload.put("requestId", "request-stopped");
        payload.put("httpMethod", "POST");
        payload.put("requestUri", EXPORTS);
        payload.put("requestPath", EXPORTS);
        payload.put("granted", false);
        payload.put("authorizationCheck", "URL_POLICY");
        return ZeroTrustSpringEvent.builder(UnanalysedRequestRecorderTest.class)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId("alice")
                .sessionId("session-0")
                .resource(EXPORTS)
                .eventTimestamp(Instant.parse("2026-09-30T03:18:00Z"))
                .payload(payload)
                .build();
    }

    /** Another protected request of the session, a customer read, answered by the decision in force. */
    private static ZeroTrustSpringEvent read(String requestId, String at) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("requestId", requestId);
        payload.put("httpMethod", "GET");
        payload.put("requestPath", CUSTOMER);
        payload.put("protectableResourceId", "ops.Customers#customer");
        payload.put("granted", true);
        payload.put("className", "ops.Customers");
        payload.put("methodName", "customer");
        return ZeroTrustSpringEvent.builder(UnanalysedRequestRecorderTest.class)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId("alice")
                .sessionId(SESSION)
                .resource(CUSTOMER)
                .eventTimestamp(Instant.parse(at))
                .payload(payload)
                .build();
    }

    private static ZeroTrustSpringEvent event(String requestId, String at, int items) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("requestId", requestId);
        payload.put("httpMethod", "POST");
        payload.put("requestPath", EXPORTS);
        payload.put("protectableResourceUrl", "/api/projects/{projectId}/exports");
        payload.put("protectableResourceId", "ops.Documents#exportDocuments");
        payload.put("protectableDeclared", true);
        payload.put("granted", true);
        payload.put("className", "ops.Documents");
        payload.put("methodName", "exportDocuments");
        payload.put("requestItems", items);
        return ZeroTrustSpringEvent.builder(UnanalysedRequestRecorderTest.class)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId("alice")
                .sessionId(SESSION)
                .clientIp("203.0.113.10")
                .userAgent("JUnit")
                .resource(EXPORTS)
                .eventTimestamp(Instant.parse(at))
                .payload(payload)
                .build();
    }
}

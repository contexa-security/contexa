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
import io.contexa.contexacore.autonomous.context.collector.DefaultSessionNarrativeCollector;
import io.contexa.contexacore.autonomous.context.collector.SessionNarrativeSnapshot;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * N-SES-1: a request answered by the decision already in force (an ALLOW still valid, a stored restriction, the
 * request sent again after a passed step-up) is not analysed, yet it is part of what its session did.
 */
class UnanalysedRequestRecorderTest {

    private static final String SESSION = "session-1";
    private static final String EXPORTS = "/api/projects/GB-500/exports";

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
    void observationsStagedAfterARequestWasRecordedUnanalysedAreNeverLearned() {
        ZeroTrustSpringEvent event = event("request-late", "2026-09-30T03:17:00Z", 300);
        unanalysed.record(event, ZeroTrustAction.ALLOW);
        SecurityEvent request = ZeroTrustSecurityEventConverter.convert(event);
        List<Boolean> learned = new ArrayList<>();

        // A request answered by the decision in force is not analysed, so it stages nothing to learn; what is staged
        // for it later is never committed (W5-3 D4).
        recorder.stage(request, ContextObservationRecorder.WORK_PROFILE, null,
                commit -> learned.add(commit.learnable()));
        recorder.commit(request, ZeroTrustAction.ALLOW.name(), true);

        assertThat(recorder.committed(request)).isTrue();
        assertThat(learned).isEmpty();
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

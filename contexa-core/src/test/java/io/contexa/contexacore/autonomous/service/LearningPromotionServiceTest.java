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
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.collector.ProtectableWorkProfileCollector;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.Deviation;
import io.contexa.contexacore.autonomous.context.decision.DeviationDimension;
import io.contexa.contexacore.autonomous.context.decision.LearningPromotionPolicy;
import io.contexa.contexacore.autonomous.context.decision.PolicySatisfaction;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.support.VocabularyVersion;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * W5-1 (plan L1): an allowed request whose first-seen time, day, network or device on a sensitive resource no record
 * explains is held back; it is learned from its own facts once every value it held is held on two different days, or
 * once the user passes a verification on a request with the value.
 */
class LearningPromotionServiceTest {

    private static final String DEVICE = "Safari/18 on MAC";

    private InMemorySecurityContextDataStore store;
    private SecurityLearningService learning;
    private ProtectableWorkProfileCollector workProfile;
    private SecurityZeroTrustProperties properties;
    private LearningPromotionService service;

    @BeforeEach
    void setUp() {
        store = new InMemorySecurityContextDataStore();
        learning = mock(SecurityLearningService.class);
        workProfile = mock(ProtectableWorkProfileCollector.class);
        properties = new SecurityZeroTrustProperties();
        service = new LearningPromotionService(store, learning, workProfile, properties);
    }

    @Test
    void aRequestWithAnUnexplainedFirstSeenValueOnASensitiveResourceIsMarkedHeld() {
        SecurityEvent held = event("r-1", "2026-09-29T06:00:00Z", "CRITICAL", device(DEVICE));
        SecurityEvent normal = event("r-2", "2026-09-29T06:00:00Z", "NORMAL", device(DEVICE));

        assertThat(service.holds(held)).isTrue();
        assertThat(held.getMetadata()).containsEntry(VectorDocumentMetadata.LEARNING_STATE,
                VectorDocumentMetadata.LEARNING_STATE_HELD);
        assertThat(service.holds(normal)).isFalse();
        assertThat(normal.getMetadata()).doesNotContainKey(VectorDocumentMetadata.LEARNING_STATE);

        properties.getBaseline().getPromotion().setEnabled(false);
        assertThat(service.holds(event("r-3", "2026-09-29T06:00:00Z", "CRITICAL", device(DEVICE)))).isFalse();
    }

    @Test
    void theFirstHeldRequestWaitsAndOneOnTheSameDayDoesNotPromoteIt() {
        service.hold(event("r-1", "2026-09-29T06:00:00Z", "CRITICAL", device(DEVICE)));
        service.hold(event("r-2", "2026-09-29T08:00:00Z", "CRITICAL", device(DEVICE)));

        assertThat(store.promotionLearning("alice")).containsOnlyKeys("r-1", "r-2");
        verify(learning, never()).learnPromoted(anyString(), any(), any());
        verify(workProfile, never()).recordVerified(any(), eq(1.0));
    }

    @Test
    void theSameValueHeldOnAnotherDayPromotesBothRequestsFromTheirOwnFacts() {
        service.hold(event("r-1", "2026-09-29T06:00:00Z", "CRITICAL", device(DEVICE)));
        service.hold(event("r-2", "2026-09-30T06:00:00Z", "CRITICAL", device(DEVICE)));

        ArgumentCaptor<SecurityEvent> learned = ArgumentCaptor.forClass(SecurityEvent.class);
        ArgumentCaptor<SecurityDecision> decision = ArgumentCaptor.forClass(SecurityDecision.class);
        verify(learning, times(2)).learnPromoted(eq("alice"), decision.capture(), learned.capture());
        assertThat(learned.getAllValues()).extracting(SecurityEvent::getEventId)
                .containsExactlyInAnyOrder("event-r-1", "event-r-2");
        assertThat(learned.getAllValues()).extracting(SecurityEvent::getTimestamp).containsExactlyInAnyOrder(
                Instant.parse("2026-09-29T06:00:00Z"), Instant.parse("2026-09-30T06:00:00Z"));
        assertThat(learned.getAllValues()).allSatisfy(event -> {
            assertThat(event.getMetadata()).doesNotContainKey(VectorDocumentMetadata.LEARNING_STATE);
            assertThat(event.getMetadata()).containsEntry("requestPath", "/api/projects/GB-500/exports");
        });
        assertThat(decision.getAllValues()).extracting(SecurityDecision::getAction)
                .containsOnly(ZeroTrustAction.ALLOW);
        verify(workProfile, times(2)).recordVerified(any(SecurityEvent.class), eq(1.0));
        assertThat(store.promotionLearning("alice")).isEmpty();
    }

    @Test
    void aRequestWaitsWhileAnotherValueItHeldIsNotYetPromoted() {
        service.hold(event("r-1", "2026-09-29T03:00:00Z", "CRITICAL", device(DEVICE), time("03")));
        service.hold(event("r-2", "2026-09-30T06:00:00Z", "CRITICAL", device(DEVICE), time("06")));

        verify(learning, never()).learnPromoted(anyString(), any(), any());
        assertThat(store.promotionLearning("alice")).containsOnlyKeys("r-1", "r-2");
    }

    @Test
    void aVerifiedRequestWithTheValuePromotesTheHeldRequestsUnlessTheHostTurnsItOff() {
        service.hold(event("r-1", "2026-09-29T06:00:00Z", "CRITICAL", device(DEVICE)));
        service.hold(event("r-2", "2026-09-29T06:30:00Z", "CRITICAL", device("Edge/140 on WINDOWS")));

        properties.getBaseline().getPromotion().setVerifiedPromotes(false);
        service.promoteVerified("alice", List.of("DEVICE=" + DEVICE));
        verify(learning, never()).learnPromoted(anyString(), any(), any());

        properties.getBaseline().getPromotion().setVerifiedPromotes(true);
        service.promoteVerified("alice", List.of("DEVICE=" + DEVICE, "NETWORK=10.40.12.0/24"));
        ArgumentCaptor<SecurityEvent> learned = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(learning).learnPromoted(eq("alice"), any(), learned.capture());
        assertThat(learned.getValue().getEventId()).isEqualTo("event-r-1");
        assertThat(store.promotionLearning("alice")).containsOnlyKeys("r-2");
    }

    private static Deviation device(String value) {
        return new Deviation(DeviationDimension.DEVICE, value, true, true, 0, 25, null,
                Deviation.Explanation.UNEXPLAINED, null);
    }

    @Test
    @SuppressWarnings("unchecked")
    void aHeldRecordSaysItsVocabularyAndAnUnstampedOneIsReadInTodays() throws Exception {
        ObjectMapper json = new ObjectMapper();
        service.hold(event("r-1", "2026-09-29T06:00:00Z", "CRITICAL", network("10.40.12.0/24")));
        Map<String, Object> record = json.readValue(store.promotionLearning("alice").get("r-1"), Map.class);
        assertThat(record).containsEntry("vocabularyVersion", VocabularyVersion.CURRENT);

        // A record of an earlier build: no version, the network in the three-octet form it was learned in.
        record.remove("vocabularyVersion");
        record.put("values", List.of("NETWORK=10.40.12"));
        record.put("day", "2026-09-28");
        store.holdPromotionLearning("alice", "r-0", json.writeValueAsString(record));
        service.hold(event("r-2", "2026-09-30T06:00:00Z", "CRITICAL", network("10.40.12.0/24")));

        // Read in today's form, the earlier record's network is the same value on a third day: all three are learned.
        verify(learning, times(3)).learnPromoted(eq("alice"), any(), any());
        assertThat(store.promotionLearning("alice")).isEmpty();
    }

    private static Deviation network(String value) {
        return new Deviation(DeviationDimension.NETWORK, value, true, true, 0, 25, null,
                Deviation.Explanation.UNEXPLAINED, null);
    }

    private static Deviation time(String value) {
        return new Deviation(DeviationDimension.TIME, value, true, true, 0, 25, null,
                Deviation.Explanation.UNEXPLAINED, null);
    }

    /**
     * docs/agent A3-7: an agent's held requests are kept apart from the person's (under the agent's learning key) and,
     * promoted, are learned as the requests of their own user, the agent's own key coming from the request.
     */
    @Test
    void anAgentsHeldRequestsAreKeptApartAndPromotedAsTheirOwnUsers() {
        SecurityEvent first = agent(event("a-1", "2026-09-29T06:00:00Z", "NORMAL", device(DEVICE)));
        SecurityEvent second = agent(event("a-2", "2026-09-30T06:00:00Z", "NORMAL", device(DEVICE)));

        service.hold(first);
        assertThat(store.promotionLearning("alice::agent::report-agent")).hasSize(1);
        assertThat(store.promotionLearning("alice")).isEmpty();
        service.hold(second);

        verify(learning, times(2)).learnPromoted(eq("alice"), any(), any());
        assertThat(store.promotionLearning("alice::agent::report-agent")).isEmpty();
    }

    /**
     * QF-19: an agent's held target is the target it names, not the name of the template variable. Two different new
     * projects held on two days are two values and neither is promoted; the same project held on two days is.
     */
    @Test
    @SuppressWarnings("unchecked")
    void anAgentsHeldTargetIsTheTargetItNamesNotTheVariableName() throws Exception {
        service.hold(agent(target(event("t-1", "2026-09-29T06:00:00Z", "NORMAL", unexplained(DeviationDimension.TARGET,
                "projectKey")), "HX-310")));
        service.hold(agent(target(event("t-2", "2026-09-30T06:00:00Z", "NORMAL", unexplained(DeviationDimension.TARGET,
                "projectKey")), "ZZ-999")));

        verify(learning, never()).learnPromoted(anyString(), any(), any());
        assertThat(store.promotionLearning("alice::agent::report-agent")).containsOnlyKeys("t-1", "t-2");
        // The kept value names the target by its digest, never by the requester's text (N-INJ-1).
        Map<String, Object> record = new ObjectMapper().readValue(
                store.promotionLearning("alice::agent::report-agent").get("t-1"), Map.class);
        assertThat((List<String>) record.get("values")).singleElement()
                .satisfies(value -> assertThat(value).startsWith("TARGET=projectKey#").doesNotContain("HX-310"));

        service.hold(agent(target(event("t-3", "2026-10-01T06:00:00Z", "NORMAL", unexplained(DeviationDimension.TARGET,
                "projectKey")), "HX-310")));

        ArgumentCaptor<SecurityEvent> learned = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(learning, times(2)).learnPromoted(eq("alice"), any(), learned.capture());
        assertThat(learned.getAllValues()).extracting(SecurityEvent::getEventId)
                .containsExactlyInAnyOrder("event-t-1", "event-t-3");
        assertThat(store.promotionLearning("alice::agent::report-agent")).containsOnlyKeys("t-2");
    }

    /**
     * QF-19: an agent's held size and rate are the order of magnitude of the count, not the sentence with the count: a
     * close count on another day is the same value, a count many times larger is another.
     */
    @Test
    void anAgentsHeldSizeAndRateAreTheirOrderOfMagnitude() {
        service.hold(agent(event("s-1", "2026-09-29T06:00:00Z", "NORMAL",
                unexplained(DeviationDimension.SIZE, "1,200 items"))));
        service.hold(agent(event("s-2", "2026-09-30T06:00:00Z", "NORMAL",
                unexplained(DeviationDimension.SIZE, "48,000 items"))));
        verify(learning, never()).learnPromoted(anyString(), any(), any());

        service.hold(agent(event("s-3", "2026-09-30T07:00:00Z", "NORMAL",
                unexplained(DeviationDimension.SIZE, "1,250 items"))));
        service.hold(agent(event("r-1", "2026-09-29T06:00:00Z", "NORMAL",
                unexplained(DeviationDimension.RATE, "40 requests in the last 60 min"))));
        service.hold(agent(event("r-2", "2026-09-30T06:00:00Z", "NORMAL",
                unexplained(DeviationDimension.RATE, "45 requests in the last 60 min of this session"))));

        ArgumentCaptor<SecurityEvent> learned = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(learning, times(4)).learnPromoted(eq("alice"), any(), learned.capture());
        assertThat(learned.getAllValues()).extracting(SecurityEvent::getEventId)
                .containsExactlyInAnyOrder("event-s-1", "event-s-3", "event-r-1", "event-r-2");
        assertThat(store.promotionLearning("alice::agent::report-agent")).containsOnlyKeys("s-2");
    }

    /**
     * QF-29: the held requests of a user are kept apart by tenant, as the user's baseline is: the same user id in two
     * tenants is two users, and a value each held on one day is promoted in neither.
     */
    @Test
    void theHeldRequestsOfOneUserIdInTwoTenantsAreKeptApart() {
        service.hold(tenant(event("a-1", "2026-09-29T06:00:00Z", "CRITICAL", device(DEVICE)), "tenant-a"));
        service.hold(tenant(event("b-1", "2026-09-30T06:00:00Z", "CRITICAL", device(DEVICE)), "tenant-b"));

        verify(learning, never()).learnPromoted(anyString(), any(), any());
        assertThat(store.promotionLearning("tenant-a::alice")).containsOnlyKeys("a-1");
        assertThat(store.promotionLearning("tenant-b::alice")).containsOnlyKeys("b-1");
        assertThat(store.promotionLearning("alice")).isEmpty();
    }

    /**
     * QF-28: two requests of the same user held at once do not both read the held requests and learn them twice; the
     * reading, learning and removing of one promotion runs before the other's.
     */
    @Test
    void twoHoldsAtOnceLearnEachHeldRequestOnce() throws Exception {
        CountDownLatch secondRead = new CountDownLatch(1);
        AtomicInteger reads = new AtomicInteger();
        InMemorySecurityContextDataStore racing = new InMemorySecurityContextDataStore() {
            @Override
            public Map<String, String> promotionLearning(String userId) {
                Map<String, String> held = super.promotionLearning(userId);
                if (reads.incrementAndGet() == 3) {
                    secondRead.countDown();
                }
                return held;
            }
        };
        List<String> learnedIds = new CopyOnWriteArrayList<>();
        doAnswer(call -> {
            // The first promotion waits while learning until the other hold has read the held requests (or a second).
            if (learnedIds.isEmpty()) {
                secondRead.await(1, TimeUnit.SECONDS);
            }
            learnedIds.add(call.<SecurityEvent>getArgument(2).getEventId());
            return null;
        }).when(learning).learnPromoted(anyString(), any(), any());
        LearningPromotionService racingService = new LearningPromotionService(racing, learning, workProfile,
                properties);
        racingService.hold(event("r-1", "2026-09-29T06:00:00Z", "CRITICAL", device(DEVICE)));

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> first = executor.submit(() -> racingService.hold(
                    event("r-2", "2026-09-30T06:00:00Z", "CRITICAL", device(DEVICE))));
            Future<?> second = executor.submit(() -> racingService.hold(
                    event("r-3", "2026-09-30T07:00:00Z", "CRITICAL", device(DEVICE))));
            first.get(10, TimeUnit.SECONDS);
            second.get(10, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }

        assertThat(learnedIds).as("each held request is learned at most once").doesNotHaveDuplicates();
        assertThat(learnedIds).isNotEmpty();
    }

    /** QF-29: a verification in one tenant vouches for the held requests of the user in that tenant only. */
    @Test
    void aVerificationVouchesForTheHeldRequestsOfItsTenantOnly() {
        service.hold(tenant(event("a-1", "2026-09-29T06:00:00Z", "CRITICAL", device(DEVICE)), "tenant-a"));
        service.hold(tenant(event("b-1", "2026-09-29T06:00:00Z", "CRITICAL", device(DEVICE)), "tenant-b"));

        service.promoteVerified("tenant-a", "alice", List.of("DEVICE=" + DEVICE));

        ArgumentCaptor<SecurityEvent> learned = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(learning).learnPromoted(eq("alice"), any(), learned.capture());
        assertThat(learned.getValue().getEventId()).isEqualTo("event-a-1");
        assertThat(store.promotionLearning("tenant-a::alice")).isEmpty();
        assertThat(store.promotionLearning("tenant-b::alice")).containsOnlyKeys("b-1");
    }

    /** A verification names a person: a person named as an agent's key vouches for nothing the agent holds. */
    @Test
    void aVerificationOfAPersonNamedAsAnAgentsKeyLeavesTheAgentsHeldRequests() {
        SecurityEvent ofTheAgent = event("a-1", "2026-09-29T06:00:00Z", "CRITICAL", device(DEVICE));
        ofTheAgent.addMetadata("executionSubjectKind", "DELEGATED_AGENT");
        ofTheAgent.addMetadata("agentId", "report-agent");
        service.hold(ofTheAgent);

        service.promoteVerified("alice::agent::report-agent", List.of("DEVICE=" + DEVICE));

        assertThat(store.promotionLearning("alice::agent::report-agent")).containsOnlyKeys("a-1");
    }

    /**
     * QF-28: with a lock service the promotion runs under the user's promotion lock; a lock not taken in time leaves the
     * requests held for the next promotion, and nothing is learned meanwhile.
     */
    @Test
    void aPromotionWhoseLockIsNotTakenLeavesTheRequestsHeld() {
        DistributedLockService locks = mock(DistributedLockService.class);
        when(locks.tryLockWithWait(anyString(), anyString(), any(), any())).thenReturn(false);
        service.setLockService(locks);

        service.hold(event("r-1", "2026-09-29T06:00:00Z", "CRITICAL", device(DEVICE)));
        service.hold(event("r-2", "2026-09-30T06:00:00Z", "CRITICAL", device(DEVICE)));

        verify(learning, never()).learnPromoted(anyString(), any(), any());
        assertThat(store.promotionLearning("alice")).containsOnlyKeys("r-1", "r-2");

        when(locks.tryLockWithWait(anyString(), anyString(), any(), any())).thenReturn(true);
        service.hold(event("r-3", "2026-09-30T07:00:00Z", "CRITICAL", device(DEVICE)));

        verify(learning, times(3)).learnPromoted(eq("alice"), any(), any());
        assertThat(store.promotionLearning("alice")).isEmpty();
        verify(locks, times(3)).tryLockWithWait(eq("learning:promotion:alice"), anyString(), any(), any());
        verify(locks).unlock(eq("learning:promotion:alice"), anyString());
    }

    private static Deviation unexplained(DeviationDimension dimension, String current) {
        return new Deviation(dimension, current, true, true, 0, 25, null, Deviation.Explanation.UNEXPLAINED, null);
    }

    /** The event's request on a project of the URL template {@code /api/projects/{projectKey}/exports}. */
    private static SecurityEvent target(SecurityEvent event, String project) {
        CanonicalSecurityContext.Resource resource = ((CanonicalSecurityContext) event.getMetadata()
                .get(LearningPromotionPolicy.DECIDED_CONTEXT)).getResource();
        resource.setPathFamily("/api/projects/{projectKey}/exports");
        resource.setRequestPath("/api/projects/" + project + "/exports");
        event.addMetadata("requestPath", "/api/projects/" + project + "/exports");
        return event;
    }

    private static SecurityEvent tenant(SecurityEvent event, String tenantId) {
        event.addMetadata("tenantId", tenantId);
        return event;
    }

    private static SecurityEvent agent(SecurityEvent event) {
        event.addMetadata("executionSubjectKind", "DELEGATED_AGENT");
        event.addMetadata("agentId", "report-agent");
        ((CanonicalSecurityContext) event.getMetadata().get(LearningPromotionPolicy.DECIDED_CONTEXT)).getAttributes()
                .put("executionSubjectKind", "DELEGATED_AGENT");
        return event;
    }

    private static SecurityEvent event(String requestId, String at, String resourceClass, Deviation... deviations) {
        CanonicalSecurityContext.Resource resource = new CanonicalSecurityContext.Resource();
        resource.setResourceClass(resourceClass);
        CanonicalSecurityContext context = new CanonicalSecurityContext();
        context.setResource(resource);
        context.setDecisionFacts(new DecisionFacts(List.of(), new ArrayList<>(List.of(deviations)),
                PolicySatisfaction.UNKNOWN, List.of()));
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-" + requestId)
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("203.0.113.9")
                .userAgent("Mozilla/5.0 (Macintosh) Safari/18")
                .timestamp(Instant.parse(at))
                .build();
        event.addMetadata("requestId", requestId);
        event.addMetadata("requestPath", "/api/projects/GB-500/exports");
        event.addMetadata(LearningPromotionPolicy.DECIDED_CONTEXT, context);
        return event;
    }
}

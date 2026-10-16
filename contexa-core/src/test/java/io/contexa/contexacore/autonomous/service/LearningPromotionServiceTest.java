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
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.support.VocabularyVersion;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

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

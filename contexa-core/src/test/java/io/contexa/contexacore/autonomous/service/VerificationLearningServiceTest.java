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
import io.contexa.contexacore.autonomous.context.collector.DefaultProtectableWorkProfileCollector;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * W5-2: the request a restriction stopped is learned from its own facts, at a reduced weight, once the user passes
 * the step-up the decision asked for or an administrator releases the block.
 */
class VerificationLearningServiceTest {

    private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            + "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
    private static final Instant NIGHT = Instant.parse("2026-09-30T03:17:00Z");

    private InMemorySecurityContextDataStore store;
    private SecurityLearningService learning;
    private VerificationLearningService service;

    @BeforeEach
    void setUp() {
        store = new InMemorySecurityContextDataStore();
        learning = mock(SecurityLearningService.class);
        service = new VerificationLearningService(store, learning, new DefaultProtectableWorkProfileCollector(store), null);
    }

    @Test
    void aStoppedRequestIsLearnedFromItsOwnFactsOnceTheUserPassesTheStepUp() {
        SecurityEvent challenged = event("request-1");
        service.hold(challenged, ZeroTrustAction.CHALLENGE);

        assertThat(service.learnStepUp("alice", "request-1")).isTrue();

        ArgumentCaptor<SecurityDecision> decision = ArgumentCaptor.forClass(SecurityDecision.class);
        ArgumentCaptor<SecurityEvent> learned = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(learning).learnAndStore(eq("alice"), decision.capture(), learned.capture());
        SecurityEvent event = learned.getValue();
        assertThat(event.getTimestamp()).isEqualTo(NIGHT);
        assertThat(event.getUserId()).isEqualTo("alice");
        assertThat(event.getSessionId()).isEqualTo("session-1");
        assertThat(event.getSourceIp()).isEqualTo("10.40.12.7");
        assertThat(event.getUserAgent()).isEqualTo(USER_AGENT);
        assertThat(event.getEventId()).isNotEqualTo(challenged.getEventId());
        assertThat(event.getMetadata())
                .containsEntry("requestId", "request-1")
                .containsEntry("requestPath", "/api/projects/PLM-OPS/exports")
                .containsEntry("httpMethod", "POST")
                .containsEntry("resourceId", "ops.Documents#exportDocuments")
                .containsEntry("requestItems", 4831)
                .containsEntry("tenantId", "tenant-acme")
                .containsEntry("verifiedBy", "STEP_UP")
                .containsEntry("verificationWeight", 0.5)
                .doesNotContainKey("notJson");
        assertThat(decision.getValue().resolveAutonomousAction()).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(decision.getValue().getReasoning()).contains("step-up");
        assertThat(store.getRecentWorkProfileObservations("tenant-acme", "alice", 10)).singleElement()
                .satisfies(line -> assertThat(line).startsWith("v5|").endsWith("|0.5"));

        // The facts are learned once.
        assertThat(service.learnStepUp("alice", "request-1")).isFalse();
        verifyNoMoreInteractions(learning);
    }

    /**
     * P3-EXTRA-3: the held request keeps no canonical context, so the item count and network zone the decision used
     * are kept as plain values and the learning after the check reads them.
     */
    @Test
    void theItemCountAndZoneTheDecisionUsedSurviveTheHold() {
        SecurityEvent challenged = event("request-zone");
        challenged.addMetadata("sealedEvidence.canonicalContext", CanonicalSecurityContext.builder()
                .location(CanonicalSecurityContext.Location.builder().networkZone("CORPORATE").build())
                .resource(CanonicalSecurityContext.Resource.builder().requestedItems(4900).build())
                .build());
        service.hold(challenged, ZeroTrustAction.CHALLENGE);

        assertThat(service.learnStepUp("alice", "request-zone")).isTrue();

        ArgumentCaptor<SecurityEvent> learned = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(learning).learnAndStore(eq("alice"), ArgumentCaptor.forClass(SecurityDecision.class).capture(),
                learned.capture());
        assertThat(learned.getValue().getMetadata())
                .containsEntry("networkZone", "CORPORATE")
                .containsEntry("requestItems", 4900)
                .doesNotContainKey("sealedEvidence.canonicalContext");
    }

    @Test
    void onlyARestrictionIsHeld() {
        service.hold(event("request-allow"), ZeroTrustAction.ALLOW);
        service.hold(event("request-pending"), ZeroTrustAction.PENDING_ANALYSIS);
        service.hold(event("request-escalate"), ZeroTrustAction.ESCALATE);
        service.hold(event("request-block"), ZeroTrustAction.BLOCK);

        VerificationLearningService.Verification release = VerificationLearningService.Verification.ADMIN_RELEASE;
        assertThat(service.take("alice", "request-allow", release)).isEmpty();
        assertThat(service.take("alice", "request-pending", release)).isEmpty();
        assertThat(service.take("alice", "request-escalate", release)).isPresent();
        assertThat(service.take("alice", "request-block", release)).isPresent();
        assertThat(service.learnStepUp("alice", "request-unknown")).isFalse();
        assertThat(service.learnStepUp("alice", null)).isFalse();
        verify(learning, never()).learnAndStore(any(), any(), any());
    }

    @Test
    void anAdministratorsReleaseTakesTheBlockedRequestOnceAndLearnsItsWorkProfileAtTheWeight() {
        service.hold(event("request-1"), ZeroTrustAction.BLOCK);

        VerificationLearningService.Verification release = VerificationLearningService.Verification.ADMIN_RELEASE;
        Optional<SecurityEvent> taken = service.take("alice", "request-1", release);
        assertThat(taken).isPresent();
        assertThat(taken.get().getTimestamp()).isEqualTo(NIGHT);
        assertThat(taken.get().getMetadata()).containsEntry("verifiedBy", "ADMIN_RELEASE")
                .containsEntry("verificationWeight", 0.5);
        assertThat(service.take("alice", "request-1", release)).isEmpty();

        service.learnWorkProfile(taken.get());
        assertThat(store.getRecentWorkProfileObservations("tenant-acme", "alice", 10)).singleElement()
                .satisfies(line -> assertThat(line).startsWith("v5|").endsWith("|0.5"));
    }

    @Test
    void theWeightComesFromTheSettings() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.getBaseline().getLearning().setVerifiedWeight(0.25);
        VerificationLearningService weighted = new VerificationLearningService(store, learning,
                new DefaultProtectableWorkProfileCollector(store), properties);
        weighted.hold(event("request-1"), ZeroTrustAction.CHALLENGE);

        assertThat(weighted.learnStepUp("alice", "request-1")).isTrue();

        assertThat(store.getRecentWorkProfileObservations("tenant-acme", "alice", 10)).singleElement()
                .satisfies(line -> assertThat(line).endsWith("|0.25"));
    }

    private static SecurityEvent event(String requestId) {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-" + requestId)
                .userId("alice")
                .userName("Alice")
                .sessionId("session-1")
                .sourceIp("10.40.12.7")
                .userAgent(USER_AGENT)
                .timestamp(NIGHT)
                .description("POST /api/projects/PLM-OPS/exports")
                .build();
        event.addMetadata("requestId", requestId);
        event.addMetadata("tenantId", "tenant-acme");
        event.addMetadata("requestPath", "/api/projects/PLM-OPS/exports");
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("actionFamily", "EXPORT");
        event.addMetadata("resourceId", "ops.Documents#exportDocuments");
        event.addMetadata("protectableResourceUrl", "/api/projects/{projectKey}/exports");
        event.addMetadata("isProtectable", true);
        event.addMetadata("granted", true);
        event.addMetadata("className", "ops.Documents");
        event.addMetadata("methodName", "exportDocuments");
        event.addMetadata("requestItems", 4831);
        event.addMetadata("notJson", new Object());
        return event;
    }
}

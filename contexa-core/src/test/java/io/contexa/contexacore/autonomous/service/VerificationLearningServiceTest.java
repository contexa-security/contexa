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

import java.util.List;
import io.contexa.contexacore.autonomous.context.decision.PolicySatisfaction;
import io.contexa.contexacore.autonomous.context.decision.DeviationDimension;
import io.contexa.contexacore.autonomous.context.decision.Deviation;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
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

import io.contexa.contexacore.autonomous.context.support.PastDeniedDecisions;
import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.context.support.PastRecordGroup;
import io.contexa.contexacore.autonomous.context.support.PastRecordScope;
import org.springframework.ai.document.Document;

import java.time.Instant;
import java.util.ArrayList;
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
        // W5-7: a v6 line keeps the weight in its v5 place, before the vocabulary and the request identity.
        assertThat(store.getRecentWorkProfileObservations("tenant-acme", "alice", 10)).singleElement()
                .satisfies(line -> assertThat(weightOf(line)).isEqualTo("0.5"));

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

    /**
     * W5-1: the step-up vouches for the identity values of the request it answered (compared or not), so held
     * requests with them are promoted; a request kept without its decision's context vouches for nothing.
     */
    @Test
    void aStepUpPromotesTheHeldRequestsWithTheVerifiedRequestsIdentityValues() {
        LearningPromotionService promotion = mock(LearningPromotionService.class);
        service.setLearningPromotionService(promotion);
        SecurityEvent challenged = event("request-verified");
        challenged.addMetadata("sealedEvidence.canonicalContext", CanonicalSecurityContext.builder()
                .decisionFacts(new DecisionFacts(List.of(), List.of(
                        new Deviation(DeviationDimension.DEVICE, "Safari/18 on MAC", true, true, 0, 25, null,
                                Deviation.Explanation.UNEXPLAINED, null),
                        new Deviation(DeviationDimension.TIME, "03", true, false, 4, 25, null, null, null),
                        new Deviation(DeviationDimension.TARGET, "GB-500", true, true, 0, 25, null,
                                Deviation.Explanation.UNEXPLAINED, null)),
                        PolicySatisfaction.UNKNOWN, List.of()))
                .build());
        service.hold(challenged, ZeroTrustAction.CHALLENGE);
        service.hold(event("request-plain"), ZeroTrustAction.CHALLENGE);

        assertThat(service.learnStepUp("alice", "request-verified")).isTrue();
        assertThat(service.learnStepUp("alice", "request-plain")).isTrue();

        verify(promotion).promoteVerified("alice", List.of("DEVICE=Safari/18 on MAC", "TIME=03"));
        verifyNoMoreInteractions(promotion);
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
                .satisfies(line -> assertThat(weightOf(line)).isEqualTo("0.5"));
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
                .satisfies(line -> assertThat(weightOf(line)).isEqualTo("0.25"));
    }

    /** The weight of a stored work profile observation: the field after the item count, in a v5 or v6 line. */
    private static String weightOf(String line) {
        String[] fields = line.split("\\|", -1);
        assertThat(fields[0]).isIn("v5", "v6");
        return fields[22];
    }

    /**
     * W5-4: the outcome is kept by the event of the stopped request before its record is written, so a record stored
     * after the verification ended still takes it; no record lookup is needed for that.
     */
    @Test
    void theOutcomeIsKeptByTheEventForARecordStoredAfterTheVerification() {
        service.hold(event("request-early"), ZeroTrustAction.CHALLENGE);

        service.take("alice", "request-early", VerificationLearningService.Verification.STEP_UP);

        assertThat(store.verificationOutcome("event-request-early")).isEqualTo(PastDeniedDecisions.VERIFIED_BY_STEP_UP);
    }

    @Test
    void aVerificationOrAReleaseWritesHowTheDecisionEndedOnItsRecord() {
        List<String[]> written = new ArrayList<>();
        service.setPastRecordQuery(new PastRecordQuery() {
            @Override
            public boolean available() {
                return true;
            }

            @Override
            public List<PastRecordGroup> groups(PastRecordScope scope) {
                return List.of();
            }

            @Override
            public List<Document> records(PastRecordScope scope, List<String> firstPaths, int limit) {
                return List.of();
            }

            @Override
            public boolean recordOutcome(String documentId, String outcome) {
                written.add(new String[]{documentId, outcome});
                return true;
            }
        });
        service.hold(event("request-verified"), ZeroTrustAction.CHALLENGE);
        service.hold(event("request-released"), ZeroTrustAction.BLOCK);

        service.take("alice", "request-verified", VerificationLearningService.Verification.STEP_UP);
        service.take("alice", "request-released", VerificationLearningService.Verification.ADMIN_RELEASE);

        // W5-4: the record of the decision the request had, under its own event, says how it ended.
        assertThat(written).extracting(row -> row[0]).containsExactlyElementsOf(new ArrayList<>() {
            {
                addAll(PastDeniedDecisions.documentIds("event-request-verified"));
                addAll(PastDeniedDecisions.documentIds("event-request-released"));
            }
        });
        assertThat(written).hasSize(6);
        assertThat(written.subList(0, 3)).extracting(row -> row[1]).containsOnly(PastDeniedDecisions.VERIFIED_BY_STEP_UP);
        assertThat(written.subList(3, 6)).extracting(row -> row[1])
                .containsOnly(PastDeniedDecisions.RELEASED_BY_ADMINISTRATOR);
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

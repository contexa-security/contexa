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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRun;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityLearningServiceTest {

    @Mock
    private BaselineLearningService baselineLearningService;

    @Mock
    private SecurityDecisionPostProcessor postProcessor;

    private SecurityLearningService service;

    private SecurityEvent event;
    private SecurityDecision decision;

    @BeforeEach
    void setUp() {
        service = new SecurityLearningService(baselineLearningService, postProcessor);

        event = SecurityEvent.builder()
                .eventId("evt-1")
                .sessionId("session-1")
                .sourceIp("10.0.0.1")
                .build();

        decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .build();
    }

    @Test
    @DisplayName("learnAndStore should invoke both baseline learning and post-processing")
    void shouldInvokeBothBaselineLearningAndPostProcessing() {
        // when
        service.learnAndStore("user1", decision, event);

        // then
        verify(baselineLearningService).learnIfNormal(eq("user1"), eq(decision), eq(event));
        verify(postProcessor).updateSessionContext(event, decision);
        verify(postProcessor).storeInVectorDatabase(event, decision);
    }

    @Test
    @DisplayName("learnBaselineOnly should invoke learnIfNormal only, not post-processing")
    void shouldInvokeLearnIfNormalOnly() {
        // when
        service.learnBaselineOnly("user1", decision, event);

        // then
        verify(baselineLearningService).learnIfNormal(eq("user1"), eq(decision), eq(event));
        verify(postProcessor, never()).updateSessionContext(any(), any());
        verify(postProcessor, never()).storeInVectorDatabase(any(), any());
    }

    @Test
    @DisplayName("postProcessDecision updates the session and leaves the decision document to the enforced outcome "
            + "(W5-3)")
    void shouldInvokePostProcessingOnly() {
        // when
        service.postProcessDecision(event, decision);

        // then
        verify(baselineLearningService, never()).learnIfNormal(any(), any(), any());
        verify(postProcessor).updateSessionContext(event, decision);
        verify(postProcessor, never()).storeInVectorDatabase(any(), any());
    }

    @Test
    @DisplayName("a shadow run's copy leaves the session and the decision documents alone (W6-9)")
    void aShadowRunsCopyLeavesTheSessionAndTheDocumentsAlone() {
        ContextObservationRecorder recorder = new ContextObservationRecorder(new InMemorySecurityContextDataStore());
        service.setContextObservationRecorder(recorder);
        SecurityEvent shadow = requestEvent("request-shadow-run");
        shadow.addMetadata(PromptShadowRun.MARK, true);

        service.postProcessDecision(shadow, decision);
        recorder.commit(shadow, ZeroTrustAction.ALLOW.name(), true);

        verify(postProcessor, never()).updateSessionContext(any(), any());
        verify(postProcessor, never()).storeInVectorDatabase(any(), any());
    }

    @Test
    @DisplayName("an analysis layer's decision document is stored only once that decision is enforced (W5-3)")
    void theDecisionDocumentWaitsForTheEnforcedOutcome() {
        ContextObservationRecorder recorder = new ContextObservationRecorder(new InMemorySecurityContextDataStore());
        service.setContextObservationRecorder(recorder);
        SecurityEvent enforced = requestEvent("request-enforced");
        SecurityEvent shadow = requestEvent("request-shadow");
        SecurityEvent other = requestEvent("request-other-outcome");

        service.postProcessDecision(enforced, decision);
        service.postProcessDecision(shadow, decision);
        service.postProcessDecision(other, decision);
        verify(postProcessor, never()).storeInVectorDatabase(any(), any());

        recorder.commit(enforced, ZeroTrustAction.ALLOW.name(), true);
        recorder.commit(shadow, ZeroTrustAction.ALLOW.name(), false);
        recorder.commit(other, ZeroTrustAction.CHALLENGE.name(), true);

        verify(postProcessor).storeInVectorDatabase(enforced, decision);
        verify(postProcessor, never()).storeInVectorDatabase(eq(shadow), any());
        verify(postProcessor, never()).storeInVectorDatabase(eq(other), any());
    }

    @Test
    @DisplayName("the document of the last analysis layer replaces the earlier one of the same request (W5-3)")
    void theLastLayerDecisionIsTheDocumentStored() {
        ContextObservationRecorder recorder = new ContextObservationRecorder(new InMemorySecurityContextDataStore());
        service.setContextObservationRecorder(recorder);
        SecurityEvent escalated = requestEvent("request-escalated");
        SecurityDecision first = SecurityDecision.builder().action(ZeroTrustAction.ESCALATE).riskScore(0.5).build();
        SecurityDecision second = SecurityDecision.builder().action(ZeroTrustAction.CHALLENGE).riskScore(0.7).build();

        service.postProcessDecision(escalated, first);
        service.postProcessDecision(escalated, second);
        recorder.commit(escalated, ZeroTrustAction.CHALLENGE.name(), true);

        verify(postProcessor).storeInVectorDatabase(escalated, second);
        verify(postProcessor, never()).storeInVectorDatabase(escalated, first);
    }

    @Test
    @DisplayName("Q-15: the late writes of a request taken in before its account was deleted are discarded")
    void theLateWritesOfARequestOfADeletedAccountAreDiscarded() {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        DeletedAccountWriteFence fence = new DeletedAccountWriteFence(store, Duration.ofMinutes(13));
        ContextObservationRecorder recorder = new ContextObservationRecorder(store);
        service.setContextObservationRecorder(recorder);
        service.setDeletedAccountWriteFence(fence);
        SecurityEvent late = requestEvent("request-of-the-deleted-account");
        late.addMetadata(DeletedAccountWriteFence.TAKEN_IN_AT, System.currentTimeMillis() - 1_000);
        fence.markDeleted("user1");

        service.postProcessDecision(late, decision);
        recorder.commit(late, ZeroTrustAction.ALLOW.name(), true);
        service.learnAndStore("user1", decision, late);
        service.learnPromoted("user1", decision, late);

        verify(postProcessor, never()).updateSessionContext(any(), any());
        verify(postProcessor, never()).storeInVectorDatabase(any(), any());
        verify(baselineLearningService, never()).learnIfNormal(any(), any(), any());
        assertThat(fence.discardedWrites())
                .containsEntry(DeletedAccountWriteFence.DECISION_DOCUMENT, 3L)
                .containsEntry(DeletedAccountWriteFence.SESSION_CONTEXT, 2L)
                .containsEntry(DeletedAccountWriteFence.BASELINE, 2L);
    }

    @Test
    @DisplayName("Q-15: a request of a later account of the same name, taken in after the deletion, is learned")
    void aRequestOfALaterAccountOfTheSameNameIsLearned() {
        DeletedAccountWriteFence fence = new DeletedAccountWriteFence(new InMemorySecurityContextDataStore(),
                Duration.ofMinutes(13));
        service.setDeletedAccountWriteFence(fence);
        fence.markDeleted("user1");
        SecurityEvent later = requestEvent("request-of-a-later-account");
        later.addMetadata(DeletedAccountWriteFence.TAKEN_IN_AT, System.currentTimeMillis() + 1_000);

        service.learnAndStore("user1", decision, later);

        verify(baselineLearningService).learnIfNormal("user1", decision, later);
        verify(postProcessor).updateSessionContext(later, decision);
        verify(postProcessor).storeInVectorDatabase(later, decision);
        verify(postProcessor, never()).removeStoredRecord(any(), any());
        assertThat(fence.discardedWrites()).isEmpty();
    }

    @Test
    @DisplayName("Q-15: a decision document stored while the purge of its account ran is removed again")
    void aDocumentStoredWhileThePurgeRanIsRemovedAgain() {
        DeletedAccountWriteFence fence = new DeletedAccountWriteFence(new InMemorySecurityContextDataStore(),
                Duration.ofMinutes(13));
        service.setDeletedAccountWriteFence(fence);
        SecurityEvent racing = requestEvent("request-racing-the-purge");
        racing.addMetadata(DeletedAccountWriteFence.TAKEN_IN_AT, System.currentTimeMillis() - 1_000);
        doAnswer(invocation -> {
            fence.markDeleted("user1");
            return null;
        }).when(postProcessor).storeInVectorDatabase(racing, decision);

        service.learnPromoted("user1", decision, racing);

        verify(postProcessor).storeInVectorDatabase(racing, decision);
        verify(postProcessor).removeStoredRecord(racing, decision);
        assertThat(fence.discardedWrites()).containsEntry(DeletedAccountWriteFence.DECISION_DOCUMENT_REMOVED, 1L);
    }

    private static SecurityEvent requestEvent(String requestId) {
        SecurityEvent request = SecurityEvent.builder()
                .eventId("evt-" + requestId)
                .userId("user1")
                .sessionId("session-1")
                .sourceIp("10.0.0.1")
                .build();
        request.addMetadata("requestId", requestId);
        return request;
    }

    @Test
    @DisplayName("learnAndStore should skip baseline learning for null userId")
    void shouldSkipBaselineLearningForNullUserId() {
        // when
        service.learnAndStore(null, decision, event);

        // then
        verify(baselineLearningService, never()).learnIfNormal(any(), any(), any());
        // Post-processing should still be called
        verify(postProcessor).updateSessionContext(event, decision);
        verify(postProcessor).storeInVectorDatabase(event, decision);
    }

    @Test
    @DisplayName("learnAndStore should skip baseline learning for blank userId")
    void shouldSkipBaselineLearningForBlankUserId() {
        // when
        service.learnAndStore("  ", decision, event);

        // then
        verify(baselineLearningService, never()).learnIfNormal(any(), any(), any());
        verify(postProcessor).updateSessionContext(event, decision);
    }
}

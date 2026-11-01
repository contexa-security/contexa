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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
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

        // QF-55: the document is stored from a copy of the request's event, so it is told by its event id.
        verify(postProcessor).storeInVectorDatabase(sameRequest(enforced), eq(decision));
        verify(postProcessor, never()).storeInVectorDatabase(sameRequest(shadow), any());
        verify(postProcessor, never()).storeInVectorDatabase(sameRequest(other), any());
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
        }).when(postProcessor).storeInVectorDatabase(sameRequest(racing), eq(decision));

        service.learnPromoted("user1", decision, racing);

        verify(postProcessor).storeInVectorDatabase(sameRequest(racing), eq(decision));
        verify(postProcessor).removeStoredRecord(sameRequest(racing), eq(decision));
        assertThat(fence.discardedWrites()).containsEntry(DeletedAccountWriteFence.DECISION_DOCUMENT_REMOVED, 1L);
    }

    /** The event of the same request: the learning stores a copy of the request's event (QF-55). */
    private static SecurityEvent sameRequest(SecurityEvent request) {
        return argThat(event -> event != null && request.getEventId().equals(event.getEventId()));
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

    // ---- BR-C6 (QF-14): every store path states how the record it stores was learned

    /** The learnedBy the event carries at the moment its document is stored; "none" when it carries none. */
    private String learnedByWhenStored(Runnable learning) {
        AtomicReference<String> seen = new AtomicReference<>("not stored");
        doAnswer(invocation -> {
            SecurityEvent stored = invocation.getArgument(0);
            Object source = stored.getMetadata().get("learnedBy");
            seen.set(source != null ? source.toString() : "none");
            return null;
        }).when(postProcessor).storeInVectorDatabase(any(), any());
        learning.run();
        return seen.get();
    }

    @Test
    @DisplayName("the model's own ALLOW, stored once it is enforced, is learned by the model alone")
    void anEnforcedAllowOfTheModelIsLearnedByTheModelAlone() {
        ContextObservationRecorder recorder = new ContextObservationRecorder(new InMemorySecurityContextDataStore());
        service.setContextObservationRecorder(recorder);
        SecurityEvent allowed = requestEvent("request-allowed");

        String learnedBy = learnedByWhenStored(() -> {
            service.postProcessDecision(allowed, decision);
            recorder.commit(allowed, ZeroTrustAction.ALLOW.name(), true);
        });

        assertThat(learnedBy).isEqualTo("MODEL_ALLOW");
    }

    @Test
    @DisplayName("a decision that did not allow is stored with no learned source: it is no learned allowance")
    void aDecisionThatDidNotAllowCarriesNoLearnedSource() {
        ContextObservationRecorder recorder = new ContextObservationRecorder(new InMemorySecurityContextDataStore());
        service.setContextObservationRecorder(recorder);
        SecurityEvent blocked = requestEvent("request-blocked");
        SecurityDecision block = SecurityDecision.builder().action(ZeroTrustAction.BLOCK).riskScore(0.9).build();

        String learnedBy = learnedByWhenStored(() -> {
            service.postProcessDecision(blocked, block);
            recorder.commit(blocked, ZeroTrustAction.BLOCK.name(), true);
        });

        assertThat(learnedBy).isEqualTo("none");
    }

    @Test
    @DisplayName("a request sent again after a step-up is learned after verification, a promoted one after promotion")
    void aResentRequestIsLearnedAfterVerificationAndAPromotedOneAfterPromotion() {
        SecurityEvent resent = requestEvent("request-resent");
        SecurityEvent promoted = requestEvent("request-promoted");
        // A stale source on a held request must not stay: the path states its own.
        promoted.addMetadata("learnedBy", "MODEL_ALLOW");

        assertThat(learnedByWhenStored(() -> service.learnVerifiedResend("user1", decision, resent)))
                .isEqualTo("VERIFIED");
        assertThat(learnedByWhenStored(() -> service.learnPromoted("user1", decision, promoted)))
                .isEqualTo("PROMOTED");
    }

    @Test
    @DisplayName("learnAndStore takes the source from the way the request was verified: step-up, release or promotion")
    void learnAndStoreTakesTheSourceFromTheWayTheRequestWasVerified() {
        SecurityEvent stepUp = requestEvent("request-step-up");
        stepUp.addMetadata("verifiedBy", "STEP_UP");
        SecurityEvent released = requestEvent("request-released");
        released.addMetadata("verifiedBy", "ADMIN_RELEASE");
        SecurityEvent promoted = requestEvent("request-promoted-by-days");
        promoted.addMetadata("verifiedBy", "PROMOTED");

        assertThat(learnedByWhenStored(() -> service.learnAndStore("user1", decision, stepUp))).isEqualTo("VERIFIED");
        assertThat(learnedByWhenStored(() -> service.learnAndStore("user1", decision, released)))
                .isEqualTo("ADMIN_RELEASE");
        assertThat(learnedByWhenStored(() -> service.learnAndStore("user1", decision, promoted)))
                .isEqualTo("PROMOTED");
    }

    @Test
    @DisplayName("a source the caller states stays, and a request with no way of verification states none")
    void aSourceTheCallerStatesStaysAndARequestWithoutOneStatesNone() {
        SecurityEvent stated = requestEvent("request-stated");
        stated.addMetadata("verifiedBy", "STEP_UP");
        stated.addMetadata("learnedBy", "ADMIN_RELEASE");
        SecurityEvent unstated = requestEvent("request-unstated");
        SecurityEvent unreadable = requestEvent("request-unreadable");
        unreadable.addMetadata("verifiedBy", "SOMEBODY");
        unreadable.addMetadata("learnedBy", "free text");

        assertThat(learnedByWhenStored(() -> service.learnAndStore("user1", decision, stated)))
                .isEqualTo("ADMIN_RELEASE");
        assertThat(learnedByWhenStored(() -> service.learnAndStore("user1", decision, unstated))).isEqualTo("none");
        assertThat(learnedByWhenStored(() -> service.learnAndStore("user1", decision, unreadable)))
                .isEqualTo("none");
    }

    // ---- QF-55: the work handed to the learning executor runs on a copy of the event, taken where it is handed over

    /** A service whose learning executor keeps the tasks handed to it until the test runs them. */
    private SecurityLearningService serviceKeeping(List<Runnable> handedOver) {
        return new SecurityLearningService(baselineLearningService, postProcessor, handedOver::add);
    }

    /** Records each event the post processor is given to store, and the learnedBy it carries when it is stored. */
    private List<String> recordStores(List<SecurityEvent> stored) {
        List<String> learnedBy = new ArrayList<>();
        doAnswer(invocation -> {
            SecurityEvent event = invocation.getArgument(0);
            stored.add(event);
            Object source = event.getMetadata().get("learnedBy");
            learnedBy.add(source != null ? source.toString() : "none");
            return null;
        }).when(postProcessor).storeInVectorDatabase(any(), any());
        return learnedBy;
    }

    @Test
    @DisplayName("QF-55: the model's enforced ALLOW is stored from a copy taken at the commit; the request's event "
            + "keeps what it had")
    void theEnforcedAllowIsStoredFromACopyTakenAtTheCommit() {
        List<Runnable> handedOver = new ArrayList<>();
        SecurityLearningService learning = serviceKeeping(handedOver);
        ContextObservationRecorder recorder = new ContextObservationRecorder(new InMemorySecurityContextDataStore());
        learning.setContextObservationRecorder(recorder);
        List<SecurityEvent> stored = new ArrayList<>();
        List<String> learnedBy = recordStores(stored);
        List<SecurityEvent> sessionUpdates = new ArrayList<>();
        doAnswer(invocation -> {
            sessionUpdates.add(invocation.getArgument(0));
            return null;
        }).when(postProcessor).updateSessionContext(any(), any());
        SecurityEvent request = requestEvent("request-qf55-allow");

        learning.postProcessDecision(request, decision);
        recorder.commit(request, ZeroTrustAction.ALLOW.name(), true);
        // The next handlers go on with the request's event while the learning executor works.
        request.addMetadata("SealedEvidenceCaptureHandler_executionTime", 1L);
        Map<String, Object> asTheRequestLeftIt = new HashMap<>(request.getMetadata());
        handedOver.forEach(Runnable::run);

        assertThat(learnedBy).containsExactly("MODEL_ALLOW");
        assertThat(stored.get(0)).isNotSameAs(request);
        assertThat(stored.get(0).getMetadata()).containsEntry("requestId", "request-qf55-allow")
                .doesNotContainKey("SealedEvidenceCaptureHandler_executionTime");
        assertThat(sessionUpdates).hasSize(1).doesNotContain(request);
        assertThat(sessionUpdates.get(0).getEventId()).isEqualTo(request.getEventId());
        assertThat(request.getMetadata()).isEqualTo(asTheRequestLeftIt).doesNotContainKey("learnedBy");
    }

    @Test
    @DisplayName("QF-55: a document the saturated executor defers is written on a copy as well")
    void aDeferredDocumentIsWrittenOnACopy() {
        Executor saturated = task -> {
            if (task instanceof LearningStoreRejectionPolicy.Deferrable deferrable) {
                deferrable.defer();
            } else {
                task.run();
            }
        };
        SecurityLearningService learning =
                new SecurityLearningService(baselineLearningService, postProcessor, saturated);
        ContextObservationRecorder recorder = new ContextObservationRecorder(new InMemorySecurityContextDataStore());
        learning.setContextObservationRecorder(recorder);
        AtomicReference<SecurityEvent> deferred = new AtomicReference<>();
        AtomicReference<Object> deferredLearnedBy = new AtomicReference<>();
        doAnswer(invocation -> {
            SecurityEvent event = invocation.getArgument(0);
            deferred.set(event);
            deferredLearnedBy.set(event.getMetadata().get("learnedBy"));
            return null;
        }).when(postProcessor).deferInVectorDatabase(any(), any());
        SecurityEvent request = requestEvent("request-qf55-deferred");

        learning.postProcessDecision(request, decision);
        recorder.commit(request, ZeroTrustAction.ALLOW.name(), true);

        assertThat(deferredLearnedBy.get()).isEqualTo("MODEL_ALLOW");
        assertThat(deferred.get()).isNotSameAs(request);
        assertThat(request.getMetadata()).doesNotContainKey("learnedBy");
        verify(postProcessor, never()).storeInVectorDatabase(any(), any());
    }

    @Test
    @DisplayName("QF-55: a request learned after verification or promotion is stored from a copy; its caller's event "
            + "keeps what it had")
    void theVerifiedAndPromotedPathsStoreFromACopy() {
        List<Runnable> handedOver = new ArrayList<>();
        SecurityLearningService learning = serviceKeeping(handedOver);
        List<SecurityEvent> stored = new ArrayList<>();
        List<String> learnedBy = recordStores(stored);
        SecurityEvent stepUp = requestEvent("request-qf55-step-up");
        stepUp.addMetadata("verifiedBy", "STEP_UP");
        SecurityEvent promoted = requestEvent("request-qf55-promoted");
        SecurityEvent resent = requestEvent("request-qf55-resent");
        List<SecurityEvent> callers = List.of(stepUp, promoted, resent);

        learning.learnAndStore("user1", decision, stepUp);
        learning.learnPromoted("user1", decision, promoted);
        learning.learnVerifiedResend("user1", decision, resent);
        List<Map<String, Object>> asTheCallersLeftThem = callers.stream()
                .map(event -> Map.copyOf(event.getMetadata()))
                .toList();
        handedOver.forEach(Runnable::run);

        assertThat(learnedBy).containsExactly("VERIFIED", "PROMOTED", "VERIFIED");
        for (int index = 0; index < callers.size(); index++) {
            assertThat(stored.get(index)).isNotSameAs(callers.get(index));
            assertThat(callers.get(index).getMetadata()).isEqualTo(asTheCallersLeftThem.get(index));
        }
    }

    @Test
    @DisplayName("QF-55: the request thread reads its event through while the learning thread stores the document")
    void theRequestThreadReadsItsEventThroughWhileTheLearningThreadStores() throws Exception {
        List<Runnable> handedOver = new ArrayList<>();
        SecurityLearningService learning = serviceKeeping(handedOver);
        ContextObservationRecorder recorder = new ContextObservationRecorder(new InMemorySecurityContextDataStore());
        learning.setContextObservationRecorder(recorder);
        SecurityEvent request = requestEvent("request-qf55-race");
        // The decision path leaves the event's metadata in an insertion-ordered map with no lock.
        request.setMetadata(new LinkedHashMap<>(request.getMetadata()));
        request.addMetadata("requestPath", "/api/orders");
        request.addMetadata("httpMethod", "GET");
        learning.postProcessDecision(request, decision);
        recorder.commit(request, ZeroTrustAction.ALLOW.name(), true);

        // The next handler copies the request's event (SealedEvidenceCaptureHandler, SecurityPlaneAgent): it is half
        // way through the metadata when the learning thread stores the document.
        Iterator<Map.Entry<String, Object>> reading = request.getMetadata().entrySet().iterator();
        reading.next();
        ExecutorService learningThread = Executors.newSingleThreadExecutor();
        try {
            for (Runnable task : handedOver) {
                learningThread.submit(task).get(10, TimeUnit.SECONDS);
            }
        } finally {
            learningThread.shutdownNow();
        }

        assertThatCode(() -> {
            while (reading.hasNext()) {
                reading.next();
            }
        }).doesNotThrowAnyException();
        verify(postProcessor).storeInVectorDatabase(any(), eq(decision));
    }
}

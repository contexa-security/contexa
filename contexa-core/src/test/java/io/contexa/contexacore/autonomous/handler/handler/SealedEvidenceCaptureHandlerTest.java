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
package io.contexa.contexacore.autonomous.handler.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import io.contexa.contexacore.verification.capture.VerificationCaptureContext;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageAssembler;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class SealedEvidenceCaptureHandlerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity();
    private SealedEvidencePromptTraceStore traceStore;
    private SealedEvidencePackageAssembler assembler;
    private SealedEvidencePackageRepository repository;
    private QueuedExecutor captureExecutor;
    private SealedEvidenceCaptureHandler handler;

    @BeforeEach
    void setUp() {
        traceStore = new SealedEvidencePromptTraceStore();
        assembler = new SealedEvidencePackageAssembler(
                objectMapper,
                new CanonicalSecurityContextSerializer(objectMapper),
                integrity,
                traceStore);
        repository = mock(SealedEvidencePackageRepository.class);
        when(repository.findByCorrelationId(any())).thenReturn(Optional.empty());
        when(repository.findByIdempotencyKey(any())).thenReturn(Optional.empty());
        captureExecutor = new QueuedExecutor();
        handler = new SealedEvidenceCaptureHandler(assembler, repository, captureExecutor, null);
    }

    @Test
    void handlerRunsRightAfterDecisionEnforcement() {
        assertThat(handler.getOrder()).isEqualTo(56);
        assertThat(handler.getOrder()).isGreaterThan(55).isLessThan(60);
    }

    @Test
    void handleConsumesTheCapturedPromptTraceAndStoresASealedPackageOffTheDecisionThread() {
        SecurityEvent event = event("req-100", "/api/orders");
        traceStore.capture(captureContext(event));
        traceStore.complete(event);
        SecurityEventContext context = decisionContext(event, "ALLOW");

        assertThat(handler.canHandle(context)).isTrue();
        assertThat(handler.handle(context)).isTrue();
        verifyNoInteractions(repository);

        captureExecutor.runAll();

        ArgumentCaptor<SealedEvidencePackage> saved = ArgumentCaptor.forClass(SealedEvidencePackage.class);
        verify(repository).save(saved.capture());
        SealedEvidencePackage evidencePackage = saved.getValue();
        assertThat(evidencePackage.getCorrelationId()).isEqualTo("req-100");
        assertThat(evidencePackage.getUserId()).isEqualTo("alice");
        assertThat(evidencePackage.getSystemPromptText()).isEqualTo("system prompt");
        assertThat(evidencePackage.getUserPromptText()).isEqualTo("user prompt");
        assertThat(evidencePackage.getRawSystemPrompt()).isEqualTo("raw system");
        assertThat(evidencePackage.getRawUserPrompt()).isEqualTo("raw user");
        assertThat(evidencePackage.getRequestFactsJson()).contains("/api/orders");
        assertThat(evidencePackage.getDecisionJson()).contains("ALLOW");
        assertThat(evidencePackage.getExpiresAt()).isAfter(evidencePackage.getCapturedAt());
        assertThat(integrity.evaluate(evidencePackage)).isEqualTo(SealedEvidencePackageIntegrity.Status.VERIFIED);
        assertThat(traceStore.find("req-100")).isNull();
        assertThat(context.getProcessingStatus()).isNotEqualTo(SecurityEventContext.ProcessingStatus.FAILED);
    }

    @Test
    void captureUsesTheEventStateObservedAtEnforcementTime() {
        SecurityEvent event = event("req-101", "/api/orders");
        traceStore.capture(captureContext(event));
        traceStore.complete(event);
        SecurityEventContext context = decisionContext(event, "ALLOW");

        handler.handle(context);
        event.addMetadata("requestPath", "/api/mutated-after-enforcement");
        captureExecutor.runAll();

        ArgumentCaptor<SealedEvidencePackage> saved = ArgumentCaptor.forClass(SealedEvidencePackage.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getRequestFactsJson())
                .contains("/api/orders")
                .doesNotContain("/api/mutated-after-enforcement");
    }

    @Test
    void missingPromptTraceStoresNothing() {
        SecurityEvent event = event("req-102", "/api/orders");

        assertThat(handler.handle(decisionContext(event, "ALLOW"))).isTrue();
        captureExecutor.runAll();

        verify(repository, never()).save(any());
    }

    @Test
    void alreadyCapturedCorrelationIsNotAssembledAgain() {
        SecurityEvent event = event("req-103", "/api/orders");
        traceStore.capture(captureContext(event));
        traceStore.complete(event);
        when(repository.findByCorrelationId("req-103"))
                .thenReturn(Optional.of(SealedEvidencePackage.builder().packageId("existing").build()));

        handler.handle(decisionContext(event, "ALLOW"));
        captureExecutor.runAll();

        verify(repository, never()).save(any());
        assertThat(traceStore.find("req-103")).isNotNull();
    }

    @Test
    void duplicateInsertRaceIsAbsorbed() {
        SecurityEvent event = event("req-104", "/api/orders");
        traceStore.capture(captureContext(event));
        traceStore.complete(event);
        when(repository.findByCorrelationId("req-104"))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of(SealedEvidencePackage.builder().packageId("other-node").build()));
        when(repository.save(any())).thenThrow(new DataIntegrityViolationException("duplicate"));
        SecurityEventContext context = decisionContext(event, "ALLOW");

        assertThat(handler.handle(context)).isTrue();
        captureExecutor.runAll();

        verify(repository).save(any());
        assertThat(context.getProcessingStatus()).isNotEqualTo(SecurityEventContext.ProcessingStatus.FAILED);
    }

    @Test
    void assemblyFailureNeverBlocksEnforcement() {
        SealedEvidencePackageAssembler failingAssembler = mock(SealedEvidencePackageAssembler.class);
        when(failingAssembler.assemble(any())).thenThrow(new IllegalStateException("assembly failed"));
        SealedEvidenceCaptureHandler failingHandler =
                new SealedEvidenceCaptureHandler(failingAssembler, repository, Runnable::run, null);
        SecurityEventContext context = decisionContext(event("req-105", "/api/orders"), "ALLOW");

        assertThat(failingHandler.handle(context)).isTrue();

        verify(repository, never()).save(any());
        assertThat(context.getProcessingStatus()).isNotEqualTo(SecurityEventContext.ProcessingStatus.FAILED);
    }

    @Test
    void rejectedCaptureIsDroppedWithoutTouchingStorageAndReleasesTheGuard() {
        AtomicBoolean saturated = new AtomicBoolean(true);
        Executor executor = command -> {
            if (saturated.get()) {
                throw new RejectedExecutionException("saturated");
            }
            command.run();
        };
        SealedEvidenceCaptureHandler saturable =
                new SealedEvidenceCaptureHandler(assembler, repository, executor, null);
        SecurityEvent event = event("req-106", "/api/orders");
        traceStore.capture(captureContext(event));
        traceStore.complete(event);
        SecurityEventContext context = decisionContext(event, "ALLOW");

        assertThat(saturable.handle(context)).isTrue();
        verifyNoInteractions(repository);
        assertThat(context.getProcessingStatus()).isNotEqualTo(SecurityEventContext.ProcessingStatus.FAILED);

        saturated.set(false);
        assertThat(saturable.handle(context)).isTrue();
        verify(repository).save(any());
    }

    @Test
    void handleErrorNeverMarksTheDecisionAsFailed() {
        SecurityEventContext context = decisionContext(event("req-107", "/api/orders"), "ALLOW");

        handler.handleError(context, new IllegalStateException("unexpected"));

        assertThat(context.getProcessingStatus()).isNotEqualTo(SecurityEventContext.ProcessingStatus.FAILED);
    }

    @Test
    void staleProcessingOwnerDoesNotStoreEvidence() {
        SecurityContextDataStore dataStore = mock(SecurityContextDataStore.class);
        when(dataStore.isEventProcessingOwner("identity-108", "token-108")).thenReturn(false);
        SealedEvidenceCaptureHandler ownerAware =
                new SealedEvidenceCaptureHandler(assembler, repository, Runnable::run, dataStore);
        SecurityEvent event = event("req-108", "/api/orders");
        event.addMetadata(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY, "identity-108");
        event.addMetadata(SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN, "token-108");
        traceStore.capture(captureContext(event));
        traceStore.complete(event);

        assertThat(ownerAware.handle(decisionContext(event, "ALLOW"))).isTrue();

        verifyNoInteractions(repository);
    }

    @Test
    void canHandleOnlySuccessfulAuthenticatedProtectedDecisions() {
        SecurityEvent anonymous = event("req-109", "/api/orders");
        anonymous.setUserId(null);
        SecurityEventContext failedResult = decisionContext(event("req-110", "/api/orders"), "ALLOW");
        ((ProcessingResult) failedResult.getMetadata().get("processingResult")).setSuccess(false);
        SecurityEventContext failedContext = decisionContext(event("req-111", "/api/orders"), "ALLOW");
        failedContext.markAsFailed("enforcement failed");
        SecurityEventContext withoutResult = new SecurityEventContext(event("req-112", "/api/orders"));

        assertThat(handler.canHandle(null)).isFalse();
        assertThat(handler.canHandle(decisionContext(anonymous, "ALLOW"))).isFalse();
        assertThat(handler.canHandle(failedResult)).isFalse();
        assertThat(handler.canHandle(failedContext)).isFalse();
        assertThat(handler.canHandle(withoutResult)).isFalse();
        assertThat(handler.canHandle(decisionContext(event("req-113", "/actuator/health"), "ALLOW"))).isFalse();
        assertThat(handler.canHandle(decisionContext(event("req-114", "/api/orders"), "BLOCK"))).isTrue();
    }

    private SecurityEvent event(String requestId, String requestPath) {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-" + requestId)
                .userId("alice")
                .sourceIp("192.168.1.100")
                .sessionId("session-1")
                .userAgent("JUnit")
                .build();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("requestId", requestId);
        metadata.put("requestPath", requestPath);
        metadata.put("httpMethod", "GET");
        event.setMetadata(metadata);
        return event;
    }

    private SecurityEventContext decisionContext(SecurityEvent event, String action) {
        SecurityEventContext context = new SecurityEventContext(event);
        ProcessingResult result = ProcessingResult.builder().success(true).build();
        result.setAction(action);
        context.addMetadata("processingResult", result);
        return context;
    }

    private VerificationCaptureContext captureContext(SecurityEvent event) {
        PromptGenerationResult promptResult = mock(PromptGenerationResult.class);
        when(promptResult.getSystemPrompt()).thenReturn("system prompt");
        when(promptResult.getUserPrompt()).thenReturn("user prompt");
        when(promptResult.getRawSystemPrompt()).thenReturn("raw system");
        when(promptResult.getRawUserPrompt()).thenReturn("raw user");
        when(promptResult.getMetadata()).thenReturn(Map.of("promptVersion", "v1"));
        VerificationCaptureContext context = mock(VerificationCaptureContext.class);
        when(context.securityEvent()).thenReturn(event);
        when(context.relatedDocuments()).thenReturn(List.of());
        when(context.promptExecution()).thenReturn(promptResult);
        return context;
    }

    private static final class QueuedExecutor implements Executor {

        private final List<Runnable> tasks = new ArrayList<>();

        @Override
        public void execute(Runnable command) {
            tasks.add(command);
        }

        void runAll() {
            List<Runnable> pending = new ArrayList<>(tasks);
            tasks.clear();
            pending.forEach(Runnable::run);
        }
    }
}

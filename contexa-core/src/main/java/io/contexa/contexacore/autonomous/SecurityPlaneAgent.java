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
package io.contexa.contexacore.autonomous;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.telemetry.SecurityEventTelemetryContext;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.time.LocalDateTime;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;


@RequiredArgsConstructor
@Slf4j
public class SecurityPlaneAgent implements CommandLineRunner, ISecurityPlaneAgent {

    private final SecurityMonitoringService securityMonitor;
    private final SecurityContextDataStore dataStore;
    private final CentralAuditFacade centralAuditFacade;
    private final SecurityEventProcessor securityEventProcessor;
    private final SecurityPlaneProperties securityPlaneProperties;
    private final Executor llmAnalysisExecutor;
    private Supplier<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterSupplier = () -> null;
    private ZeroTrustActionRepository zeroTrustActionRepository;

    private AgentState currentState;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong processedEvents = new AtomicLong(0);
    private KeyedSerialExecutor actorSerialExecutor;
    private static final String PROCESSING_BUDGET_MS = "processingBudgetMs";
    private static final String PROCESSING_TIMEOUT_MS = "processingTimeoutMs";
    private static final String PROCESSING_QUEUE_TIMEOUT_MS = "processingQueueTimeoutMs";
    private static final String PROCESSING_QUEUE_TIMEOUT_AT = "processingQueueTimeoutAt";
    private static final String PROCESSING_TIMEOUT_AT = "processingTimeoutAt";
    private static final String PROCESSING_TIMEOUT_CANCELLATION_REQUESTED = "processingTimeoutCancellationRequested";
    private static final String LATE_PROCESSING_RESULT_DISCARDED = "lateProcessingResultDiscarded";
    private static final String LATE_PROCESSING_RESULT_DISCARDED_AT = "lateProcessingResultDiscardedAt";
    private static final String TIMEOUT_OBSERVATION_RECORDED = "timeoutObservationRecorded";
    private static final String TIMEOUT_OBSERVATION_ID = "timeoutObservationId";
    public static final String EVENT_PROCESSING_IDENTITY = "eventProcessingIdentity";
    public static final String EVENT_PROCESSING_OWNER_TOKEN = "eventProcessingOwnerToken";

    public void setAiSecurityDecisionObservationWriterSupplier(
            Supplier<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterSupplier) {
        this.aiSecurityDecisionObservationWriterSupplier = aiSecurityDecisionObservationWriterSupplier != null
                ? aiSecurityDecisionObservationWriterSupplier
                : () -> null;
    }

    public void setZeroTrustActionRepository(ZeroTrustActionRepository zeroTrustActionRepository) {
        this.zeroTrustActionRepository = zeroTrustActionRepository;
    }

    @PostConstruct
    public void initialize() {
        currentState = AgentState.INITIALIZING;
        securityMonitor.setBatchProcessor(this::processBatch);
        initializeStripedExecutors();
    }

    private void processBatch(List<SecurityEvent> events) {
        if (events == null || events.isEmpty()) {
            return;
        }

        if (!running.get()) {
            throw new IllegalStateException("SecurityPlaneAgent is not running");
        }

        for (SecurityEvent event : events) {
            String analysisKey = resolveAnalysisKey(event);
            int stripeId = resolveStripeId(analysisKey);
            event.addMetadata("analysisKey", analysisKey);
            event.addMetadata("stripeId", stripeId);
            event.addMetadata("analysisQueuedAt", System.currentTimeMillis());

            actorSerialExecutor.execute(analysisKey, () -> {
                try {
                    event.addMetadata("analysisStartedAt", System.currentTimeMillis());
                    processSecurityEventWithinBudget(event);
                    processedEvents.incrementAndGet();
                    event.addMetadata("analysisFinishedAt", System.currentTimeMillis());
                } catch (Exception e) {
                    event.addMetadata("analysisFinishedAt", System.currentTimeMillis());
                    if (deferForRetry(event, classifyDeferReason(e), e)) {
                        log.warn("[SecurityPlaneAgent] Deferred event {} after transient processing failure: {}",
                                event.getEventId(), e.getMessage());
                        return;
                    }
                    log.error("[SecurityPlaneAgent] Error processing event: {}", event.getEventId(), e);
                    if (centralAuditFacade != null) {
                        auditError("SecurityPlaneAgent", "processBatch", e, Map.of(
                                "eventId", event.getEventId(),
                                "userId", event.getUserId() != null ? event.getUserId() : "unknown",
                                "phase", "async_batch_processing",
                                "analysisKey", analysisKey,
                                "stripeId", stripeId
                        ));
                    }
                }
            });
        }
    }

    private String classifyDeferReason(Exception exception) {
        if (hasCause(exception, TimeoutException.class)
                || hasCause(exception, EventProcessingDeadlineExceededException.class)) {
            return "event_processing_timeout";
        }
        if (hasCause(exception, EventProcessingInFlightException.class)) {
            return "event_processing_in_flight";
        }
        if (hasCause(exception, RejectedExecutionException.class)) {
            return "llm_executor_rejected";
        }
        return "processing_failure";
    }

    private boolean hasCause(Throwable throwable, Class<? extends Throwable> expectedType) {
        Throwable current = throwable;
        while (current != null) {
            if (expectedType.isInstance(current)) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    @Override
    public void run(String... args) {
        if (securityPlaneProperties.getAgent().isAutoStart()) {
            start();
        }
    }

    @Override
    public void start() {
        String agentName = securityPlaneProperties.getAgent().getName();
        if (running.compareAndSet(false, true)) {
            currentState = AgentState.RUNNING;
        } else {
            log.error("Agent {} is already running", agentName);
        }
    }

    @Override
    public void stop() {
        if (running.compareAndSet(true, false)) {
            currentState = AgentState.STOPPING;
        }
    }

    @PreDestroy
    public void shutdown() {
        stop();
        shutdownStripedExecutors();
    }

    public SecurityEventContext processSecurityEvent(SecurityEvent event) {
        long startTime = System.currentTimeMillis();
        SecurityContextDataStore.EventProcessingLease lease = claimEventProcessing(event);
        SecurityContextDataStore.EventProcessingClaim claim = lease.claim();
        if (claim == SecurityContextDataStore.EventProcessingClaim.PROCESSED) {
            log.error("[SecurityPlaneAgent] Event {} already processed, skipping duplicate", event.getEventId());
            SecurityEventContext skippedContext = SecurityEventContext.builder()
                    .securityEvent(event)
                    .processingStatus(SecurityEventContext.ProcessingStatus.SKIPPED)
                    .build();
            skippedContext.addMetadata("skipReason", "duplicate_event");
            return skippedContext;
        }
        if (claim == SecurityContextDataStore.EventProcessingClaim.IN_FLIGHT) {
            SecurityEventContext skippedContext = SecurityEventContext.builder()
                    .securityEvent(event)
                    .processingStatus(SecurityEventContext.ProcessingStatus.SKIPPED)
                    .build();
            skippedContext.addMetadata("skipReason", "event_processing_in_flight");
            return skippedContext;
        }
        SecurityEventContext reconciledContext = reconcilePersistedFinalDecision(event);
        return reconciledContext != null ? reconciledContext : processClaimedSecurityEvent(event, startTime);
    }

    private SecurityEventContext processClaimedSecurityEvent(SecurityEvent event, long startTime) {
        try {
            SecurityEventContext context = securityEventProcessor.process(event);
            if (context == null
                    || context.getProcessingStatus() == SecurityEventContext.ProcessingStatus.FAILED) {
                throw new IllegalStateException("Security event pipeline did not produce a final result");
            }
            if (SecurityEventProcessor.hasProcessingDeadlineExceeded(event)) {
                event.addMetadata(LATE_PROCESSING_RESULT_DISCARDED, true);
                event.addMetadata(LATE_PROCESSING_RESULT_DISCARDED_AT, System.currentTimeMillis());
                recordTimeoutObservation(event, "Event processing timeout: deadline exceeded after result completion");
                throw new EventProcessingDeadlineExceededException(event.getEventId());
            }
            if (!markEventProcessed(event)) {
                event.addMetadata("staleProcessingResultDiscarded", true);
                event.addMetadata("staleProcessingResultDiscardedAt", System.currentTimeMillis());
                throw new StaleEventProcessingOwnerException(event.getEventId());
            }
            return context;

        } catch (Exception e) {
            releaseEventProcessing(event);
            if (e instanceof EventProcessingDeadlineExceededException) {
                log.warn("[SecurityPlaneAgent] Discarded late processing result after event deadline: eventId={}", event.getEventId());
            } else {
                log.error("[SecurityPlaneAgent] Error processing event: {}", event.getEventId(), e);
            }

            if (centralAuditFacade != null && !(e instanceof EventProcessingDeadlineExceededException)) {
                auditError("SecurityPlaneAgent", "processSecurityEvent", e, Map.of(
                        "eventId", event.getEventId(),
                        "userId", event.getUserId() != null ? event.getUserId() : "unknown",
                        "sourceIp", event.getSourceIp() != null ? event.getSourceIp() : "unknown",
                        "processingTime", System.currentTimeMillis() - startTime
                ));
            }
            throw new RuntimeException("Event processing failed: " + event.getEventId(), e);
        }
    }
    private SecurityEventContext reconcilePersistedFinalDecision(SecurityEvent event) {
        AiSecurityDecisionObservationWriter writer = aiSecurityDecisionObservationWriterSupplier.get();
        if (writer == null || zeroTrustActionRepository == null) {
            return null;
        }
        String identity = metadataText(event.getMetadata(), EVENT_PROCESSING_IDENTITY);
        AiSecurityDecisionObservationWriter.PersistedFinalDecision persisted =
                writer.findFinalDecision(identity);
        if (persisted == null) {
            return null;
        }

        String eventUserId = firstText(event.getUserId(), metadataText(event.getMetadata(), "userId"));
        if (persisted.userId() != null && !persisted.userId().equals(eventUserId)) {
            throw new IllegalStateException("Persisted final decision user does not match processing identity");
        }
        String eventContextBindingHash = firstText(
                metadataText(event.getMetadata(), "contextBindingHash"),
                SessionFingerprintUtil.generateContextBindingHash(
                        event.getSessionId(), event.getSourceIp(), event.getUserAgent()));
        if (persisted.contextBindingHash() != null
                && !persisted.contextBindingHash().equals(eventContextBindingHash)) {
            throw new IllegalStateException("Persisted final decision context does not match processing identity");
        }
        if (persisted.observationId() == null || persisted.observationId().isBlank()
                || persisted.processingGeneration() == null || persisted.processingGeneration().isBlank()) {
            return null;
        }

        Map<String, Object> fields = new HashMap<>();
        fields.put("observationId", persisted.observationId());
        fields.put("processingGeneration", persisted.processingGeneration());
        fields.put("persistedFinalReused", true);
        if (persisted.requestId() != null) {
            fields.put("requestId", persisted.requestId());
        }
        if (persisted.contextBindingHash() != null) {
            fields.put("contextBindingHash", persisted.contextBindingHash());
        }
        ZeroTrustAction finalAction = ZeroTrustAction.fromString(persisted.finalAction());
        if (!zeroTrustActionRepository.saveFinalAction(eventUserId, finalAction, fields)) {
            throw new IllegalStateException("Persisted final decision did not converge to runtime action");
        }
        if (!markEventProcessed(event)) {
            throw new StaleEventProcessingOwnerException(event.getEventId());
        }

        event.addMetadata("persistedFinalDecisionReused", true);
        event.addMetadata("persistedFinalObservationId", persisted.observationId());
        SecurityEventContext reconciled = SecurityEventContext.builder()
                .securityEvent(event)
                .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED)
                .build();
        reconciled.addMetadata("persistedFinalDecisionReused", true);
        reconciled.addMetadata("finalAction", finalAction.name());
        return reconciled;
    }

    private void auditError(String component, String operation, Exception exception,
                            Map<String, Object> errorContext) {
        try {
            Map<String, Object> details = new HashMap<>();
            details.put("component", component);
            details.put("operation", operation);
            details.put("errorClass", exception.getClass().getName());
            details.put("errorMessage", exception.getMessage());
            if (errorContext != null) {
                details.put("errorContext", errorContext);
            }
            if (exception.getCause() != null) {
                details.put("cause", exception.getCause().getMessage());
            }

            String userId = errorContext != null ? String.valueOf(errorContext.getOrDefault("userId", "SYSTEM")) : "SYSTEM";
            String sourceIp = errorContext != null ? String.valueOf(errorContext.getOrDefault("sourceIp", "")) : null;
            String eventId = errorContext != null ? String.valueOf(errorContext.getOrDefault("eventId", component)) : component;

            centralAuditFacade.recordSync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.SECURITY_ERROR)
                    .principalName(userId)
                    .eventSource("CORE")
                    .clientIp(sourceIp != null && !sourceIp.isBlank() ? sourceIp : null)
                    .resourceIdentifier(eventId)
                    .resourceUri("/errors/" + component)
                    .action("SECURITY_ERROR")
                    .decision("ERROR")
                    .reason(exception.getMessage())
                    .outcome(exception.getClass().getSimpleName())
                    .details(details)
                    .build());
        } catch (Exception e) {
            log.error("Failed to audit error for component: {}", component, e);
        }
    }

    private SecurityContextDataStore.EventProcessingLease claimEventProcessing(SecurityEvent event) {
        String identity = eventProcessingIdentity(event);
        SecurityContextDataStore.EventProcessingLease lease = dataStore.claimEventProcessingLease(identity);
        if (lease.claim() == SecurityContextDataStore.EventProcessingClaim.ACQUIRED) {
            event.addMetadata(EVENT_PROCESSING_IDENTITY, identity);
            event.addMetadata(EVENT_PROCESSING_OWNER_TOKEN, lease.ownerToken());
        }
        return lease;
    }

    private boolean markEventProcessed(SecurityEvent event) {
        return dataStore.markEventProcessed(
                metadataText(event.getMetadata(), EVENT_PROCESSING_IDENTITY),
                metadataText(event.getMetadata(), EVENT_PROCESSING_OWNER_TOKEN));
    }

    private boolean releaseEventProcessing(SecurityEvent event) {
        return dataStore.releaseEventProcessing(
                metadataText(event.getMetadata(), EVENT_PROCESSING_IDENTITY),
                metadataText(event.getMetadata(), EVENT_PROCESSING_OWNER_TOKEN));
    }

    private String eventProcessingIdentity(SecurityEvent event) {
        if (event == null) {
            return sha256("tenant-unspecified|user-unspecified|context-unspecified|event-unspecified|resource-unspecified|method-unspecified");
        }
        Map<String, Object> metadata = event.getMetadata();
        String tenantId = firstText(metadataText(metadata, "tenantId"), metadataText(metadata, "tenant_id"), "tenant-unspecified");
        String userId = firstText(event.getUserId(), metadataText(metadata, "userId"), "user-unspecified");
        String contextBindingHash = firstText(
                metadataText(metadata, "contextBindingHash"),
                SessionFingerprintUtil.generateContextBindingHash(
                        event.getSessionId(), event.getSourceIp(), event.getUserAgent()),
                "context-unspecified");
        String eventReference = firstText(event.getEventId(), metadataText(metadata, "requestId"),
                metadataText(metadata, "correlationId"), "event-unspecified");
        String resource = firstText(metadataText(metadata, "protectableResourceId"),
                metadataText(metadata, "resourceId"), metadataText(metadata, "requestPath"),
                "resource-unspecified");
        String method = firstText(metadataText(metadata, "protectableHttpMethod"),
                metadataText(metadata, "httpMethod"), metadataText(metadata, "method"), "method-unspecified");
        return sha256(String.join("|", tenantId, userId, contextBindingHash, eventReference, resource, method));
    }

    private String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required", exception);
        }
    }

    private String firstText(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private String metadataText(Map<String, Object> metadata, String key) {
        if (metadata == null) {
            return null;
        }
        Object value = metadata.get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }

    private void initializeStripedExecutors() {
        int workerCount = Math.max(1, securityPlaneProperties.getAgent().getAnalysisStripes());
        actorSerialExecutor = new KeyedSerialExecutor(
                Executors.newFixedThreadPool(workerCount, new ActorSerialThreadFactory()),
                workerCount);
    }

    private String resolveAnalysisKey(SecurityEvent event) {
        if (event == null) {
            return "unknown";
        }
        String userId = event.getUserId();
        String sessionId = event.getSessionId();
        if (userId != null && !userId.isBlank() && sessionId != null && !sessionId.isBlank()) {
            return userId + "|" + sessionId;
        }
        if (userId != null && !userId.isBlank()) {
            return userId;
        }
        if (sessionId != null && !sessionId.isBlank()) {
            return sessionId;
        }
        if (event.getSourceIp() != null && !event.getSourceIp().isBlank()) {
            return event.getSourceIp();
        }
        if (event.getEventId() != null && !event.getEventId().isBlank()) {
            return event.getEventId();
        }
        return "unknown";
    }

    private int resolveStripeId(String analysisKey) {
        KeyedSerialExecutor executor = actorSerialExecutor;
        if (executor == null || executor.parallelism() <= 0) {
            throw new IllegalStateException("SecurityPlaneAgent actor serial executor is not initialized");
        }
        return Math.floorMod(analysisKey.hashCode(), executor.parallelism());
    }

    private void shutdownStripedExecutors() {
        KeyedSerialExecutor executor = actorSerialExecutor;
        if (executor != null) {
            executor.shutdown();
        }
    }

    private SecurityEventContext processSecurityEventWithinBudget(SecurityEvent event) throws Exception {
        long timeoutMs = Math.max(1000L, securityPlaneProperties.getAgent().getEventTimeoutMs());
        SecurityContextDataStore.EventProcessingLease lease = claimEventProcessing(event);
        SecurityContextDataStore.EventProcessingClaim claim = lease.claim();
        if (claim == SecurityContextDataStore.EventProcessingClaim.PROCESSED) {
            log.error("[SecurityPlaneAgent] Event {} already processed, skipping duplicate", event.getEventId());
            SecurityEventContext skippedContext = SecurityEventContext.builder()
                    .securityEvent(event)
                    .processingStatus(SecurityEventContext.ProcessingStatus.SKIPPED)
                    .build();
            skippedContext.addMetadata("skipReason", "duplicate_event");
            return skippedContext;
        }
        if (claim == SecurityContextDataStore.EventProcessingClaim.IN_FLIGHT) {
            throw new EventProcessingInFlightException(event.getEventId());
        }
        SecurityEventContext reconciledContext = reconcilePersistedFinalDecision(event);
        if (reconciledContext != null) {
            return reconciledContext;
        }

        CompletableFuture<SecurityEventContext> processingFuture = new CompletableFuture<>();
        long submittedAt = System.currentTimeMillis();
        long deadlineAt = submittedAt + timeoutMs;
        event.addMetadata("analysisSubmittedAt", submittedAt);
        event.addMetadata(PROCESSING_BUDGET_MS, timeoutMs);
        event.addMetadata(SecurityEventProcessor.PROCESSING_DEADLINE_AT, deadlineAt);

        try {
            llmAnalysisExecutor.execute(() -> {
            try (SecurityEventTelemetryContext.Scope ignored = SecurityEventTelemetryContext.open(event)) {
                long executionStartedAt = System.currentTimeMillis();
                event.addMetadata("analysisExecutionStartedAt", executionStartedAt);
                long executorQueueWaitMs = Math.max(0L, executionStartedAt - submittedAt);
                event.addMetadata("executorQueueWaitMs", executorQueueWaitMs);
                long queueTimeoutMs = Math.max(0L, securityPlaneProperties.getLlmExecutor().getQueueTimeoutMs());
                if (queueTimeoutMs > 0L && executorQueueWaitMs > queueTimeoutMs) {
                    event.addMetadata(SecurityEventProcessor.PROCESSING_TIMED_OUT, true);
                    event.addMetadata("decisionFailureCategory", "QUEUE_TIMEOUT");
                    event.addMetadata(PROCESSING_QUEUE_TIMEOUT_MS, queueTimeoutMs);
                    event.addMetadata(PROCESSING_QUEUE_TIMEOUT_AT, executionStartedAt);
                    recordTimeoutObservation(event, "LLM executor queue timeout: waited "
                            + executorQueueWaitMs + "ms > " + queueTimeoutMs + "ms");
                    releaseEventProcessing(event);
                    processingFuture.completeExceptionally(new TimeoutException("LLM executor queue timeout"));
                    return;
                }
                SecurityEventTelemetryContext.putIfAbsent("chatAcquireMs", 0L);
                SecurityEventTelemetryContext.putIfAbsent("embeddingAcquireMs", 0L);
                SecurityEventTelemetryContext.putIfAbsent("vectorRetryCount", 0L);
                processingFuture.complete(processClaimedSecurityEvent(event, executionStartedAt));
            } catch (Throwable throwable) {
                processingFuture.completeExceptionally(throwable);
            } finally {
                event.addMetadata("analysisExecutionFinishedAt", System.currentTimeMillis());
            }
        });
        } catch (RejectedExecutionException rejectedExecutionException) {
            event.addMetadata("llmExecutorRejected", true);
            event.addMetadata("llmExecutorRejectedAt", System.currentTimeMillis());
            event.addMetadata("decisionFailureCategory", "REJECTED_BACKPRESSURE");
            recordRejectedObservation(event);
            releaseEventProcessing(event);
            throw rejectedExecutionException;
        }

        try {
            SecurityEventContext context = processingFuture.get(timeoutMs, TimeUnit.MILLISECONDS);
            event.addMetadata("analysisCompletedAt", System.currentTimeMillis());
            event.addMetadata(SecurityEventProcessor.PROCESSING_TIMED_OUT, false);
            if (context != null
                    && context.getProcessingStatus() == SecurityEventContext.ProcessingStatus.SKIPPED
                    && "event_processing_in_flight".equals(context.getMetadata().get("skipReason"))) {
                throw new EventProcessingInFlightException(event.getEventId());
            }
            return context;
        } catch (TimeoutException timeoutException) {
            processingFuture.cancel(true);
            event.addMetadata("analysisCompletedAt", System.currentTimeMillis());
            event.addMetadata(SecurityEventProcessor.PROCESSING_TIMED_OUT, true);
            event.addMetadata("decisionFailureCategory", "EVENT_TIMEOUT");
            event.addMetadata(PROCESSING_TIMEOUT_MS, timeoutMs);
            event.addMetadata(PROCESSING_TIMEOUT_AT, System.currentTimeMillis());
            event.addMetadata(PROCESSING_TIMEOUT_CANCELLATION_REQUESTED, true);
            recordTimeoutObservation(event, "Event processing timeout: budget exceeded");
            releaseEventProcessing(event);
            throw timeoutException;
        }
    }

    private void recordTimeoutObservation(SecurityEvent event, String message) {
        if (event == null) {
            return;
        }
        synchronized (event) {
            if (Boolean.TRUE.equals(event.getMetadata().get(TIMEOUT_OBSERVATION_RECORDED))) {
                return;
            }
            event.addMetadata(TIMEOUT_OBSERVATION_RECORDED, true);
        }

        AiSecurityDecisionObservationWriter writer = aiSecurityDecisionObservationWriterSupplier.get();
        if (writer == null) {
            return;
        }

        ProcessingResult result = ProcessingResult.builder()
                .success(false)
                .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                .status(ProcessingResult.ProcessingStatus.TIMEOUT)
                .message(message)
                .errorMessage(message)
                .processedAt(LocalDateTime.now())
                .build();
        try {
            event.addMetadata("timeoutObservationAction", ZeroTrustAction.PENDING_ANALYSIS.name());
            event.addMetadata("llmDecisionPresent", false);
            String observationId = writer.recordDecision(event, result, ZeroTrustAction.PENDING_ANALYSIS);
            if (observationId != null && !observationId.isBlank()) {
                event.addMetadata(TIMEOUT_OBSERVATION_ID, observationId);
            }
        } catch (Exception ex) {
            log.error("[SecurityPlaneAgent] Failed to record timeout observation: eventId={}", event.getEventId(), ex);
        }
    }


    private void recordRejectedObservation(SecurityEvent event) {
        if (event == null) {
            return;
        }
        AiSecurityDecisionObservationWriter writer = aiSecurityDecisionObservationWriterSupplier.get();
        if (writer == null) {
            return;
        }
        ProcessingResult result = ProcessingResult.builder()
                .success(false)
                .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                .status(ProcessingResult.ProcessingStatus.FAILED)
                .message("LLM executor rejected analysis due to backpressure")
                .errorMessage("REJECTED_BACKPRESSURE")
                .processedAt(LocalDateTime.now())
                .build();
        try {
            event.addMetadata("backpressureObservationAction", ZeroTrustAction.PENDING_ANALYSIS.name());
            event.addMetadata("llmDecisionPresent", false);
            writer.recordDecision(event, result, ZeroTrustAction.PENDING_ANALYSIS);
        } catch (Exception ex) {
            log.error("[SecurityPlaneAgent] Failed to record backpressure rejection observation: eventId={}", event.getEventId(), ex);
        }
    }
    private boolean deferForRetry(SecurityEvent event, String reason, Exception exception) {
        int deferredCount = getIntegerMetadata(event, "deferredCount");
        int maxDeferredRetries = Math.max(0, securityPlaneProperties.getAgent().getMaxDeferredRetries());
        if (deferredCount >= maxDeferredRetries) {
            event.addMetadata("deferExhausted", true);
            event.addMetadata("deferExhaustedReason", reason);
            return false;
        }

        event.addMetadata("deferRequestedAt", System.currentTimeMillis());
        event.addMetadata("deferReason", reason);
        if (exception != null) {
            event.addMetadata("deferErrorClass", exception.getClass().getName());
            event.addMetadata("deferErrorMessage", exception.getMessage());
        }
        securityMonitor.deferEvent(event, reason);
        return true;
    }

    private int getIntegerMetadata(SecurityEvent event, String key) {
        Object value = event.getMetadata() != null ? event.getMetadata().get(key) : null;
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String stringValue) {
            try {
                return Integer.parseInt(stringValue);
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    private final class ActorSerialThreadFactory implements ThreadFactory {
        private final AtomicLong threadIds = new AtomicLong();

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "SecurityPlane-Actor-" + threadIds.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    }

    private final class KeyedSerialExecutor {
        private final ExecutorService workerPool;
        private final ConcurrentMap<String, SerialTaskQueue> queues = new ConcurrentHashMap<>();
        private final int parallelism;

        private KeyedSerialExecutor(ExecutorService workerPool, int parallelism) {
            this.workerPool = workerPool;
            this.parallelism = parallelism;
        }

        private int parallelism() {
            return parallelism;
        }

        private void execute(String key, Runnable task) {
            String queueKey = key == null || key.isBlank() ? "unknown" : key;
            queues.computeIfAbsent(queueKey, SerialTaskQueue::new).submit(task);
        }

        private void shutdown() {
            workerPool.shutdown();
            try {
                if (!workerPool.awaitTermination(30, TimeUnit.SECONDS)) {
                    workerPool.shutdownNow();
                }
            } catch (InterruptedException interruptedException) {
                Thread.currentThread().interrupt();
                workerPool.shutdownNow();
            }
        }

        private final class SerialTaskQueue implements Runnable {
            private final String key;
            private final Queue<Runnable> tasks = new ArrayDeque<>();
            private boolean running;

            private SerialTaskQueue(String key) {
                this.key = key;
            }

            private void submit(Runnable task) {
                boolean shouldSchedule = false;
                synchronized (this) {
                    tasks.add(task);
                    if (!running) {
                        running = true;
                        shouldSchedule = true;
                    }
                }
                if (shouldSchedule) {
                    workerPool.execute(this);
                }
            }

            @Override
            public void run() {
                while (true) {
                    Runnable next;
                    synchronized (this) {
                        next = tasks.poll();
                        if (next == null) {
                            running = false;
                            queues.remove(key, this);
                            return;
                        }
                    }
                    try {
                        next.run();
                    } catch (Throwable throwable) {
                        log.error("[SecurityPlaneAgent] Actor serial task failed: key={}", key, throwable);
                    }
                }
            }
        }
    }

    private enum AgentState {
        INITIALIZING,
        RUNNING,
        STOPPING
    }

    private static final class EventProcessingInFlightException extends RuntimeException {
        private EventProcessingInFlightException(String eventId) {
            super("Event is already being processed: " + eventId);
        }
    }

    private static final class EventProcessingDeadlineExceededException extends RuntimeException {
        private EventProcessingDeadlineExceededException(String eventId) {
            super("Event processing deadline exceeded: " + eventId);
        }
    }

    private static final class StaleEventProcessingOwnerException extends RuntimeException {
        private StaleEventProcessingOwnerException(String eventId) {
            super("Event processing ownership is stale: " + eventId);
        }
    }
}

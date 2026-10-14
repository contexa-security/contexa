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

import java.util.List;
import io.contexa.contexacommon.domain.TruthValues;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.verification.evidence.SealedEvidenceCaptureSampling;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageAssembler;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

/**
 * Persists a sealed evidence package for every successfully enforced security decision.
 *
 * The handler runs at order 56, immediately after SecurityDecisionEnforcementHandler (55). It is
 * strictly non-invasive: it never changes the decision, always continues the handler chain and never
 * marks the event context as failed.
 *
 * The decision pipeline can run on a request thread (synchronous protectable decisions), so the
 * handler only takes a detached snapshot of the event context on the calling thread. Package assembly,
 * the processing owner check and the database insert run on the dedicated capture executor. A capture
 * that cannot be scheduled or fails is logged and dropped; it never blocks or fails decision enforcement.
 *
 * Prompt originals are consumed from SealedEvidencePromptTraceStore, which is filled by
 * SealedEvidencePromptCaptureAspect and SealedEvidenceLayer1CompletionAspect. When no prompt trace
 * exists for the event, the assembler rejects the package and nothing is stored. The store hands a
 * trace out once, so a decision is sealed once; the unique idempotency key of the package table
 * absorbs what is left, a race between nodes.
 */
@Slf4j
public class SealedEvidenceCaptureHandler implements SecurityEventHandler {

    public static final int ORDER = 56;

    private static final String HANDLER_NAME = "SealedEvidenceCaptureHandler";
    private static final String PROCESSING_RESULT_KEY = "processingResult";
    private static final List<String> EXCLUDED_PATH_PREFIXES = List.of("/actuator", "/health", "/.well-known/");
    private static final String SERVER_SENT_EVENTS_SEGMENT = "/sse/";

    private final SealedEvidencePackageAssembler assembler;
    private final SealedEvidencePackageRepository repository;
    private final Executor captureExecutor;
    private final SecurityContextDataStore securityContextDataStore;
    private final SealedEvidenceCaptureSampling sampling;

    public SealedEvidenceCaptureHandler(
            SealedEvidencePackageAssembler assembler,
            SealedEvidencePackageRepository repository,
            Executor captureExecutor,
            SecurityContextDataStore securityContextDataStore) {
        this(assembler, repository, captureExecutor, securityContextDataStore, SealedEvidenceCaptureSampling.ALL);
    }

    /** R4-S6: seals only the packages the sampling keeps; the four-argument constructor seals every package. */
    public SealedEvidenceCaptureHandler(
            SealedEvidencePackageAssembler assembler,
            SealedEvidencePackageRepository repository,
            Executor captureExecutor,
            SecurityContextDataStore securityContextDataStore,
            SealedEvidenceCaptureSampling sampling) {
        this.assembler = Objects.requireNonNull(assembler, "assembler must not be null");
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.captureExecutor = Objects.requireNonNull(captureExecutor, "captureExecutor must not be null");
        this.securityContextDataStore = securityContextDataStore;
        this.sampling = Objects.requireNonNull(sampling, "sampling must not be null");
    }

    @Override
    public boolean canHandle(SecurityEventContext context) {
        if (context == null || context.getSecurityEvent() == null) {
            return false;
        }
        if (context.getProcessingStatus() == SecurityEventContext.ProcessingStatus.FAILED) {
            return false;
        }
        SecurityEvent event = context.getSecurityEvent();
        if (!StringUtils.hasText(event.getUserId())) {
            return false;
        }
        Object result = context.getMetadata() == null ? null : context.getMetadata().get(PROCESSING_RESULT_KEY);
        if (!(result instanceof ProcessingResult processingResult) || !processingResult.isSuccess()) {
            return false;
        }
        return !isExcludedPath(event);
    }

    @Override
    public boolean handle(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        try {
            SecurityEventContext snapshot = detachedSnapshot(context);
            captureExecutor.execute(() -> capture(snapshot));
        } catch (RejectedExecutionException e) {
            log.error("[{}] Sealed evidence capture rejected by the capture executor: eventId={}",
                    HANDLER_NAME, event.getEventId(), e);
        } catch (RuntimeException e) {
            log.error("[{}] Failed to schedule sealed evidence capture: eventId={}",
                    HANDLER_NAME, event.getEventId(), e);
        }
        return true;
    }

    @Override
    public void handleError(SecurityEventContext context, Exception error) {
        // Evidence capture must never change the outcome of decision enforcement.
        log.error("[{}] Sealed evidence capture error ignored: eventId={}",
                HANDLER_NAME,
                context == null || context.getSecurityEvent() == null ? null : context.getSecurityEvent().getEventId(),
                error);
    }

    @Override
    public String getName() {
        return HANDLER_NAME;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    /**
     * Assembles the package from the decision's prompt trace and stores it while this node still owns the event's
     * processing; the owner is asked last because it can change while the package is assembled.
     */
    private void capture(SecurityEventContext snapshot) {
        SecurityEvent event = snapshot.getSecurityEvent();
        try {
            SealedEvidencePackage evidencePackage = assembler.assemble(snapshot);
            if (evidencePackage == null || !isCurrentProcessingOwner(event)) {
                return;
            }
            if (!sampling.shouldSeal(evidencePackage)) {
                return;
            }
            saveIfAbsent(evidencePackage);
        } catch (RuntimeException e) {
            log.error("[{}] Failed to capture sealed evidence: eventId={}", HANDLER_NAME, event.getEventId(), e);
        }
    }

    private void saveIfAbsent(SealedEvidencePackage evidencePackage) {
        try {
            repository.save(evidencePackage);
        } catch (DataIntegrityViolationException e) {
            if (isAlreadyCaptured(evidencePackage.getIdempotencyKey(), evidencePackage.getCorrelationId())) {
                return;
            }
            throw e;
        }
    }

    private boolean isAlreadyCaptured(String idempotencyKey, String correlationId) {
        if (StringUtils.hasText(idempotencyKey)) {
            return repository.findByIdempotencyKey(idempotencyKey.trim()).isPresent();
        }
        if (StringUtils.hasText(correlationId)) {
            return repository.findByCorrelationId(correlationId.trim()).isPresent();
        }
        return false;
    }

    private boolean isCurrentProcessingOwner(SecurityEvent event) {
        String identity = metadataText(event, SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY);
        String ownerToken = metadataText(event, SecurityPlaneAgent.EVENT_PROCESSING_OWNER_TOKEN);
        if (identity == null && ownerToken == null) {
            return true;
        }
        return securityContextDataStore != null
                && identity != null
                && ownerToken != null
                && securityContextDataStore.isEventProcessingOwner(identity, ownerToken);
    }

    /**
     * Infrastructure endpoints that never carry a protected decision: probes, actuator, discovery and the server-sent
     * event transport. A protected decision is sealed wherever its path is, so a streamed export is sealed like any
     * other export.
     */
    private boolean isExcludedPath(SecurityEvent event) {
        if (isProtectedDecision(event)) {
            return false;
        }
        String path = metadataText(event, "requestPath");
        if (path == null) {
            return false;
        }
        return EXCLUDED_PATH_PREFIXES.stream().anyMatch(path::startsWith) || path.contains(SERVER_SENT_EVENTS_SEGMENT);
    }

    /** A decision on a {@code @Protectable} method, marked by the event publisher as the observation writer reads it. */
    private boolean isProtectedDecision(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        return metadata != null && (Boolean.TRUE.equals(TruthValues.parse(metadata.get("protectableDeclared")))
                || metadata.containsKey("protectableMethod"));
    }

    /**
     * Copies the event and context state as observed right after decision enforcement, so the
     * asynchronous capture neither races with later handlers nor reads metadata that changes afterwards.
     */
    private SecurityEventContext detachedSnapshot(SecurityEventContext context) {
        SecurityEvent source = context.getSecurityEvent();
        SecurityEvent event = SecurityEvent.builder()
                .eventId(source.getEventId())
                .source(source.getSource())
                .timestamp(source.getTimestamp())
                .severity(source.getSeverity())
                .description(source.getDescription())
                .sourceIp(source.getSourceIp())
                .userId(source.getUserId())
                .userName(source.getUserName())
                .sessionId(source.getSessionId())
                .userAgent(source.getUserAgent())
                .blocked(source.isBlocked())
                .metadata(copyOf(source.getMetadata()))
                .build();
        return SecurityEventContext.builder()
                .securityEvent(event)
                .processingStatus(context.getProcessingStatus())
                .metadata(copyOf(context.getMetadata()))
                .createdAt(context.getCreatedAt())
                .updatedAt(context.getUpdatedAt())
                .build();
    }

    private Map<String, Object> copyOf(Map<String, Object> source) {
        if (source == null) {
            return new HashMap<>();
        }
        synchronized (source) {
            return new HashMap<>(source);
        }
    }

    private String metadataText(SecurityEvent event, String key) {
        if (event == null || event.getMetadata() == null) {
            return null;
        }
        Object value = event.getMetadata().get(key);
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }
}

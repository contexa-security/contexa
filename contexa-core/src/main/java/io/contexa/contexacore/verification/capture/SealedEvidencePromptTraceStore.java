package io.contexa.contexacore.verification.capture;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;


/**
 * Enterprise-grade prompt trace store that captures PromptGenerationResult
 * along with SecurityDecisionContext for sealed evidence assembly.
 *
 * Lifecycle:
 * 1. capture() -- called by SealedEvidencePromptCaptureAspect when PromptGenerator.generatePrompt() completes
 * 2. complete() -- called by SealedEvidenceLayer1CompletionAspect when Layer1.evaluate() finishes
 * 3. consume() -- called by SealedEvidenceCaptureHandler to retrieve and remove the snapshot for sealing
 *
 * Modeled after TDD source: OfficialVerificationPromptTraceStore
 * Key difference: production-grade with consume() semantics for single-use retrieval.
 */
@Slf4j
public class SealedEvidencePromptTraceStore {

    private static final String PROMPT_FAULT_SCENARIO_KEY = "pqaPromptFaultScenario";

    private final ConcurrentMap<String, SealedEvidencePromptSnapshot> pendingByEventId = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, SealedEvidencePromptSnapshot> completedByRequestId = new ConcurrentHashMap<>();
    private final AtomicReference<SealedEvidencePromptSnapshot> latestCompleted = new AtomicReference<>();

    private final Executor captureExecutor;
    private final PromptEvidenceMetadataProvider metadataProvider;
    private final VerificationCaptureStoreOptions options;
    private final Clock clock;

    public SealedEvidencePromptTraceStore() {
        this(null, Runnable::run, VerificationCaptureStoreOptions.defaults(), Clock.systemUTC());
    }

    public SealedEvidencePromptTraceStore(PromptEvidenceMetadataProvider metadataProvider) {
        this(metadataProvider, Runnable::run, VerificationCaptureStoreOptions.defaults(), Clock.systemUTC());
    }

    public SealedEvidencePromptTraceStore(
            PromptEvidenceMetadataProvider metadataProvider,
            Executor captureExecutor,
            VerificationCaptureStoreOptions options,
            Clock clock
    ) {
        this.metadataProvider = metadataProvider;
        this.captureExecutor = Objects.requireNonNull(captureExecutor, "captureExecutor must not be null");
        this.options = Objects.requireNonNull(options, "options must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }
    /**
     * Called by SealedEvidencePromptCaptureAspect at PromptGenerator.generatePrompt() completion.
     * Stores the prompt snapshot as pending (not yet completed by Layer1).
     */
    public void capture(VerificationCaptureContext context) {
        PromptGenerationResult promptResult = context == null ? null : context.promptExecution();
        if (context == null || promptResult == null) {
            return;
        }

        pruneSnapshots();
        SecurityEvent event = context.securityEvent();
        if (event == null || !StringUtils.hasText(event.getEventId())) {
            return;
        }

        String requestId = resolveRequestId(event);
        PromptFaultProjection promptFault = applyPromptFaultScenarioIfRequested(
                event,
                promptResult.getUserPrompt(),
                null);

        CompletableFuture<Map<String, Object>> metadataFuture =
                CompletableFuture.supplyAsync(() -> {
                    Map<String, Object> metadata = buildPromptEvidenceMetadata(context, promptResult);
                    applyPromptFaultScenarioIfRequested(event, promptResult.getUserPrompt(), metadata);
                    return Map.copyOf(metadata);
                }, captureExecutor);

        Object sessionContext = context.session();
        Object behaviorAnalysis = context.behavior();
        List<Document> relatedDocuments =
                context.relatedDocuments();

        SealedEvidencePromptSnapshot snapshot = new SealedEvidencePromptSnapshot(
                requestId,
                clock.instant(),
                event,
                sessionContext,
                behaviorAnalysis,
                relatedDocuments != null ? List.copyOf(relatedDocuments) : List.of(),
                promptResult.getRawSystemPrompt(),
                promptResult.getRawUserPrompt(),
                promptResult.getSystemPrompt(),
                promptFault.userPrompt(),
                new LazyDelegatingMap(metadataFuture),
                promptResult.getPromptExecutionMetadata()
        );

        pendingByEventId.put(event.getEventId(), snapshot);
        pruneSnapshots();
    }

    /**
     * Called by SealedEvidenceLayer1CompletionAspect when Layer1.evaluate() finishes.
     * Moves the snapshot from pending to completed, keyed by requestId.
     */
    public void complete(SecurityEvent event) {
        if (event == null || !StringUtils.hasText(event.getEventId())) {
            return;
        }

        pruneSnapshots();
        SealedEvidencePromptSnapshot pending = pendingByEventId.remove(event.getEventId());
        if (pending == null) {
            return;
        }

        String requestId = resolveRequestId(event);

        SealedEvidencePromptSnapshot completed = new SealedEvidencePromptSnapshot(
                requestId,
                pending.capturedAt(),
                event,
                pending.sessionContext(),
                pending.behaviorAnalysis(),
                pending.relatedDocuments(),
                pending.rawSystemPrompt(),
                pending.rawUserPrompt(),
                pending.systemPrompt(),
                pending.userPrompt(),
                pending.metadata(),
                pending.promptExecutionMetadata()
        );

        completedByRequestId.put(requestId, completed);
        latestCompleted.set(completed);
        pruneSnapshots();
    }

    /**
     * Called by SealedEvidenceCaptureHandler to retrieve and remove the completed snapshot.
     * Single-use: once consumed, the snapshot is removed from the store.
     */
    public SealedEvidencePromptSnapshot consume(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return null;
        }
        pruneSnapshots();
        SealedEvidencePromptSnapshot snapshot = completedByRequestId.remove(requestId);
        if (snapshot != null) {
            latestCompleted.compareAndSet(snapshot, null);
            return snapshot;
        }
        snapshot = consumePending(requestId);
        if (snapshot != null) {
            log.error("[SealedEvidence] Consumed pending prompt snapshot before Layer1 completion: requestId={}, eventId={}",
                    requestId,
                    snapshot.securityEvent() == null ? null : snapshot.securityEvent().getEventId());
        }
        return snapshot;
    }

    /**
     * Non-destructive lookup for replay/diagnostic purposes.
     */
    public SealedEvidencePromptSnapshot find(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return null;
        }
        pruneSnapshots();
        return completedByRequestId.get(requestId);
    }

    private SealedEvidencePromptSnapshot consumePending(String requestId) {
        SealedEvidencePromptSnapshot direct = pendingByEventId.remove(requestId);
        if (direct != null) {
            return direct;
        }
        for (var entry : pendingByEventId.entrySet()) {
            SealedEvidencePromptSnapshot candidate = entry.getValue();
            if (candidate != null && requestId.equals(candidate.requestId())
                    && pendingByEventId.remove(entry.getKey(), candidate)) {
                return candidate;
            }
        }
        SealedEvidencePromptSnapshot latest = latestCompleted.get();
        if (latest != null && requestId.equals(latest.requestId())) {
            completedByRequestId.remove(requestId, latest);
            latestCompleted.compareAndSet(latest, null);
            return latest;
        }
        return null;
    }

    private String resolveRequestId(SecurityEvent event) {
        if (event.getMetadata() != null) {
            Object rid = event.getMetadata().get("requestId");
            if (rid != null && !rid.toString().isBlank()) {
                return rid.toString();
            }
            Object cid = event.getMetadata().get("correlationId");
            if (cid != null && !cid.toString().isBlank()) {
                return cid.toString();
            }
        }
        return event.getEventId();
    }

    private Map<String, Object> buildPromptEvidenceMetadata(
            VerificationCaptureContext context,
            PromptGenerationResult promptResult) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        if (promptResult.getMetadata() != null) {
            metadata.putAll(promptResult.getMetadata());
        }
        if (metadataProvider != null) {
            try {
                Map<String, Object> providerMetadata = metadataProvider.buildMetadata(context.domainContext(), promptResult);
                if (providerMetadata != null) {
                    metadata.putAll(providerMetadata);
                }
            } catch (Exception e) {
                log.error("[SealedEvidence] Failed to build metadata via provider", e);
            }
        }
        return metadata;
    }

    private PromptFaultProjection applyPromptFaultScenarioIfRequested(
            SecurityEvent event,
            String userPrompt,
            Map<String, Object> metadata) {
        String scenario = firstText(
                text(event == null || event.getMetadata() == null ? null : event.getMetadata().get(PROMPT_FAULT_SCENARIO_KEY)),
                text(event == null || event.getMetadata() == null ? null : event.getMetadata().get("officialVerification.pqaPromptFaultScenario")),
                text(metadata == null ? null : metadata.get(PROMPT_FAULT_SCENARIO_KEY)));
        if (!StringUtils.hasText(scenario)) {
            return new PromptFaultProjection(userPrompt);
        }
        String normalizedScenario = scenario.trim().toUpperCase(Locale.ROOT);
        if (!"RAG_SCOPE_SLOT_FAULT".equals(normalizedScenario)
                && !"RUNTIME_SLOT_MULTI_FAULT".equals(normalizedScenario)) {
            return new PromptFaultProjection(userPrompt);
        }
        if (metadata != null) {
            metadata.put(PROMPT_FAULT_SCENARIO_KEY, normalizedScenario);
            metadata.putIfAbsent("pqaPromptFaultApplied", false);
            metadata.putIfAbsent("pqaPromptFaultSource", "PROMPT_GENERATION_ONLY");
        }
        if (event != null) {
            event.addMetadata(PROMPT_FAULT_SCENARIO_KEY, normalizedScenario);
            if (event.getMetadata() == null || !event.getMetadata().containsKey("pqaPromptFaultApplied")) {
                event.addMetadata("pqaPromptFaultApplied", false);
            }
            if (event.getMetadata() == null || !event.getMetadata().containsKey("pqaPromptFaultSource")) {
                event.addMetadata("pqaPromptFaultSource", "PROMPT_GENERATION_ONLY");
            }
        }
        return new PromptFaultProjection(userPrompt);
    }

    private static String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isBlank() ? null : text;
    }

    private void pruneSnapshots() {
        Instant cutoff = clock.instant().minus(options.snapshotTtl());
        pruneMap(pendingByEventId, cutoff, options.maxPending());
        pruneMap(completedByRequestId, cutoff, options.maxCompleted());
SealedEvidencePromptSnapshot latest = latestCompleted.get();
        if (latest != null && (latest.capturedAt().isBefore(cutoff)
                || completedByRequestId.get(latest.requestId()) != latest)) {
            latestCompleted.compareAndSet(latest, null);
        }
    }

    private void pruneMap(
            ConcurrentMap<String, SealedEvidencePromptSnapshot> snapshots,
            Instant cutoff,
            int maximumSize
    ) {
        snapshots.entrySet().removeIf(entry -> entry.getValue().capturedAt().isBefore(cutoff));
        while (snapshots.size() > maximumSize) {
            snapshots.entrySet().stream()
                    .min(Comparator.comparing(entry -> entry.getValue().capturedAt()))
                    .ifPresent(entry -> snapshots.remove(entry.getKey(), entry.getValue()));
        }
    }
    private record PromptFaultProjection(String userPrompt) {
    }
}

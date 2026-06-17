package io.contexa.contexacore.verification.capture;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.SecurityEvent;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;


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
    private static final String PROMPT_FAULT_SCENARIO_HEADER = "X-PQA-Prompt-Fault";

    private final ConcurrentMap<String, SealedEvidencePromptSnapshot> pendingByEventId = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, SealedEvidencePromptSnapshot> completedByRequestId = new ConcurrentHashMap<>();
    private final AtomicReference<SealedEvidencePromptSnapshot> latestCompleted = new AtomicReference<>();

    private final ExecutorService captureExecutor = Executors.newFixedThreadPool(
            Math.max(2, Runtime.getRuntime().availableProcessors()),
            r -> {
                Thread thread = new Thread(r, "sealed-evidence-capturer");
                thread.setDaemon(true);
                return thread;
            }
    );

    private final PromptEvidenceMetadataProvider metadataProvider;

    public SealedEvidencePromptTraceStore() {
        this(null);
    }

    public SealedEvidencePromptTraceStore(PromptEvidenceMetadataProvider metadataProvider) {
        this.metadataProvider = metadataProvider;
    }

    /**
     * Called by SealedEvidencePromptCaptureAspect at PromptGenerator.generatePrompt() completion.
     * Stores the prompt snapshot as pending (not yet completed by Layer1).
     */
    public void capture(DomainContext context, PromptGenerationResult promptResult) {
        if (context == null || promptResult == null) {
            return;
        }

        SecurityEvent event = (SecurityEvent) getFieldValue(context, "securityEvent");
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

        Object sessionContext = getFieldValue(context, "sessionContext");
        Object behaviorAnalysis = getFieldValue(context, "behaviorAnalysis");
        List<Document> relatedDocuments =
                (List<Document>) getFieldValue(context, "relatedDocuments");

        SealedEvidencePromptSnapshot snapshot = new SealedEvidencePromptSnapshot(
                requestId,
                Instant.now(),
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
    }

    /**
     * Called by SealedEvidenceLayer1CompletionAspect when Layer1.evaluate() finishes.
     * Moves the snapshot from pending to completed, keyed by requestId.
     */
    public void complete(SecurityEvent event) {
        if (event == null || !StringUtils.hasText(event.getEventId())) {
            return;
        }

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
    }

    /**
     * Called by SealedEvidenceCaptureHandler to retrieve and remove the completed snapshot.
     * Single-use: once consumed, the snapshot is removed from the store.
     */
    public SealedEvidencePromptSnapshot consume(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return null;
        }
        SealedEvidencePromptSnapshot snapshot = completedByRequestId.remove(requestId);
        if (snapshot != null) {
            latestCompleted.compareAndSet(snapshot, null);
            return snapshot;
        }
        snapshot = consumePending(requestId);
        if (snapshot != null) {
            log.warn("[SealedEvidence] Consumed pending prompt snapshot before Layer1 completion: requestId={}, eventId={}",
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
            DomainContext context,
            PromptGenerationResult promptResult) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        if (promptResult.getMetadata() != null) {
            metadata.putAll(promptResult.getMetadata());
        }
        if (metadataProvider != null) {
            try {
                Map<String, Object> providerMetadata = metadataProvider.buildMetadata(context, promptResult);
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
                currentRequestPromptFaultScenario(),
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

    private String currentRequestPromptFaultScenario() {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)) {
            return null;
        }
        HttpServletRequest request = attributes.getRequest();
        return firstText(
                request.getParameter(PROMPT_FAULT_SCENARIO_KEY),
                request.getHeader(PROMPT_FAULT_SCENARIO_HEADER),
                text(request.getAttribute(PROMPT_FAULT_SCENARIO_KEY)),
                text(request.getAttribute("officialVerification.pqaPromptFaultScenario")));
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

    private static Object getFieldValue(Object obj, String fieldName) {
        if (obj == null) {
            return null;
        }
        Class<?> clazz = obj.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            } catch (Exception e) {
                log.error("[SealedEvidence] Unexpected error reading field {} from {}", fieldName, obj.getClass().getName(), e);
                break;
            }
        }
        return null;
    }

    private record PromptFaultProjection(String userPrompt) {
    }
}

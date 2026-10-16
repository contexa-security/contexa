package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.support.PastRecordRanking;
import io.contexa.contexacore.autonomous.context.support.PastRecordRelevance;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRun;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptSnapshot;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Assembles a SealedEvidencePackage by combining data from three authoritative sources:
 *
 * 1. SealedEvidencePromptTraceStore -- prompt originals (system/user prompt text, raw prompts,
 *    sessionContext, behaviorAnalysis, relatedDocuments, promptExecutionMetadata)
 *    captured by SealedEvidencePromptCaptureAspect at PromptGenerator.generatePrompt() completion.
 *
 * 2. SecurityEventContext.metadata -- CanonicalSecurityContext (captured by P1-F01 hook),
 *    ProcessingResult (set by ProcessingExecutionHandler)
 *
 * 3. SecurityEvent.metadata -- HTTP request facts, authentication state,
 *    prompt runtime telemetry (hashes, versions, sections)
 *
 * Each section's data source is documented. No data is assumed to exist at a key
 * without verified production evidence of its presence.
 */
@Slf4j
public class SealedEvidencePackageAssembler {

    /** How long a sealed package is kept when the host sets no retention (R4-S4, D-C). */
    public static final Duration DEFAULT_RETENTION = Duration.ofDays(90);
    private static final int SEALED_METADATA_TEXT_LIMIT = 512;
    private static final int SEALED_METADATA_GENERIC_LIST_LIMIT = 512;

    private final ObjectMapper objectMapper;
    private final CanonicalSecurityContextSerializer contextSerializer;
    private final SealedEvidencePackageIntegrity integrity;
    private final SealedEvidencePromptTraceStore promptTraceStore;
    private final Duration retention;

    public SealedEvidencePackageAssembler(ObjectMapper objectMapper, CanonicalSecurityContextSerializer contextSerializer,
                                          SealedEvidencePackageIntegrity integrity,
                                          SealedEvidencePromptTraceStore promptTraceStore) {
        this(objectMapper, contextSerializer, integrity, promptTraceStore, DEFAULT_RETENTION);
    }

    public SealedEvidencePackageAssembler(ObjectMapper objectMapper, CanonicalSecurityContextSerializer contextSerializer,
                                          SealedEvidencePackageIntegrity integrity,
                                          SealedEvidencePromptTraceStore promptTraceStore, Duration retention) {
        this.objectMapper = objectMapper;
        this.contextSerializer = contextSerializer;
        this.integrity = integrity;
        this.promptTraceStore = promptTraceStore;
        if (retention == null || retention.isNegative() || retention.isZero()) {
            throw new IllegalArgumentException("Sealed evidence retention must be positive: " + retention);
        }
        this.retention = retention;
    }

    /**
     * Assembles a sealed evidence package from the given SecurityEventContext.
     * Prompt originals are consumed from the prompt trace store (single-use retrieval).
     *
     * @param eventContext the security event context after decision enforcement
     * @return assembled package, or null if essential data is missing
     */
    public SealedEvidencePackage assemble(SecurityEventContext eventContext) {
        if (eventContext == null || eventContext.getSecurityEvent() == null) {
            return null;
        }

        SecurityEvent event = eventContext.getSecurityEvent();
        Map<String, Object> contextMetadata = eventContext.getMetadata();
        ProcessingResult result = extractProcessingResult(contextMetadata);
        String correlationId = resolveCorrelationId(event);

        // Source 1: Prompt trace store -- captured by AOP at PromptGenerator.generatePrompt()
        SealedEvidencePromptSnapshot promptSnapshot = promptTraceStore.consume(
                resolvePromptTraceKey(event, correlationId));
        if (promptSnapshot == null) {
            log.error("[SealedEvidence] Prompt snapshot missing. Sealed package rejected: correlationId={}", correlationId);
            return null;
        }
        if (!hasText(promptSnapshot.systemPrompt()) || !hasText(promptSnapshot.userPrompt())) {
            log.error("[SealedEvidence] Final LLM prompt text missing. Sealed package rejected: correlationId={}, systemPromptPresent={}, userPromptPresent={}",
                    correlationId,
                    hasText(promptSnapshot.systemPrompt()),
                    hasText(promptSnapshot.userPrompt()));
            return null;
        }
        String rawSystemPrompt = promptSnapshot.rawSystemPrompt();
        String rawUserPrompt = promptSnapshot.rawUserPrompt();
        List<String> captureWarnings = new ArrayList<>();
        if (!hasText(promptSnapshot.rawSystemPrompt())) {
            captureWarnings.add("rawSystemPrompt was missing.");
        }
        if (!hasText(promptSnapshot.rawUserPrompt())) {
            captureWarnings.add("rawUserPrompt was missing.");
        }

        // Source 2: SecurityEvent.metadata -- CanonicalSecurityContext
        // (stored by P1-F01 hook in SecurityDecisionPromptSections.createBuildContext()
        //  via event.addMetadata("sealedEvidence.canonicalContext", ctx))
        CanonicalSecurityContext canonicalContext = extractCanonicalContext(event.getMetadata());
        String requestFactsJson = buildRequestFacts(event, correlationId);
        String authStateJson = buildAuthState(event);
        String canonicalContextJson = canonicalContext != null ? contextSerializer.serialize(canonicalContext) : null;
        String baselineSnapshotJson = buildBaselineSnapshot(event);
        String ragResultsJson = buildRagResults(event, promptSnapshot);
        String promptExecutionMetadataJson = serializePromptExecutionMetadata(promptSnapshot, event.getMetadata());
        String decisionJson = buildDecisionSnapshot(result, event.getMetadata());
        String sealFailureReason = null;
        if (!captureWarnings.isEmpty()) {
            sealFailureReason = "Prompt raw capture incomplete: " + String.join(" ", captureWarnings);
            log.error("[SealedEvidence] Prompt raw capture incomplete; package will still be sealed for audit without raw prompt backfill: correlationId={}, reason={}",
                    correlationId,
                    sealFailureReason);
        }

        SealedEvidencePackage pkg = SealedEvidencePackage.builder()
                .packageId(UUID.randomUUID().toString())
                .correlationId(correlationId)
                .idempotencyKey(resolveText(event.getMetadata(), SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY))
                .tenantId(resolveText(event.getMetadata(), "tenantId", "tenant_id"))
                .userId(event.getUserId())
                .capturedAt(Instant.now())

                // Section 1: HTTP request facts -- from SecurityEvent (set by ZeroTrustEventPublisher)
                .requestFactsJson(requestFactsJson)

                // Section 2: Authentication state -- from SecurityEvent.metadata (set by ZeroTrustEventPublisher)
                .authStateJson(authStateJson)

                // Section 3: CanonicalSecurityContext -- from SecurityEvent.metadata
                // (set by P1-F01 hook in SecurityDecisionPromptSections.createBuildContext())
                .canonicalContextJson(canonicalContextJson)

                // Section 4: Baseline -- from SecurityEvent.metadata (set by ZeroTrustEventPublisher)
                .baselineSnapshotJson(baselineSnapshotJson)

                // Section 5: RAG results -- from prompt snapshot's related documents + event metadata
                .ragResultsJson(ragResultsJson)

                // Section 6: Prompt originals -- from SealedEvidencePromptTraceStore
                // (captured by SealedEvidencePromptCaptureAspect)
                // Raw prompts: before compression/budget enforcement
                .rawSystemPrompt(rawSystemPrompt)
                .rawUserPrompt(rawUserPrompt)
                // LLM-view prompts: after compression (what LLM actually received)
                .systemPromptText(promptSnapshot.systemPrompt())
                .userPromptText(promptSnapshot.userPrompt())
                .promptHash(resolvePromptHash(event, promptSnapshot))
                .systemPromptHash(sha256Prefixed(promptSnapshot.systemPrompt()))
                .userPromptHash(sha256Prefixed(promptSnapshot.userPrompt()))
                .rawSystemPromptHash(sha256Prefixed(rawSystemPrompt))
                .rawUserPromptHash(sha256Prefixed(rawUserPrompt))
                .promptExecutionMetadataJson(promptExecutionMetadataJson)
                .sealState(SealedEvidencePackage.SEAL_STATE_SEALED)
                .sealFailureReason(sealFailureReason)

                // Section 7: Decision -- from ProcessingResult (set by ProcessingExecutionHandler)
                .decisionJson(decisionJson)

                .schemaVersion(2)
                .sealed(true)
                .expiresAt(Instant.now().plus(retention))
                .build();

        pkg.setPackageHash(integrity.computeHash(pkg));
        return pkg;
    }

    // --- Source extraction ---

    private ProcessingResult extractProcessingResult(Map<String, Object> metadata) {
        if (metadata == null) {
            return null;
        }
        Object obj = metadata.get("processingResult");
        return obj instanceof ProcessingResult pr ? pr : null;
    }

    private CanonicalSecurityContext extractCanonicalContext(Map<String, Object> metadata) {
        if (metadata == null) {
            return null;
        }
        Object ctx = metadata.get("sealedEvidence.canonicalContext");
        return ctx instanceof CanonicalSecurityContext csc ? csc : null;
    }

    private String resolvePromptTraceKey(SecurityEvent event, String correlationId) {
        if (event != null && event.getMetadata() != null) {
            Object identity = event.getMetadata().get(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY);
            if (identity != null && hasText(identity.toString())) {
                return identity.toString().trim();
            }
        }
        return correlationId;
    }

    private String resolveCorrelationId(SecurityEvent event) {
        if (event.getMetadata() != null) {
            String requestId = resolveText(event.getMetadata(), "requestId");
            if (requestId != null) {
                return requestId;
            }
            String correlationId = resolveText(event.getMetadata(), "correlationId");
            if (correlationId != null) {
                return correlationId;
            }
        }
        return event.getEventId();
    }

    // --- Section builders ---

    /**
     * Section 1: HTTP request facts.
     * Source: SecurityEvent fields (set by ZeroTrustEventPublisher.buildMethodAuthorizationEvent())
     */
    private String buildRequestFacts(SecurityEvent event, String correlationId) {
        Map<String, Object> facts = new LinkedHashMap<>();
        putIfPresent(facts, "requestId", firstNonBlank(resolveText(event.getMetadata(), "requestId"), correlationId));
        putIfPresent(facts, "correlationId", firstNonBlank(resolveText(event.getMetadata(), "correlationId"), correlationId));
        putIfPresent(facts, "tenantId", resolveText(event.getMetadata(), "tenantId", "tenant_id"));
        putIfPresent(facts, "organizationId", resolveText(event.getMetadata(), "organizationId", "orgId"));
        putIfPresent(facts, "userId", event.getUserId());
        facts.put("clientIp", event.getSourceIp());
        facts.put("userAgent", event.getUserAgent());
        facts.put("sessionId", event.getSessionId());
        putFromMetadata(facts, event, "httpMethod");
        putFromMetadata(facts, event, "requestPath");
        putFromMetadata(facts, event, "servletPath");
        putFromMetadata(facts, event, "queryString");
        putFromMetadata(facts, event, "resourceId");
        putFromMetadata(facts, event, "requestedResourceId");
        putFromMetadata(facts, event, "protectedResourceId");
        putFromMetadata(facts, event, "protectableDeclared");
        putFromMetadata(facts, event, "protectableResourceId");
        putFromMetadata(facts, event, "protectableResourceUrl");
        putFromMetadata(facts, event, "protectableHttpMethod");
        putFromMetadata(facts, event, "protectableMethod");
        putFromMetadata(facts, event, "protectableCriticality");
        putFromMetadata(facts, event, "protectableVerificationRequired");
        putFromMetadata(facts, event, "protectableSync");
        putIfPresent(facts, "contextBindingHash", firstNonBlank(
                resolveText(event.getMetadata(), "contextBindingHash"),
                SessionFingerprintUtil.generateContextBindingHash(
                        event.getSessionId(), event.getSourceIp(), event.getUserAgent())));
        normalizeActualResourceIdentity(facts, event);
        return toJson(facts);
    }

    /**
     * Section 2: Authentication state.
     * Source: SecurityEvent.metadata (set by ZeroTrustEventPublisher)
     */
    private String buildAuthState(SecurityEvent event) {
        Map<String, Object> state = new LinkedHashMap<>();
        putFromMetadata(state, event, "authMethod");
        putFromMetadata(state, event, "mfaVerified");
        putFromMetadata(state, event, "effectiveRoles");
        putFromMetadata(state, event, "effectivePermissions");
        putFromMetadata(state, event, "authorizationEffect");
        putFromMetadata(state, event, "authorizationEffectProvenance");
        putFromMetadata(state, event, "principalType");
        return toJson(state);
    }

    /**
     * Section 4: Behavioral baseline.
     * Source: SecurityEvent.metadata (set by request context and behavior analysis)
     */
    private String buildBaselineSnapshot(SecurityEvent event) {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        putFromMetadata(snapshot, event, "baselineEstablished");
        putFromMetadata(snapshot, event, "personalBaselineEstablished");
        putFromMetadata(snapshot, event, "organizationBaselineEstablished");
        putFromMetadata(snapshot, event, "isNewUser");
        putFromMetadata(snapshot, event, "isNewDevice");
        putFromMetadata(snapshot, event, "isNewSession");
        putFromMetadata(snapshot, event, "baselineProfileStatus");
        putFromMetadata(snapshot, event, "personalBaselineStatus");
        putFromMetadata(snapshot, event, "baselineObservations");
        putFromMetadata(snapshot, event, "observedPatternEvidenceScope");
        putFromMetadata(snapshot, event, "eventCount");
        putFromMetadata(snapshot, event, "observationDays");
        putFromMetadata(snapshot, event, "fallbackRatio");
        putFromMetadata(snapshot, event, "coverage");
        return toJson(snapshot);
    }

    /**
     * Section 5: RAG retrieval results.
     * Source: SecurityEvent.metadata (counts) + prompt snapshot (documents)
     */
    private String buildRagResults(SecurityEvent event, SealedEvidencePromptSnapshot promptSnapshot) {
        Map<String, Object> rag = new LinkedHashMap<>();
        putFromMetadata(rag, event, "retrievalPurpose");
        putFromMetadata(rag, event, "requestedDocumentCount");
        putFromMetadata(rag, event, "allowedDocumentCount");
        putFromMetadata(rag, event, "deniedDocumentCount");
        putFromMetadata(rag, event, "ragUnavailable");
        putFromMetadata(rag, event, "ragTimedOut");
        putFromMetadata(rag, event, "ragFailureType");
        putFromMetadata(rag, event, "ragFailureMessage");
        putFromMetadata(rag, event, "ragTimeoutMs");
        putFromMetadata(rag, event, "ragRequestedTopK");
        putFromMetadata(rag, event, "ragCandidateDocumentCount");
        putFromMetadata(rag, event, "ragAuthorizedDocumentCount");
        putFromMetadata(rag, event, "ragDeniedDocumentCount");
        putFromMetadata(rag, event, "ragSearchExecuted");
        putFromMetadata(rag, event, "ragRetrievalState");
        putFromMetadata(rag, event, "ragAbsenceReason");
        putFromMetadata(rag, event, "ragPermissionFiltered");
        putFromMetadata(rag, event, "ragProjectedToFinalPrompt");
        putFromMetadata(rag, event, "ragProjectionState");
        putFromMetadata(rag, event, "ragSearchScope");

        List<Map<String, Object>> documents = List.of();
        List<PastRecordRelevance.Subject> records = List.of();
        if (promptSnapshot != null && promptSnapshot.relatedDocuments() != null) {
            documents = promptSnapshot.relatedDocuments().stream()
                    .map(SealedPastRecordSummary::of)
                    .toList();
            records = promptSnapshot.relatedDocuments().stream()
                    .map(document -> document == null
                            ? PastRecordRelevance.Subject.ofRecord(null, null)
                            : PastRecordRelevance.Subject.ofRecord(document.getMetadata(), document.getText()))
                    .toList();
        }
        // The same computation as the prompt and the canonical reasoning: the path template and the target (W2-8).
        PastRecordRelevance.Subject request = PastRecordRelevance.Subject.ofRequest(
                event == null ? null : event.getMetadata(),
                event == null ? null : event.getDescription());
        for (int index = 0; index < documents.size(); index++) {
            Map<String, Object> document = documents.get(index);
            if (document != null && !document.isEmpty()) {
                document.put("relation", PastRecordRelevance.relation(request, records.get(index)).name());
                document.put("sameTarget", PastRecordRelevance.sameTarget(request, records.get(index)));
            }
        }
        if (!documents.isEmpty()) {
            rag.put("relatedDocuments", documents);
        }
        rag.put("ragRelevance", PastRecordRelevance.relevance(request, records));
        rag.put("relatedDocumentCount", documents.size());
        putProjection(rag, promptSnapshot);
        return toJson(rag);
    }

    /**
     * W6-12: whether the past records reached the prompt, read from the IDs the render drew against the records the
     * lookup returned and not from how many it returned; a drawn ID the lookup did not return is named apart. A render
     * that names no drawn IDs leaves the state the event gave.
     */
    private static void putProjection(Map<String, Object> rag, SealedEvidencePromptSnapshot promptSnapshot) {
        List<String> drawn = drawnPastRecordIds(promptSnapshot);
        if (drawn == null) {
            return;
        }
        Set<String> returned = new LinkedHashSet<>();
        if (promptSnapshot.relatedDocuments() != null) {
            promptSnapshot.relatedDocuments().stream()
                    .filter(Objects::nonNull)
                    .map(PastRecordRanking::storedId)
                    .forEach(returned::add);
        }
        List<String> projected = drawn.stream().filter(returned::contains).toList();
        List<String> unmatched = drawn.stream().filter(id -> !returned.contains(id)).toList();
        rag.put("projectedDocumentIds", projected);
        rag.put("ragProjectedToFinalPrompt", !projected.isEmpty());
        if (!unmatched.isEmpty()) {
            rag.put("unmatchedDrawnIds", unmatched);
        }
    }

    private static List<String> drawnPastRecordIds(SealedEvidencePromptSnapshot promptSnapshot) {
        if (promptSnapshot == null) {
            return null;
        }
        Object ids = null;
        if (promptSnapshot.metadata() != null) {
            ids = promptSnapshot.metadata().get(PromptExecutionMetadata.PROMPT_PAST_RECORD_IDS);
        }
        if (ids == null && promptSnapshot.promptExecutionMetadata() != null) {
            ids = promptSnapshot.promptExecutionMetadata().toMetadataMap().get(PromptExecutionMetadata.PROMPT_PAST_RECORD_IDS);
        }
        if (!(ids instanceof List<?> list)) {
            return null;
        }
        return list.stream().filter(Objects::nonNull).map(String::valueOf).toList();
    }

    /**
     * Section 6 partial: PromptExecutionMetadata serialization.
     * Source: SealedEvidencePromptSnapshot.promptExecutionMetadata (captured by AOP)
     */
    private String serializePromptExecutionMetadata(
            SealedEvidencePromptSnapshot promptSnapshot,
            Map<String, Object> runtimeMetadata) {
        if (promptSnapshot == null) {
            return null;
        }
        Map<String, Object> metadata = new LinkedHashMap<>();
        if (promptSnapshot.promptExecutionMetadata() != null) {
            metadata.putAll(promptSnapshot.promptExecutionMetadata().toMetadataMap());
        }
        if (promptSnapshot.metadata() != null) {
            metadata.putAll(promptSnapshot.metadata());
        }
        putIfAbsent(metadata, "runtimeModelId", resolveText(
                runtimeMetadata,
                "runtimeModelId",
                "requestedModelId",
                "preferredModel"));
        return toJson(compactPromptExecutionMetadata(metadata));
    }

    private Map<String, Object> compactPromptExecutionMetadata(Map<String, Object> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> compact = new LinkedHashMap<>();
        copyPromptMetadataField(compact, source, "requestId");
        copyPromptMetadataField(compact, source, "correlationId");
        copyPromptMetadataField(compact, source, "resourceId");
        copyPromptMetadataField(compact, source, "protectableResourceId");
        copyPromptMetadataField(compact, source, "endpointKey");
        copyPromptMetadataField(compact, source, "actualResourceId");
        copyPromptMetadataField(compact, source, "promptHash");
        copyPromptMetadataField(compact, source, "userPromptHash");
        copyPromptMetadataField(compact, source, "systemPromptHash");
        copyPromptMetadataField(compact, source, "rawPromptHash");
        copyPromptMetadataField(compact, source, "rawUserPromptHash");
        copyPromptMetadataField(compact, source, "rawSystemPromptHash");
        copyPromptMetadataField(compact, source, "contextHash");
        copyPromptMetadataField(compact, source, "contextBindingHash");
        copyPromptMetadataField(compact, source, PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR);
        copyPromptMetadataField(compact, source, "promptVersion");
        copyPromptMetadataField(compact, source, "promptBundleVersion");
        copyPromptMetadataField(compact, source, "promptBundleHash");
        copyPromptMetadataField(compact, source, "promptBundleSelectionSource");
        copyPromptMetadataField(compact, source, "promptTemplateVersion");
        copyPromptMetadataField(compact, source, "promptGovernanceVersion");
        copyPromptMetadataField(compact, source, "provider");
        copyPromptMetadataField(compact, source, "llmProvider");
        copyPromptMetadataField(compact, source, "model");
        copyPromptMetadataField(compact, source, "runtimeModelId");
        copyPromptMetadataField(compact, source, "defaultBudgetProfile");
        copyPromptMetadataField(compact, source, "promptBudgetProfile");
        copyPromptMetadataField(compact, source, "budgetProfile");
        copyPromptMetadataField(compact, source, "compressionApplied");
        copyPromptMetadataField(compact, source, "promptCompressionApplied");
        copyPromptMetadataField(compact, source, "promptRawTruthParity");
        copyPromptMetadataField(compact, source, "promptViewTransformationMode");
        copyPromptMetadataField(compact, source, "transformationMode");
        copyPromptCompressionLedger(compact, source);
        // What the prompt inspector compares a v20 prompt with: the clock its times were drawn on, the retrieval state
        // and the counted facts of its past records, the baseline state its evidence and status lines state and the
        // entries its budget took out.
        copyPromptMetadataField(compact, source, PromptExecutionMetadata.EVENT_TIME_ZONE);
        copyPromptMetadataField(compact, source, PromptExecutionMetadata.PROMPT_RAG_STATE);
        copyPromptMetadataField(compact, source, PromptExecutionMetadata.PROMPT_PAST_RECORD_COUNTS);
        copyPromptMetadataField(compact, source, PromptExecutionMetadata.PROMPT_PAST_RECORD_IDS);
        copyPromptMetadataField(compact, source, PromptExecutionMetadata.PROMPT_PAST_DENIED_DECISIONS);
        copyPromptMetadataField(compact, source, PromptExecutionMetadata.PROMPT_BASELINE_STATUS);
        copyPromptMetadataField(compact, source, PromptExecutionMetadata.OMITTED_SECTIONS);
        compact.put("storagePolicy", "OFFICIAL_VERIFICATION_MINIMAL_METADATA_V1");
        return compact;
    }

    private void copyPromptCompressionLedger(Map<String, Object> target, Map<String, Object> source) {
        Object value = source.get("promptCompressionLedger");
        if (!(value instanceof Iterable<?> records)) {
            return;
        }
        List<Object> compact = new ArrayList<>();
        for (Object record : records) {
            if (!(record instanceof Map<?, ?> map)) {
                continue;
            }
            Map<String, Object> item = new LinkedHashMap<>();
            copyCompressionLedgerValue(item, map, "action");
            copyCompressionLedgerValue(item, map, "scopeKey");
            copyCompressionLedgerValue(item, map, "reason");
            if (!item.isEmpty()) {
                compact.add(item);
            }
        }
        if (!compact.isEmpty()) {
            target.put("promptCompressionLedger", compact);
        }
    }

    private void copyCompressionLedgerValue(Map<String, Object> target, Map<?, ?> source, String key) {
        Object value = source.get(key);
        if (value != null) {
            target.put(key, compactTextValue(value));
        }
    }

    private void copyPromptMetadataField(Map<String, Object> target, Map<String, Object> source, String key) {
        if (!source.containsKey(key)) {
            return;
        }
        Object value = compactMetadataValue(source.get(key));
        if (value != null) {
            target.put(key, value);
        }
    }

    private Object compactMetadataValue(Object value) {
        if (value instanceof String || value instanceof Number || value instanceof Boolean || value == null) {
            return compactTextValue(value);
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> compact = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() != null) {
                    compact.put(String.valueOf(entry.getKey()), compactMetadataValue(entry.getValue()));
                }
            }
            return compact;
        }
        if (value instanceof Iterable<?> iterable) {
            List<Object> compact = new ArrayList<>();
            int count = 0;
            for (Object item : iterable) {
                if (count++ >= SEALED_METADATA_GENERIC_LIST_LIMIT) {
                    compact.add(Map.of("omittedReason", "SEALED_METADATA_GENERIC_LIST_LIMIT", "limit", SEALED_METADATA_GENERIC_LIST_LIMIT));
                    break;
                }
                compact.add(compactMetadataValue(item));
            }
            return compact;
        }
        return compactTextValue(value);
    }

    private Object compactTextValue(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number || value instanceof Boolean) {
            return value;
        }
        String text = String.valueOf(value);
        if (text.length() <= SEALED_METADATA_TEXT_LIMIT) {
            return text;
        }
        return Map.of(
                "storagePolicy", "OMITTED_LARGE_TEXT",
                "length", text.length(),
                "sha256", sha256Prefixed(text));
    }

    /**
     * Section 6 partial: Prompt hash resolution.
     * Primary source: SecurityEvent.metadata (set by prompt runtime telemetry)
     * Fallback: PromptExecutionMetadata from prompt snapshot
     */
    private String resolvePromptHash(SecurityEvent event, SealedEvidencePromptSnapshot promptSnapshot) {
        String hash = resolveText(event.getMetadata(), "promptHash");
        if (hash != null) {
            return hash;
        }
        if (promptSnapshot != null && promptSnapshot.promptExecutionMetadata() != null) {
            return promptSnapshot.promptExecutionMetadata().promptHash();
        }
        return null;
    }

    /**
     * Section 7: Decision result.
     * Source: ProcessingResult (set by ProcessingExecutionHandler -> SecurityEventContext.metadata)
     */
    private String buildDecisionSnapshot(ProcessingResult result, Map<String, Object> eventMetadata) {
        if (result == null) {
            return null;
        }
        Map<String, Object> decision = new LinkedHashMap<>();
        decision.put("action", result.getAction());
        decision.put("riskScore", result.resolveAuditRiskScore());
        decision.put("confidence", result.resolveAuditConfidence());
        decision.put("reasoning", result.getReasoning());
        decision.put("llmReasoning", result.getLlmReasoning());
        // W4-3: the reason codes the model gave with the fact IDs they cite; a v19 decision has none.
        if (result.getReasonCodes() != null && !result.getReasonCodes().isEmpty()) {
            decision.put("reasonCodes", result.getReasonCodes());
        }
        decision.put("processingPath", result.getProcessingPath() != null
                ? result.getProcessingPath().name() : null);
        decision.put("llmProposedAction", result.getProposedAction());
        decision.put("technicalFallbackApplied", result.getTechnicalFallbackApplied());
        decision.put("technicalFallbackCategory", result.getTechnicalFallbackCategory());
        decision.put("technicalFallbackReason", result.getTechnicalFallbackReason());
        decision.put("technicalFallbackAction", result.getTechnicalFallbackAction());
        decision.put("responseActionFallbackApplied", result.getResponseActionFallbackApplied());
        decision.put("responseActionFallbackCategory", result.getResponseActionFallbackCategory());
        decision.put("responseActionFallbackReason", result.getResponseActionFallbackReason());
        decision.put("responseActionFallbackAction", result.getResponseActionFallbackAction());
        decision.put("autonomyConstraintApplied", result.getAutonomyConstraintApplied());
        decision.put("autonomyConstraintReasons", result.getAutonomyConstraintReasons());
        decision.put("autonomyConstraintSummary", result.getAutonomyConstraintSummary());
        decision.put("autonomyConstraintPolicy", result.getAutonomyConstraintPolicy());
        decision.put("autonomyConstraintSource", result.getAutonomyConstraintSource());
        decision.put("autonomyConstraintVersion", result.getAutonomyConstraintVersion());
        decision.put("fieldProvenance", result.getFieldProvenance());
        decision.put("aiAnalysisLevel", result.getAiAnalysisLevel());

        Map<String, Object> analysisData = result.getAnalysisData();
        if (analysisData != null) {
            Object layer1 = analysisData.get("layer1Assessment");
            if (layer1 != null) {
                decision.put("layer1Assessment", layer1);
            }
            Object layer2 = analysisData.get("layer2Assessment");
            if (layer2 != null) {
                decision.put("layer2Assessment", layer2);
            }
            Object decisionStage = analysisData.get("decisionAppliedStage");
            if (decisionStage != null) {
                decision.put("decisionAppliedStage", decisionStage);
            }
        }
        // N-OUT-1 (G1-2, G2-8): the model output the decision came from: the first verdict, the re-call, the raw
        // answers and the effective settings, as the decision recorded them.
        Map<String, Object> modelOutput = new LinkedHashMap<>();
        if (eventMetadata != null) {
            for (String key : PromptRuntimeTelemetrySupport.modelOutputRecordKeys()) {
                Object value = eventMetadata.get(key);
                if (value != null) {
                    modelOutput.put(key, value);
                }
            }
        }
        if (!modelOutput.isEmpty()) {
            decision.put("modelOutput", modelOutput);
        }
        // N-SHD-1: a shadow run's seal names the request its copy was made from, the id the decision is sealed under.
        if (eventMetadata != null && eventMetadata.get(PromptShadowRun.ORIGINAL_REQUEST_ID) instanceof String original
                && !original.isBlank()) {
            decision.put(PromptShadowRun.ORIGINAL_REQUEST_ID, original);
        }
        // W6-6: every model call of the decision, layer by layer, as the event recorded them.
        if (eventMetadata != null
                && eventMetadata.get(PromptRuntimeTelemetrySupport.MODEL_CALL_STAGES) instanceof List<?> stages
                && !stages.isEmpty()) {
            decision.put("modelCallStages", stages);
        }

        return toJson(decision);
    }

    // --- Utility ---

    private void putFromMetadata(Map<String, Object> target, SecurityEvent event, String key) {
        if (event.getMetadata() == null) {
            return;
        }
        Object value = event.getMetadata().get(key);
        if (value != null) {
            target.put(key, value);
        }
    }

    private void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value == null) {
            return;
        }
        if (value instanceof String text && text.isBlank()) {
            return;
        }
        target.put(key, value);
    }

    private void putIfAbsent(Map<String, Object> target, String key, Object value) {
        if (target == null || target.containsKey(key)) {
            return;
        }
        putIfPresent(target, key, value);
    }

    private String resolveText(Map<String, Object> metadata, String... keys) {
        if (metadata == null) {
            return null;
        }
        for (String key : keys) {
            Object value = metadata.get(key);
            if (value instanceof String text && !text.isBlank()) {
                return text;
            }
        }
        return null;
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private void normalizeActualResourceIdentity(Map<String, Object> facts, SecurityEvent event) {
        String requestPath = firstNonBlank(objectText(facts.get("requestPath")), objectText(facts.get("servletPath")));
        String declaredTemplate = firstNonBlank(
                objectText(facts.get("protectableResourceUrl")),
                resolveText(event.getMetadata(), "resourceTemplateUrl", "resourceUrl", "resourceTemplate"));
        String currentResource = objectText(facts.get("resourceId"));
        String derivedActualResourceId = firstNonBlank(
                resolveText(event.getMetadata(), "actualResourceId", "runtimeResourceId"),
                deriveResourceIdFromTemplate(requestPath, declaredTemplate),
                looksLikeTemplate(currentResource) ? lastPathSegment(requestPath) : null);
        if (!hasText(derivedActualResourceId) || looksLikeTemplate(derivedActualResourceId)) {
            return;
        }

        String currentRequested = objectText(facts.get("requestedResourceId"));
        if (!hasText(currentRequested) || looksLikeTemplate(currentRequested)) {
            facts.put("requestedResourceId", derivedActualResourceId);
        }
        String currentActual = objectText(facts.get("actualResourceId"));
        if (!hasText(currentActual) || looksLikeTemplate(currentActual)) {
            facts.put("actualResourceId", derivedActualResourceId);
        }
        if (!hasText(currentResource) || looksLikeTemplate(currentResource)) {
            facts.put("resourceId", derivedActualResourceId);
        }
        String currentProtected = objectText(facts.get("protectedResourceId"));
        if (!hasText(currentProtected) && hasText(objectText(facts.get("protectableResourceId")))) {
            facts.put("protectedResourceId", facts.get("protectableResourceId"));
        }
        if (hasText(declaredTemplate) && declaredTemplate.contains("{resourceId}")) {
            facts.put("resourceTemplateUrl", declaredTemplate);
        }
    }

    private String deriveResourceIdFromTemplate(String requestPath, String template) {
        if (!hasText(requestPath) || !hasText(template) || !template.contains("{resourceId}")) {
            return null;
        }
        String[] requestParts = requestPath.split("/");
        String[] templateParts = template.split("/");
        if (requestParts.length != templateParts.length) {
            return null;
        }
        for (int i = 0; i < templateParts.length; i++) {
            if ("{resourceId}".equals(templateParts[i])) {
                return requestParts[i];
            }
        }
        return null;
    }

    private String lastPathSegment(String value) {
        if (!hasText(value)) {
            return null;
        }
        String normalized = value.trim();
        int queryIndex = normalized.indexOf('?');
        if (queryIndex >= 0) {
            normalized = normalized.substring(0, queryIndex);
        }
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        int slashIndex = normalized.lastIndexOf('/');
        return slashIndex >= 0 ? normalized.substring(slashIndex + 1) : normalized;
    }

    private boolean looksLikeTemplate(String value) {
        return hasText(value) && (value.contains("{") || value.contains("}"));
    }

    private String objectText(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isBlank() ? null : text;
    }

    private String toJson(Map<String, Object> map) {
        if (map == null || map.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(map);
        } catch (JsonProcessingException e) {
            log.error("[SealedEvidence] Failed to serialize to JSON", e);
            return null;
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    /** The hash of a value, none for a blank one. */
    private String sha256Prefixed(String value) {
        return hasText(value) ? PromptGovernanceSupport.sha256(value) : null;
    }
}

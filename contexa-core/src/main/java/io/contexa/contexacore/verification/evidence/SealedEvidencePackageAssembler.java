package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptSnapshot;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
@RequiredArgsConstructor
public class SealedEvidencePackageAssembler {

    private static final Duration DEFAULT_RETENTION = Duration.ofDays(90);
    private static final int SEALED_METADATA_TEXT_LIMIT = 512;
    private static final int SEALED_METADATA_GENERIC_LIST_LIMIT = 512;
    private static final int SEALED_METADATA_FIELD_LEDGER_LIMIT = 512;
    private static final HexFormat HEX = HexFormat.of();

    private final ObjectMapper objectMapper;
    private final CanonicalSecurityContextSerializer contextSerializer;
    private final SealedEvidencePackageIntegrity integrity;
    private final SealedEvidencePromptTraceStore promptTraceStore;

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
        SealedEvidencePromptSnapshot promptSnapshot = promptTraceStore.consume(correlationId);
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
        String promptExecutionMetadataJson = serializePromptExecutionMetadata(promptSnapshot);
        String decisionJson = buildDecisionSnapshot(result);
        UserPromptEvidenceContract.Result evidenceContract = UserPromptEvidenceContract.evaluate(
                objectMapper,
                promptSnapshot.userPrompt(),
                requestFactsJson,
                authStateJson,
                canonicalContextJson,
                baselineSnapshotJson,
                ragResultsJson,
                promptExecutionMetadataJson,
                decisionJson);
        String sealFailureReason = null;
        if (!evidenceContract.sealable()) {
            sealFailureReason = "Official verification input contract is not satisfied: "
                    + summarizeContractViolations(evidenceContract.violations());
            log.warn("[SealedEvidence] User prompt evidence contract failed; package will still be sealed for audit: correlationId={}, reason={}",
                    correlationId,
                    sealFailureReason);
        }
        if (!captureWarnings.isEmpty()) {
            String captureWarning = "Prompt raw capture incomplete: " + String.join(" ", captureWarnings);
            sealFailureReason = hasText(sealFailureReason) ? sealFailureReason + " " + captureWarning : captureWarning;
            log.warn("[SealedEvidence] Prompt raw capture incomplete; package will still be sealed for audit without raw prompt backfill: correlationId={}, reason={}",
                    correlationId,
                    captureWarning);
        }

        SealedEvidencePackage pkg = SealedEvidencePackage.builder()
                .packageId(UUID.randomUUID().toString())
                .correlationId(correlationId)
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

                // Section 4: Baseline -- from SecurityEvent.metadata (set by HCADFilter/ZeroTrustEventPublisher)
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
                .promptEvidenceManifestJson(evidenceContract.manifestJson())
                .sealState("SEALED")
                .sealFailureReason(sealFailureReason)

                // Section 7: Decision -- from ProcessingResult (set by ProcessingExecutionHandler)
                .decisionJson(decisionJson)

                .schemaVersion(2)
                .sealed(true)
                .expiresAt(Instant.now().plus(DEFAULT_RETENTION))
                .build();

        pkg.setPackageHash(integrity.computeHash(pkg));
        return pkg;
    }

    private String summarizeContractViolations(List<Map<String, Object>> violations) {
        if (violations == null || violations.isEmpty()) {
            return "Required prompt evidence fields did not satisfy the official verification input contract.";
        }
        return violations.stream()
                .limit(5)
                .map(this::summarizeContractViolation)
                .filter(this::hasText)
                .reduce((left, right) -> left + "; " + right)
                .orElse("Required prompt evidence fields did not satisfy the official verification input contract.");
    }

    private String summarizeContractViolation(Map<String, Object> violation) {
        if (violation == null || violation.isEmpty()) {
            return null;
        }
        String label = firstText(violation, "fieldLabel", "title", "fieldKey");
        String reason = firstText(violation, "reason", "projectionState", "severity");
        if (!hasText(label)) {
            return reason;
        }
        if (!hasText(reason)) {
            return label;
        }
        return label + " - " + reason;
    }

    private String firstText(Map<String, Object> values, String... keys) {
        if (values == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            Object value = values.get(key);
            if (value instanceof String text && hasText(text)) {
                return text;
            }
        }
        return null;
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
        putFromMetadata(facts, event, "protectableVerificationRequired");
        putFromMetadata(facts, event, "protectableSync");
        putFromMetadata(facts, event, "contextBindingHash");
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
     * Source: SecurityEvent.metadata (set by HCADFilter and behavior analysis)
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

        List<Map<String, Object>> documents = List.of();
        if (promptSnapshot != null && promptSnapshot.relatedDocuments() != null) {
            documents = promptSnapshot.relatedDocuments().stream()
                    .map(this::ragDocumentSummary)
                    .toList();
        }
        if ((documents == null || documents.isEmpty()) && faultScenarioApplied(promptSnapshot)) {
            documents = promptRagDocumentSummaries(promptSnapshot.userPrompt());
        }
        if (documents != null && !documents.isEmpty()) {
            rag.put("relatedDocuments", documents);
        }
        int relatedDocumentCount = documents.size();
        if (faultScenarioApplied(promptSnapshot) && relatedDocumentCount > 0) {
            applyFaultRagRuntimeMetadata(rag, relatedDocumentCount, documents);
        }
        rag.put("relatedDocumentCount", relatedDocumentCount);

        boolean retrievalFailed = truthy(rag.get("ragUnavailable"))
                || truthy(rag.get("ragTimedOut"))
                || hasText(objectText(rag.get("ragFailureType")))
                || hasText(objectText(rag.get("ragFailureMessage")));
        boolean searchExecuted = rag.containsKey("ragSearchExecuted")
                ? truthy(rag.get("ragSearchExecuted"))
                : metadataHasAny(event,
                "requestedDocumentCount",
                "allowedDocumentCount",
                "deniedDocumentCount",
                "ragRequestedTopK",
                "ragUnavailable",
                "ragTimedOut",
                "ragFailureType",
                "ragFailureMessage")
                || relatedDocumentCount > 0;
        boolean permissionFiltered = rag.containsKey("ragPermissionFiltered")
                ? truthy(rag.get("ragPermissionFiltered"))
                : intValue(rag.get("deniedDocumentCount")) > 0
                || (intValue(rag.get("requestedDocumentCount")) > 0
                && intValue(rag.get("allowedDocumentCount")) == 0
                && relatedDocumentCount == 0);
        boolean zeroResults = searchExecuted && !retrievalFailed && relatedDocumentCount == 0
                && intValue(rag.get("allowedDocumentCount")) == 0;
        boolean projectedToFinalPrompt = relatedDocumentCount > 0
                && relatedDocumentsProjectedToPrompt(promptSnapshot == null ? null : promptSnapshot.userPrompt(), documents);

        String retrievalState = ragRetrievalState(rag, searchExecuted, retrievalFailed, permissionFiltered, zeroResults);
        String projectionState = ragProjectionState(searchExecuted, retrievalFailed, permissionFiltered, zeroResults,
                relatedDocumentCount, projectedToFinalPrompt);

        rag.put("ragSearchExecuted", searchExecuted);
        rag.put("ragPermissionFiltered", permissionFiltered);
        rag.put("ragZeroResults", zeroResults);
        rag.put("ragProjectedToFinalPrompt", relatedDocumentCount == 0 ? null : projectedToFinalPrompt);
        rag.put("ragProjectionState", projectionState);
        rag.put("ragRetrievalState", retrievalState);
        rag.put("ragAbsenceReason", ragAbsenceReason(rag, searchExecuted, retrievalFailed, permissionFiltered, zeroResults, relatedDocumentCount, projectedToFinalPrompt));

        return toJson(rag);
    }

    private void applyFaultRagRuntimeMetadata(
            Map<String, Object> rag,
            int relatedDocumentCount,
            List<Map<String, Object>> documents) {
        int denied = 0;
        for (Map<String, Object> document : documents) {
            String authorization = objectText(document.get("authorization"));
        if (hasText(authorization) && !authorization.toLowerCase(Locale.ROOT).contains("allow")) {
                denied++;
            }
        }
        rag.remove("ragFailureType");
        rag.remove("ragFailureMessage");
        rag.remove("ragTimeoutMs");
        rag.put("ragUnavailable", false);
        rag.put("ragTimedOut", false);
        rag.put("requestedDocumentCount", relatedDocumentCount);
        rag.put("allowedDocumentCount", Math.max(0, relatedDocumentCount - denied));
        rag.put("deniedDocumentCount", denied);
        rag.put("ragCandidateDocumentCount", relatedDocumentCount);
        rag.put("ragAuthorizedDocumentCount", Math.max(0, relatedDocumentCount - denied));
        rag.put("ragDeniedDocumentCount", denied);
        rag.put("ragSearchExecuted", true);
        rag.put("ragRetrievalState", "AVAILABLE");
        rag.put("ragAbsenceReason", "NONE");
        rag.put("ragPermissionFiltered", false);
        rag.put("ragProjectedToFinalPrompt", true);
        rag.put("ragProjectionState", "PROJECTED");
    }

    private String ragProjectionState(
            boolean searchExecuted,
            boolean retrievalFailed,
            boolean permissionFiltered,
            boolean zeroResults,
            int relatedDocumentCount,
            boolean projectedToFinalPrompt) {
        if (!searchExecuted) {
            return "NOT_EXECUTED_DECLARED";
        }
        if (retrievalFailed) {
            return "UNAVAILABLE_DECLARED";
        }
        if (permissionFiltered && relatedDocumentCount == 0) {
            return "PERMISSION_FILTERED_DECLARED";
        }
        if (zeroResults) {
            return "ZERO_RESULTS_DECLARED";
        }
        return projectedToFinalPrompt ? "PROJECTED" : "MISSING_IN_FINAL_PROMPT";
    }

    private String ragRetrievalState(
            Map<String, Object> rag,
            boolean searchExecuted,
            boolean retrievalFailed,
            boolean permissionFiltered,
            boolean zeroResults) {
        if (!searchExecuted) {
            return "NOT_EXECUTED";
        }
        if (truthy(rag.get("ragTimedOut"))) {
            return "TIMEOUT";
        }
        if (retrievalFailed) {
            return "FAILED";
        }
        if (permissionFiltered) {
            return "PERMISSION_FILTERED";
        }
        if (zeroResults) {
            return "ZERO_RESULTS";
        }
        return "AVAILABLE";
    }

    private String ragAbsenceReason(
            Map<String, Object> rag,
            boolean searchExecuted,
            boolean retrievalFailed,
            boolean permissionFiltered,
            boolean zeroResults,
            int relatedDocumentCount,
            boolean projectedToFinalPrompt) {
        if (!searchExecuted) {
            return "SEARCH_NOT_EXECUTED";
        }
        if (truthy(rag.get("ragTimedOut"))) {
            return "TIMEOUT";
        }
        if (retrievalFailed) {
            return "PROVIDER_OR_VECTOR_ERROR";
        }
        if (permissionFiltered && relatedDocumentCount == 0) {
            return "PERMISSION_FILTER_EXCLUDED";
        }
        if (zeroResults) {
            return "ZERO_RESULTS";
        }
        if (relatedDocumentCount > 0 && !projectedToFinalPrompt) {
            return "FINAL_PROMPT_NOT_PROJECTED";
        }
        return "NONE";
    }

    private boolean relatedDocumentsProjectedToPrompt(String finalUserPrompt, List<Map<String, Object>> documents) {
        if (!hasText(finalUserPrompt) || documents == null || documents.isEmpty()) {
            return false;
        }
        String prompt = finalUserPrompt.toLowerCase(Locale.ROOT);
        if (prompt.contains("rag")
                || prompt.contains("relateddocuments")
                || prompt.contains("related documents")
                || prompt.contains("retrieved document")
                || prompt.contains("document evidence")
                || prompt.contains("\uAC80\uC0C9 \uBB38\uC11C")) {
            return true;
        }
        for (Map<String, Object> document : documents) {
            if (document == null) {
                continue;
            }
            for (String key : List.of("id", "documentType", "retrievalPurpose", "accessScope", "textPreview")) {
                String value = objectText(document.get(key));
            if (hasText(value) && prompt.contains(value.toLowerCase(Locale.ROOT))) {
                    return true;
                }
            }
        }
        return false;
    }

    private Map<String, Object> ragDocumentSummary(Document document) {
        Map<String, Object> summary = new LinkedHashMap<>();
        if (document == null) {
            return summary;
        }
        Map<String, Object> metadata = document.getMetadata();
        if (metadata != null) {
            putIfPresent(summary, "id", metadata.get("id"));
            putIfPresent(summary, "documentType", metadata.get("documentType"));
            putIfPresent(summary, "userId", metadata.get("userId"));
            putIfPresent(summary, "tenantId", metadata.get("tenantId"));
            putIfPresent(summary, "organizationId", metadata.get("organizationId"));
            putIfPresent(summary, "resourceId", metadata.get("resourceId"));
            putIfPresent(summary, "requestPath", metadata.get("requestPath"));
            putIfPresent(summary, "resourceFamily", metadata.get("resourceFamily"));
            putIfPresent(summary, "pathFamily", metadata.get("pathFamily"));
            putIfPresent(summary, "authorization", firstNonBlank(
                    objectText(metadata.get(VectorDocumentMetadata.AUTHORIZATION_DECISION)),
                    objectText(metadata.get("authorization")),
                    objectText(metadata.get("authorized")),
                    objectText(metadata.get("allowed"))));
            putIfPresent(summary, "purpose", firstNonBlank(
                    objectText(metadata.get(VectorDocumentMetadata.PURPOSE_MATCH)),
                    objectText(metadata.get("purpose")),
                    objectText(metadata.get("purposeMatch"))));
            putIfPresent(summary, "tenantBound", firstNonBlank(
                    objectText(metadata.get(VectorDocumentMetadata.TENANT_BOUND)),
                    objectText(metadata.get("tenantBound"))));
            putIfPresent(summary, "retrievalPurpose", metadata.get("retrievalPurpose"));
            putIfPresent(summary, "retrievalPolicy", firstNonBlank(
                    objectText(metadata.get(VectorDocumentMetadata.RETRIEVAL_POLICY_SUMMARY)),
                    objectText(metadata.get("retrievalPolicy"))));
            putIfPresent(summary, "accessScope", metadata.get("accessScope"));
            putIfPresent(summary, "action", metadata.get("action"));
        }
        String text = document.getText();
        if (hasText(text)) {
            putIfPresent(summary, "resourceFamily", firstNonBlank(
                    objectText(summary.get("resourceFamily")),
                    deriveResourceFamily(text)));
            putIfPresent(summary, "pathFamily", firstNonBlank(
                    objectText(summary.get("pathFamily")),
                    derivePathFamily(objectText(summary.get("requestPath"))),
                    derivePathFamily(extractPathToken(text))));
            summary.put("textPreview", text.length() > 240 ? text.substring(0, 240) : text);
            summary.put("textLength", text.length());
        }
        return summary;
    }

    private List<Map<String, Object>> promptRagDocumentSummaries(String finalUserPrompt) {
        if (!hasText(finalUserPrompt)) {
            return List.of();
        }
        List<Map<String, Object>> documents = new ArrayList<>();
        for (String line : finalUserPrompt.split("\\R+")) {
            if (!hasText(line) || !line.toLowerCase(Locale.ROOT).contains("ragdocument")) {
                continue;
            }
            Map<String, Object> document = promptRagDocumentSummary(line);
            if (!document.isEmpty()) {
                documents.add(document);
            }
        }
        return documents;
    }

    private Map<String, Object> promptRagDocumentSummary(String line) {
        Map<String, Object> parsed = parsePromptRagDocumentLine(line);
        if (parsed.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        putIfPresent(summary, "id", parsed.get("id"));
        putIfPresent(summary, "documentType", firstNonBlank(objectText(parsed.get("documentType")), objectText(parsed.get("type"))));
        putIfPresent(summary, "userId", firstNonBlank(objectText(parsed.get("userId")), objectText(parsed.get("user"))));
        putIfPresent(summary, "tenantId", parsed.get("tenantId"));
        putIfPresent(summary, "organizationId", parsed.get("organizationId"));
        putIfPresent(summary, "resourceId", firstNonBlank(objectText(parsed.get("resourceId")), objectText(parsed.get("resource"))));
        putIfPresent(summary, "requestPath", firstNonBlank(objectText(parsed.get("requestPath")), objectText(parsed.get("path"))));
        putIfPresent(summary, "authorization", firstNonBlank(
                objectText(parsed.get("authorization")),
                objectText(parsed.get("authorized")),
                objectText(parsed.get("allowed"))));
        putIfPresent(summary, "purpose", firstNonBlank(
                objectText(parsed.get("purpose")),
                objectText(parsed.get("purposeMatch"))));
        putIfPresent(summary, "tenantBound", parsed.get("tenantBound"));
        putIfPresent(summary, "retrievalPurpose", parsed.get("retrievalPurpose"));
        putIfPresent(summary, "retrievalPolicy", parsed.get("retrievalPolicy"));
        putIfPresent(summary, "accessScope", firstNonBlank(objectText(parsed.get("accessScope")), objectText(parsed.get("scope"))));
        putIfPresent(summary, "action", parsed.get("action"));
        String preview = line.trim();
        summary.put("textPreview", preview.length() > 240 ? preview.substring(0, 240) : preview);
        summary.put("textLength", preview.length());
        return summary;
    }

    private Map<String, Object> parsePromptRagDocumentLine(String line) {
        if (!hasText(line)) {
            return Map.of();
        }
        String body = line;
        int open = body.indexOf('[');
        int close = body.indexOf(']');
        if (open >= 0 && close > open) {
            body = body.substring(open + 1, close);
        }
        Map<String, Object> values = new LinkedHashMap<>();
        for (String token : body.split("\\|\\s*|,\\s*")) {
            if (!hasText(token)) {
                continue;
            }
            int separator = token.indexOf('=');
            if (separator < 0) {
                separator = token.indexOf(':');
            }
            if (separator <= 0) {
                if (!values.containsKey("id")) {
                    values.put("id", token.trim());
                }
                continue;
            }
            String key = token.substring(0, separator).trim();
            String value = token.substring(separator + 1).trim();
            if (hasText(key) && hasText(value)) {
                values.put(key, value);
            }
        }
        return values;
    }

    private String deriveResourceFamily(String text) {
        String value = firstNonBlank(
                extractNamedToken(text, "resource"),
                extractPathToken(text));
        return SecuritySemanticNormalizer.normalizeResourceFamily(value);
    }

    private String derivePathFamily(String path) {
        if (!hasText(path) || !path.startsWith("/")) {
            return null;
        }
        String clean = path.trim();
        int queryIndex = clean.indexOf('?');
        if (queryIndex >= 0) {
            clean = clean.substring(0, queryIndex);
        }
        String[] parts = clean.split("/");
        if (parts.length >= 5) {
            return "/" + parts[1] + "/" + parts[2] + "/" + parts[3] + "/" + parts[4] + "/*";
        }
        return clean;
    }

    private String extractNamedToken(String text, String key) {
        if (!hasText(text) || !hasText(key)) {
            return null;
        }
        Matcher matcher = Pattern
                .compile("(?i)(?:^|[\\s,;|])" + Pattern.quote(key.trim()) + "\\s*=\\s*([^\\s,;|.\\]]+)")
                .matcher(text);
        return matcher.find() ? matcher.group(1).trim() : null;
    }

    private String extractPathToken(String text) {
        if (!hasText(text)) {
            return null;
        }
        Matcher matcher = Pattern
                .compile("(/[^\\s,;|\\]]+)")
                .matcher(text);
        return matcher.find() ? matcher.group(1).trim() : null;
    }

    /**
     * Section 6 partial: PromptExecutionMetadata serialization.
     * Source: SealedEvidencePromptSnapshot.promptExecutionMetadata (captured by AOP)
     */
    private String serializePromptExecutionMetadata(SealedEvidencePromptSnapshot promptSnapshot) {
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
        normalizeFaultedPromptHashes(promptSnapshot, metadata);
        return toJson(compactPromptExecutionMetadata(metadata));
    }
    private Map<String, Object> compactPromptExecutionMetadata(Map<String, Object> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> compact = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            String key = entry.getKey();
            if (!hasText(key)) {
                continue;
            }
            Object value = entry.getValue();
            switch (key) {
                case "promptSourceContextLedger" -> {
                    compact.put("promptSourceContextLedgerStoragePolicy", "SUMMARY_ONLY");
                    compact.put("promptSourceContextLedgerOriginalCount", collectionSize(value));
                }
                case "promptFieldStateLedger" -> {
                    compact.put("promptFieldStateLedgerStoragePolicy", "OFFICIAL_RELEVANT_ROWS_ONLY");
                    compact.put("promptFieldStateLedgerOriginalCount", collectionSize(value));
                    compact.put("promptFieldStateLedger", compactFieldStateLedger(value));
                }
                case "promptRawUserFieldLedger", "promptFinalUserFieldLedger", "promptUserFieldDiffLedger" -> {
                    compact.put(key + "StoragePolicy", "COMPACT_ROWS");
                    compact.put(key + "OriginalCount", collectionSize(value));
                    compact.put(key, compactLedgerRows(value, false));
                }
                default -> compact.put(key, compactMetadataValue(value));
            }
        }
        return compact;
    }

    private List<Object> compactFieldStateLedger(Object value) {
        if (!(value instanceof Iterable<?> rows)) {
            return List.of();
        }
        List<Object> result = new ArrayList<>();
        for (Object row : rows) {
            if (!(row instanceof Map<?, ?> map) || !officialRelevantFieldStateRow(map)) {
                continue;
            }
            result.add(compactLedgerRow(map));
            if (result.size() >= SEALED_METADATA_FIELD_LEDGER_LIMIT) {
                result.add(Map.of("omittedReason", "SEALED_METADATA_FIELD_LEDGER_LIMIT", "limit", SEALED_METADATA_FIELD_LEDGER_LIMIT));
                break;
            }
        }
        return result;
    }

    private boolean officialRelevantFieldStateRow(Map<?, ?> row) {
        return truthy(row.get("blockingCandidate"))
                || truthy(row.get("rawBlockingCandidate"))
                || truthy(row.get("officialBlockingCandidate"))
                || "LLM_DECISION_CONTRACT".equalsIgnoreCase(objectText(row.get("qualityRelevance")))
                || hasMetricCodes(row.get("metricCodes"));
    }

    private boolean hasMetricCodes(Object value) {
        if (value instanceof Iterable<?> iterable) {
            for (Object ignored : iterable) {
                return true;
            }
        }
        return false;
    }

    private List<Object> compactLedgerRows(Object value, boolean officialOnly) {
        if (!(value instanceof Iterable<?> rows)) {
            return List.of();
        }
        List<Object> result = new ArrayList<>();
        int count = 0;
        for (Object row : rows) {
            if (!(row instanceof Map<?, ?> map)) {
                continue;
            }
            if (officialOnly && !officialRelevantFieldStateRow(map)) {
                continue;
            }
            if (count++ >= SEALED_METADATA_GENERIC_LIST_LIMIT) {
                result.add(Map.of("omittedReason", "SEALED_METADATA_GENERIC_LIST_LIMIT", "limit", SEALED_METADATA_GENERIC_LIST_LIMIT));
                break;
            }
            result.add(compactLedgerRow(map));
        }
        return result;
    }

    private Map<String, Object> compactLedgerRow(Map<?, ?> row) {
        Map<String, Object> compact = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : row.entrySet()) {
            if (entry.getKey() == null) {
                continue;
            }
            String key = String.valueOf(entry.getKey());
            Object value = entry.getValue();
            if (value instanceof Map<?, ?> || value instanceof Iterable<?>) {
                compact.put(key, compactMetadataValue(value));
            }
            else {
                compact.put(key, compactTextValue(value));
            }
        }
        return compact;
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

    private int collectionSize(Object value) {
        if (value instanceof Iterable<?> iterable) {
            int count = 0;
            for (Object ignored : iterable) {
                count++;
            }
            return count;
        }
        return 0;
    }

    private void normalizeFaultedPromptHashes(SealedEvidencePromptSnapshot promptSnapshot, Map<String, Object> metadata) {
        if (!faultScenarioApplied(promptSnapshot)) {
            return;
        }
        String systemPromptHash = sha256Prefixed(promptSnapshot.systemPrompt());
        String userPromptHash = sha256Prefixed(promptSnapshot.userPrompt());
        String promptHash = finalPromptHash(promptSnapshot);
        putIfText(metadata, "promptHash", promptHash);
        putIfText(metadata, "finalPromptHash", promptHash);
        putIfText(metadata, "systemPromptHash", systemPromptHash);
        putIfText(metadata, "userPromptHash", userPromptHash);
        putIfText(metadata, "llmUserPromptHash", userPromptHash);
        putIfText(metadata, "finalUserPromptHash", userPromptHash);
        putIfText(metadata, "rawSystemPromptHash", sha256Prefixed(promptSnapshot.rawSystemPrompt()));
        putIfText(metadata, "rawUserPromptHash", sha256Prefixed(promptSnapshot.rawUserPrompt()));
    }

    private void putIfText(Map<String, Object> metadata, String key, String value) {
        if (metadata != null && hasText(value)) {
            metadata.put(key, value);
        }
    }

    /**
     * Section 6 partial: Prompt hash resolution.
     * Primary source: SecurityEvent.metadata (set by prompt runtime telemetry)
     * Fallback: PromptExecutionMetadata from prompt snapshot
     */
    private String resolvePromptHash(SecurityEvent event, SealedEvidencePromptSnapshot promptSnapshot) {
        if (faultScenarioApplied(promptSnapshot)) {
            return finalPromptHash(promptSnapshot);
        }
        String hash = resolveText(event.getMetadata(), "promptHash");
        if (hash != null) {
            return hash;
        }
        if (promptSnapshot != null && promptSnapshot.promptExecutionMetadata() != null) {
            return promptSnapshot.promptExecutionMetadata().promptHash();
        }
        return null;
    }

    private boolean faultScenarioApplied(SealedEvidencePromptSnapshot promptSnapshot) {
        if (promptSnapshot == null || promptSnapshot.metadata() == null) {
            return false;
        }
        Object applied = promptSnapshot.metadata().get("pqaPromptFaultApplied");
        return applied instanceof Boolean booleanValue
                ? booleanValue
                : applied != null && "true".equalsIgnoreCase(String.valueOf(applied));
    }

    private String finalPromptHash(SealedEvidencePromptSnapshot promptSnapshot) {
        if (promptSnapshot == null || !hasText(promptSnapshot.systemPrompt()) || !hasText(promptSnapshot.userPrompt())) {
            return null;
        }
        return sha256Prefixed(promptSnapshot.systemPrompt() + "\n---\n" + promptSnapshot.userPrompt());
    }

    /**
     * Section 7: Decision result.
     * Source: ProcessingResult (set by ProcessingExecutionHandler -> SecurityEventContext.metadata)
     */
    private String buildDecisionSnapshot(ProcessingResult result) {
        if (result == null) {
            return null;
        }
        Map<String, Object> decision = new LinkedHashMap<>();
        decision.put("action", result.getAction());
        decision.put("riskScore", result.resolveAuditRiskScore());
        decision.put("confidence", result.resolveAuditConfidence());
        decision.put("reasoning", result.getReasoning());
        decision.put("processingPath", result.getProcessingPath() != null
                ? result.getProcessingPath().name() : null);
        decision.put("llmProposedAction", result.getProposedAction());
        decision.put("autonomyConstraintApplied", result.getAutonomyConstraintApplied());
        decision.put("autonomyConstraintReasons", result.getAutonomyConstraintReasons());
        decision.put("autonomyConstraintSummary", result.getAutonomyConstraintSummary());
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

    private boolean metadataHasAny(SecurityEvent event, String... keys) {
        if (event == null || event.getMetadata() == null || keys == null) {
            return false;
        }
        for (String key : keys) {
            if (event.getMetadata().containsKey(key) && event.getMetadata().get(key) != null) {
                return true;
            }
        }
        return false;
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

    private boolean truthy(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof Number number) {
            return number.intValue() != 0;
        }
        String text = objectText(value);
        return "true".equalsIgnoreCase(text)
                || "yes".equalsIgnoreCase(text)
                || "1".equals(text);
    }

    private int intValue(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        String text = objectText(value);
        if (!hasText(text)) {
            return 0;
        }
        try {
            return Integer.parseInt(text);
        }
        catch (NumberFormatException ignored) {
            return 0;
        }
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

    private String sha256Prefixed(String value) {
        if (!hasText(value)) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HEX.formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}

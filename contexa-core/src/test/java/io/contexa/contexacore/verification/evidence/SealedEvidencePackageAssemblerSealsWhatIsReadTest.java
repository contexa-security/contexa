package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * R4-C2: the sealed package keeps what a decision recorded and what the prompt inspector reads (the inspection sources
 * test), and nothing the twelve-metric verification alone used: no evidence contract, no fault scenario rewriting, no
 * retrieval state recomputed at sealing, no runtime governance rule keys, no canonical context hash, no verification
 * model key and no metadata provider ledgers.
 */
class SealedEvidencePackageAssemblerSealsWhatIsReadTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    private final SealedEvidencePromptTraceStore traceStore = new SealedEvidencePromptTraceStore();
    private final SealedEvidencePackageAssembler assembler = new SealedEvidencePackageAssembler(
            JSON, new CanonicalSecurityContextSerializer(JSON), new SealedEvidencePackageIntegrity(), traceStore);

    /** R4-S4 (D-C): a package expires after the retention the host sets, by default 90 days. */
    @Test
    void aPackageExpiresAfterTheRetentionTheHostSets() {
        SealedEvidencePackageAssembler thirtyDays = new SealedEvidencePackageAssembler(JSON,
                new CanonicalSecurityContextSerializer(JSON), new SealedEvidencePackageIntegrity(), traceStore,
                Duration.ofDays(30));

        Instant before = Instant.now();
        SealedEvidencePackage kept = seal(thirtyDays, "req-s4-1", "user prompt", Map.of(), List.of(), Map.of());
        SealedEvidencePackage defaulted = seal("req-s4-2", "user prompt", Map.of(), List.of(), Map.of());
        Instant after = Instant.now();

        assertThat(kept.getExpiresAt()).isBetween(before.plus(Duration.ofDays(30)), after.plus(Duration.ofDays(30)));
        assertThat(defaulted.getExpiresAt()).isBetween(before.plus(Duration.ofDays(90)), after.plus(Duration.ofDays(90)));
    }

    /** W4-3: the decision record keeps the reason codes the model gave with the fact IDs they cite. */
    @Test
    void theDecisionRecordKeepsTheReasonCodes() throws Exception {
        SealedEvidencePackage sealed = seal(assembler, "req-w43", "user prompt", Map.of(), List.of(), Map.of(),
                List.of(new SecurityDecisionOutputContract.Citation("DEVIATION_TIME", "F1")));

        Map<String, Object> decision = JSON.readValue(sealed.getDecisionJson(), MAP);
        assertThat(decision).containsEntry("reasonCodes", List.of(Map.of("code", "DEVIATION_TIME", "fact", "F1")));
    }

    /** W6-6 (P6-CHANGE-4): the decision section keeps every model call stage the event recorded, in order. */
    @Test
    void theDecisionSectionKeepsEveryModelCallStage() throws Exception {
        List<Map<String, Object>> stages = List.of(Map.of("layer", "Layer1", "userPromptHash", "sha256:first"),
                Map.of("layer", "Layer2", "userPromptHash", "sha256:first"));
        Map<String, Object> eventMetadata = new HashMap<>();
        eventMetadata.put("modelCallStages", stages);

        SealedEvidencePackage sealed = seal("req-w66", "user prompt", Map.of(), List.of(), eventMetadata);

        Map<String, Object> decision = JSON.readValue(sealed.getDecisionJson(), MAP);
        assertThat(decision.get("modelCallStages")).isEqualTo(stages);
    }

    /**
     * N-OUT-1 (G1-2, G2-8): the decision section keeps the model output: the first verdict, the re-call, the raw answers
     * and the effective settings the call ran with.
     */
    @Test
    void theDecisionSectionKeepsTheModelOutput() throws Exception {
        Map<String, Object> eventMetadata = new HashMap<>();
        eventMetadata.put("securityDecisionInitialProposedAction", "CHALLENGE");
        eventMetadata.put("securityDecisionOutputRetryAttempted", true);
        eventMetadata.put("securityDecisionOutputRetryReason", "REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH");
        eventMetadata.put("securityDecisionInitialRawOutput", "{\"action\":\"CHALLENGE\"}");
        eventMetadata.put("securityDecisionRawOutput", "{\"action\":\"ALLOW\"}");
        eventMetadata.put("maxTokens", 2048);
        eventMetadata.put("providerReasoningEffort", "low");
        eventMetadata.put("providerResponseModel", "gpt-6-luna-2026-09-30");
        eventMetadata.put("providerFinishReason", "stop");

        SealedEvidencePackage sealed = seal("req-n-out-1", "user prompt", Map.of(), List.of(), eventMetadata);

        Map<String, Object> decision = JSON.readValue(sealed.getDecisionJson(), MAP);
        assertThat(decision.get("modelOutput")).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> modelOutput = (Map<String, Object>) decision.get("modelOutput");
        assertThat(modelOutput)
                .containsEntry("securityDecisionInitialProposedAction", "CHALLENGE")
                .containsEntry("securityDecisionOutputRetryAttempted", true)
                .containsEntry("securityDecisionInitialRawOutput", "{\"action\":\"CHALLENGE\"}")
                .containsEntry("securityDecisionRawOutput", "{\"action\":\"ALLOW\"}")
                .containsEntry("maxTokens", 2048)
                .containsEntry("providerReasoningEffort", "low")
                .containsEntry("providerResponseModel", "gpt-6-luna-2026-09-30")
                .containsEntry("providerFinishReason", "stop");
    }

    /**
     * N-OUT-3: the model output keeps every output retry of the decision in its order across the layers, next to the
     * single retry fields that hold the last layer's; the model call stages stay as the event recorded them.
     */
    @Test
    void theModelOutputKeepsEveryOutputRetryInItsOrder() throws Exception {
        List<Map<String, Object>> retries = List.of(
                Map.of("layer", "Layer1", "reason", "OUTPUT_TRUNCATED", "succeeded", false,
                        "failureReason", "REASON_CODE_MISMATCH"),
                Map.of("layer", "Layer2", "reason", "REASON_CODE_MISMATCH", "succeeded", false,
                        "failureReason", "REASON_CODE_MISMATCH"));
        List<Map<String, Object>> stages = List.of(Map.of("layer", "Layer1", "userPromptHash", "sha256:first"),
                Map.of("layer", "Layer2", "userPromptHash", "sha256:first"));
        Map<String, Object> eventMetadata = new HashMap<>();
        eventMetadata.put("securityDecisionOutputRetryAttempted", true);
        eventMetadata.put("securityDecisionOutputRetryReason", "REASON_CODE_MISMATCH");
        eventMetadata.put("securityDecisionOutputRetrySucceeded", false);
        eventMetadata.put(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES, retries);
        eventMetadata.put("modelCallStages", stages);

        SealedEvidencePackage sealed = seal("req-n-out-3", "user prompt", Map.of(), List.of(), eventMetadata);

        Map<String, Object> decision = JSON.readValue(sealed.getDecisionJson(), MAP);
        assertThat(decision.get("modelOutput")).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> modelOutput = (Map<String, Object>) decision.get("modelOutput");
        assertThat(modelOutput)
                .containsEntry(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES, retries)
                .containsEntry("securityDecisionOutputRetryReason", "REASON_CODE_MISMATCH")
                .containsEntry("securityDecisionOutputRetrySucceeded", false);
        assertThat(decision.get("modelCallStages")).isEqualTo(stages);
    }

    @Test
    void noEvidenceContractIsEvaluatedOrSealed() {
        SealedEvidencePackage sealed = seal("req-c2-1", "user prompt", Map.of(), List.of(), Map.of());

        assertThat(sealed.getPromptEvidenceManifestJson()).isNull();
        assertThat(sealed.getSealFailureReason()).isNull();
        assertThat(new SealedEvidencePackageIntegrity().evaluate(sealed))
                .isEqualTo(SealedEvidencePackageIntegrity.Status.VERIFIED);
    }

    @Test
    void theRetrievalStateIsSealedAsTheDecisionRecordedIt() throws Exception {
        Map<String, Object> eventMetadata = new HashMap<>();
        eventMetadata.put("ragSearchExecuted", true);
        eventMetadata.put("ragRetrievalState", "AVAILABLE");
        eventMetadata.put("allowedDocumentCount", 0);

        SealedEvidencePackage sealed = seal("req-c2-2", "user prompt", Map.of(), List.of(), eventMetadata);

        Map<String, Object> rag = JSON.readValue(sealed.getRagResultsJson(), MAP);
        assertThat(rag).containsEntry("ragRetrievalState", "AVAILABLE")
                .containsEntry("ragSearchExecuted", true)
                .containsEntry("relatedDocumentCount", 0)
                .doesNotContainKeys("ragZeroResults", "ragProjectionState", "ragAbsenceReason", "ragPermissionFiltered");
    }

    @Test
    void aFaultScenarioMarkerNoLongerRewritesTheSealedPackage() throws Exception {
        Map<String, Object> promptMetadata = new HashMap<>();
        promptMetadata.put("pqaPromptFaultApplied", true);
        Map<String, Object> eventMetadata = new HashMap<>();
        eventMetadata.put("promptHash", "sha256:recorded-by-the-decision");

        SealedEvidencePackage sealed = seal("req-c2-3", "ragDocument [id=doc-9|action=EXPORT|authorization=DENY]",
                promptMetadata, List.of(), eventMetadata);

        assertThat(sealed.getPromptHash()).isEqualTo("sha256:recorded-by-the-decision");
        Map<String, Object> rag = JSON.readValue(sealed.getRagResultsJson(), MAP);
        assertThat(rag).doesNotContainKey("relatedDocuments").containsEntry("relatedDocumentCount", 0);
        Map<String, Object> metadata = JSON.readValue(sealed.getPromptExecutionMetadataJson(), MAP);
        assertThat(metadata).doesNotContainKeys("finalPromptHash", "llmUserPromptHash", "finalUserPromptHash");
    }

    @Test
    void theExecutionMetadataKeepsNoKeyOnlyTheTwelveMetricVerificationRead() throws Exception {
        Map<String, Object> promptMetadata = new HashMap<>();
        promptMetadata.put("promptVersion", "v20");
        promptMetadata.put("promptRuntimeGovernanceRuleCount", 3);
        promptMetadata.put("promptRuntimeGovernanceRuleIds", List.of("rule-1", "rule-2", "rule-3"));
        promptMetadata.put("promptFieldStateCount", 5);
        promptMetadata.put("promptFieldStateLedger", List.of(Map.of("fieldKey", "Approval", "blockingCandidate", true)));
        promptMetadata.put("promptSourceContextLedger", List.of(Map.of("fieldKey", "Approval")));
        promptMetadata.put("promptUserFieldLineageSummary", "summary");
        Map<String, Object> eventMetadata = new HashMap<>();
        eventMetadata.put("officialVerificationPinnedModelId", "pinned-model");
        eventMetadata.put("sealedEvidence.canonicalContext", CanonicalSecurityContext.builder().build());

        SealedEvidencePackage sealed = seal("req-c2-4", "user prompt", promptMetadata, List.of(), eventMetadata);

        Map<String, Object> metadata = JSON.readValue(sealed.getPromptExecutionMetadataJson(), MAP);
        assertThat(sealed.getCanonicalContextJson()).isNotNull();
        assertThat(metadata).containsEntry("promptVersion", "v20")
                .doesNotContainKeys("canonicalContextHash", "runtimeModelId", "promptFieldStateCount",
                        "promptFieldStateLedger", "promptSourceContextLedgerStoragePolicy", "promptUserFieldLineageSummary");
        assertThat(metadata.keySet()).noneMatch(key -> key.startsWith("promptRuntimeGovernance"));
    }

    private SealedEvidencePackage seal(String requestId, String userPrompt, Map<String, Object> promptMetadata,
                                       List<Document> documents, Map<String, Object> eventMetadata) {
        return seal(assembler, requestId, userPrompt, promptMetadata, documents, eventMetadata);
    }

    private SealedEvidencePackage seal(SealedEvidencePackageAssembler assembler, String requestId, String userPrompt,
                                       Map<String, Object> promptMetadata, List<Document> documents,
                                       Map<String, Object> eventMetadata) {
        return seal(assembler, requestId, userPrompt, promptMetadata, documents, eventMetadata, null);
    }

    private SealedEvidencePackage seal(SealedEvidencePackageAssembler assembler, String requestId, String userPrompt,
                                       Map<String, Object> promptMetadata, List<Document> documents,
                                       Map<String, Object> eventMetadata,
                                       List<SecurityDecisionOutputContract.Citation> reasonCodes) {
        SecurityEvent event = SecurityEvent.builder().eventId("evt-" + requestId).userId("alice").sessionId("s-1").build();
        Map<String, Object> metadata = new HashMap<>(eventMetadata);
        metadata.put("requestId", requestId);
        metadata.put("requestPath", "/api/projects/PLM-OPS/exports");
        event.setMetadata(metadata);

        PromptGenerationResult promptResult = mock(PromptGenerationResult.class);
        when(promptResult.getSystemPrompt()).thenReturn("system prompt");
        when(promptResult.getUserPrompt()).thenReturn(userPrompt);
        when(promptResult.getRawSystemPrompt()).thenReturn("system prompt");
        when(promptResult.getRawUserPrompt()).thenReturn(userPrompt);
        when(promptResult.getMetadata()).thenReturn(promptMetadata);
        SecurityDecisionContext capture = mock(SecurityDecisionContext.class);
        when(capture.getSecurityEvent()).thenReturn(event);
        when(capture.getRelatedDocuments()).thenReturn(documents);
        traceStore.capture(capture, promptResult);
        traceStore.complete(event);

        SecurityEventContext context = new SecurityEventContext(event);
        ProcessingResult result = ProcessingResult.builder().success(true).build();
        result.setAction("ALLOW");
        result.setReasonCodes(reasonCodes);
        context.addMetadata("processingResult", result);
        SealedEvidencePackage sealed = assembler.assemble(context);
        assertThat(sealed).isNotNull();
        return sealed;
    }
}

package io.contexa.contexacore.verification.inspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageAssembler;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The seal integrity check: a package as the assembler seals it matches its hashes, the prompt the model got is the
 * rendered one or the difference is recorded, and the request can be traced; a package changed after sealing is
 * pointed at.
 */
class SealIntegrityCheckTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final PromptInspector INSPECTOR = new PromptInspector(List.of(new SealIntegrityCheck(new SealedEvidencePackageIntegrity())), JSON);

    private final SealedEvidencePromptTraceStore traceStore = new SealedEvidencePromptTraceStore();
    private final SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity();
    private final SealedEvidencePackageAssembler assembler = new SealedEvidencePackageAssembler(
            JSON, new CanonicalSecurityContextSerializer(JSON), integrity, traceStore);

    /** R1b-3: the prompt hash is the render metadata's own: the same hash form, taken of the same combined prompt. */
    @Test
    void thePromptHashIsTheRenderMetadatasOwn() {
        assertThat(PromptGovernanceSupport.combinedPrompt("system", "user")).isEqualTo("system\n---\nuser");
        assertThat(SealIntegrityCheck.sha256("system\n---\nuser"))
                .isEqualTo(PromptGovernanceSupport.sha256(PromptGovernanceSupport.combinedPrompt("system", "user")))
                .startsWith("sha256:");
        assertThat(SealIntegrityCheck.sha256(null)).isEqualTo(PromptGovernanceSupport.sha256(""));
    }

    @Test
    void aPackageAsTheAssemblerSealsItKeepsItsIntegrity() {
        PromptInspectionCheckResult check = check(seal("user prompt", "user prompt", Map.of()));

        assertThat(check.findings()).isEmpty();
        // Package hash, prompts, five hashes, parity and the request the facts name (R1b-9: one trace).
        assertThat(check.matched()).isEqualTo(9);
    }

    @Test
    void aUserPromptChangedAfterSealingIsPointedAtByThePackageAndPromptHashes() {
        SealedEvidencePackage sealed = seal("user prompt", "user prompt", Map.of());
        sealed.setUserPromptText("user prompt with a line added later");

        List<PromptInspectionFinding> findings = check(sealed).findings();
        assertThat(findings).extracting(PromptInspectionFinding::sourceRef)
                .contains("sealedPackage.packageHash", "sealedPackage.promptHash", "sealedPackage.userPromptHash");
        assertThat(findings).allMatch(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH);
    }

    @Test
    void aPackageWithoutAPackageHashCannotBeVerifiedAndSaysSo() {
        SealedEvidencePackage sealed = seal("user prompt", "user prompt", Map.of());
        sealed.setPackageHash(null);

        PromptInspectionFinding finding = single(check(sealed));
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(finding.sourceRef()).isEqualTo("sealedPackage.packageHash");
    }

    @Test
    void aPromptTheModelGotOtherThanTheRenderedOneWithoutARecordedReasonIsPointedAt() {
        PromptInspectionFinding finding = single(check(seal("rendered prompt", "changed prompt", Map.of())));

        assertThat(finding.sourceRef()).isEqualTo("sealedPackage.rawUserPrompt");
        assertThat(finding.expected()).contains("same");
    }

    @Test
    void aRecordedCompressionExplainsADifferenceBetweenTheRenderedAndTheSentPrompt() {
        PromptInspectionCheckResult check = check(seal("rendered prompt", "compressed prompt",
                Map.of("promptCompressionApplied", true)));

        assertThat(check.findings()).isEmpty();
    }

    @Test
    void aPackageWithoutItsRequestIdCannotBeTracedAndIsPointedAt() {
        SealedEvidencePackage sealed = seal("user prompt", "user prompt", Map.of());
        sealed.setCorrelationId(null);
        sealed.setRequestFactsJson("{}");
        sealed.setPromptExecutionMetadataJson("{}");
        sealed.setPackageHash(integrity.computeHash(sealed));

        assertThat(check(sealed).findings()).extracting(PromptInspectionFinding::entry)
                .contains("requestId").doesNotContain("correlationId");
    }

    /** R1b-9: the trace compares: the request facts name the request the package is sealed for. */
    @Test
    void theRequestFactsOfAnotherRequestArePointedAt() {
        SealedEvidencePackage sealed = seal("user prompt", "user prompt", Map.of());
        assertThat(check(sealed).findings()).isEmpty();
        sealed.setRequestFactsJson(sealed.getRequestFactsJson().replace("\"req-1\"", "\"req-2\""));
        sealed.setPackageHash(integrity.computeHash(sealed));

        assertThat(check(sealed).findings()).filteredOn(finding -> "requestId".equals(finding.entry()))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
                    assertThat(finding.expected()).isEqualTo(sealed.getCorrelationId());
                    assertThat(finding.actual()).isEqualTo("req-2");
                });
    }

    /** R1b-9: no code writes a whitespace-only layout ledger, so it is no reason for a different prompt. */
    @Test
    void aLayoutLedgerIsNoReasonForADifferentPrompt() {
        SealedEvidencePackage sealed = seal("rendered user prompt", "user prompt", Map.of("promptCompressionLedger",
                List.of(Map.of("scopeKey", "USER_PROMPT_LAYOUT", "action", "TRIMMED",
                        "reason", "whitespace-only normalization"))));

        assertThat(check(sealed).findings()).extracting(PromptInspectionFinding::entry).containsExactly("rawUserPrompt");
    }

    /** R1b-5: a sealed source that does not read is named once and is never compared as if it were empty. */
    @Test
    void aSealedSourceThatDoesNotReadIsNamed() {
        SealedEvidencePackage sealed = seal("user prompt", "user prompt", Map.of());
        sealed.setAuthStateJson("{not json");
        sealed.setPackageHash(integrity.computeHash(sealed));

        assertThat(check(sealed).findings()).filteredOn(finding -> "authStateJson".equals(finding.entry()))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
                    assertThat(finding.sourceRef()).isEqualTo("sealedPackage.authStateJson");
                });
    }

    /**
     * W6-6 (P6-CHANGE-4): the sealed prompt is the one the decision rests on, the prompt the last model call sent; a
     * second pass that called the model again is the last call.
     */
    @Test
    void theSealedPromptIsTheOneTheLastModelCallSent() throws Exception {
        SealedEvidencePackage sealed = withStages(seal("user prompt", "user prompt", Map.of()), List.of(
                Map.of("layer", "Layer1", "userPromptHash", SealIntegrityCheck.sha256("first pass prompt")),
                Map.of("layer", "Layer2", "userPromptHash", SealIntegrityCheck.sha256("user prompt"))));

        PromptInspectionCheckResult check = check(sealed);

        assertThat(check.findings()).isEmpty();
        assertThat(check.matched()).isEqualTo(10);
    }

    @Test
    void aSealedPromptOtherThanTheLastModelCallsIsPointedAt() throws Exception {
        SealedEvidencePackage sealed = withStages(seal("user prompt", "user prompt", Map.of()), List.of(
                Map.of("layer", "Layer1", "userPromptHash", SealIntegrityCheck.sha256("user prompt")),
                Map.of("layer", "Layer2", "userPromptHash", SealIntegrityCheck.sha256("second pass prompt"))));

        PromptInspectionFinding finding = single(check(sealed));

        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.entry()).isEqualTo("modelCallStages");
        assertThat(finding.sourceRef()).isEqualTo("sealedPackage.decisionJson.modelCallStages");
        assertThat(finding.expected()).isEqualTo(SealIntegrityCheck.sha256("second pass prompt"));
        assertThat(finding.actual()).isEqualTo(SealIntegrityCheck.sha256("user prompt"));
    }

    @Test
    void aLastModelCallWithoutItsPromptHashCannotBeComparedAndSaysSo() throws Exception {
        SealedEvidencePackage sealed = withStages(seal("user prompt", "user prompt", Map.of()),
                List.of(Map.of("layer", "Layer1")));

        PromptInspectionFinding finding = single(check(sealed));

        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(finding.entry()).isEqualTo("modelCallStages");
    }

    private SealedEvidencePackage withStages(SealedEvidencePackage sealed, List<Map<String, Object>> stages)
            throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> decision = JSON.readValue(sealed.getDecisionJson(), Map.class);
        decision.put("modelCallStages", stages);
        sealed.setDecisionJson(JSON.writeValueAsString(decision));
        sealed.setPackageHash(integrity.computeHash(sealed));
        return sealed;
    }

    /** N-OUT-3: the rule the retries of the P8 N-OUT-2 host decision (N2A) broke in both layers. */
    private static final String BROKEN_RULE =
            "REASON_CODE_MISMATCH: POLICY_UNKNOWN P1 (the code does not cite PAST_RECORDS.PastRecordCounts)";

    /**
     * N-OUT-3: the decision's output retries agree with its model call stages, a stage that retried owning one, and
     * the last model call's retry is the one the single retry fields name (P8 N-OUT-2 host, N2A: the first layer's
     * truncated retry, then the second layer's corrective one). A package sealed before the retries were kept is not
     * compared.
     */
    @Test
    void retriesThatAgreeWithTheStagesAndTheSingleFieldsAreMatched() throws Exception {
        SealedEvidencePackage before = withDecision(seal("user prompt", "user prompt", Map.of()), n2aStages(),
                singleFields("REASON_CODE_MISMATCH", false));
        SealedEvidencePackage sealed = withDecision(seal("user prompt", "user prompt", Map.of()), n2aStages(),
                withRetries(singleFields("REASON_CODE_MISMATCH", false), n2aRetries()));

        assertThat(check(before).findings()).isEmpty();
        assertThat(check(before).matched()).isEqualTo(10);
        PromptInspectionCheckResult check = check(sealed);
        assertThat(check.findings()).isEmpty();
        // The ten of a package with stages, the two stages that retried and the single retry fields.
        assertThat(check.matched()).isEqualTo(13);
    }

    /** N-OUT-3: a retry other than the one its model call stage recorded is pointed at. */
    @Test
    void aRetryOtherThanItsStagesIsPointedAt() throws Exception {
        List<Map<String, Object>> retries = List.of(retry("Layer1", "OUTPUT_TRUNCATED", true, null),
                retry("Layer2", "REASON_CODE_MISMATCH", false, BROKEN_RULE));
        SealedEvidencePackage sealed = withDecision(seal("user prompt", "user prompt", Map.of()), n2aStages(),
                withRetries(singleFields("REASON_CODE_MISMATCH", false), retries));

        PromptInspectionFinding finding = single(check(sealed));

        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.entry()).isEqualTo("securityDecisionOutputRetries");
        assertThat(finding.sourceRef()).isEqualTo("sealedPackage.decisionJson.modelCallStages");
        assertThat(finding.expected()).isEqualTo("Layer1: OUTPUT_TRUNCATED, succeeded false, failure " + BROKEN_RULE);
        assertThat(finding.actual()).isEqualTo("Layer1: OUTPUT_TRUNCATED, succeeded true");
    }

    /** N-OUT-3: a retry no model call stage recorded is pointed at; a stage that did not retry owns none. */
    @Test
    void aRetryNoModelCallStageRecordedIsPointedAt() throws Exception {
        List<Map<String, Object>> stages = List.of(stage("Layer1", "first pass prompt", null, null, null),
                stage("Layer2", "user prompt", "REASON_CODE_MISMATCH", false, BROKEN_RULE));
        List<Map<String, Object>> retries = List.of(retry("Layer2", "REASON_CODE_MISMATCH", false, BROKEN_RULE),
                retry("Layer2", "PARSER_ACTION_MISSING", true, null));
        SealedEvidencePackage sealed = withDecision(seal("user prompt", "user prompt", Map.of()), stages,
                withRetries(singleFields("REASON_CODE_MISMATCH", false), retries));

        PromptInspectionFinding finding = single(check(sealed));

        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.sourceRef()).isEqualTo("sealedPackage.decisionJson.modelCallStages");
        assertThat(finding.expected()).isEqualTo("no retry");
        assertThat(finding.actual()).isEqualTo("Layer2: PARSER_ACTION_MISSING, succeeded true");
    }

    /**
     * N-OUT-3: a model call stage's retry the retries leave out is pointed at, and so are the single retry fields that
     * name the retry of the last model call the retries leave out.
     */
    @Test
    void aStagesRetryTheRetriesLeaveOutIsPointedAt() throws Exception {
        SealedEvidencePackage sealed = withDecision(seal("user prompt", "user prompt", Map.of()), n2aStages(),
                withRetries(singleFields("REASON_CODE_MISMATCH", false),
                        List.of(retry("Layer1", "OUTPUT_TRUNCATED", false, BROKEN_RULE))));

        List<PromptInspectionFinding> findings = check(sealed).findings();

        assertThat(findings).extracting(PromptInspectionFinding::sourceRef).containsExactly(
                "sealedPackage.decisionJson.modelCallStages",
                "sealedPackage.decisionJson.modelOutput.securityDecisionOutputRetryReason");
        assertThat(findings).extracting(PromptInspectionFinding::actual).containsExactly("missing", "no retry");
        assertThat(findings.get(0).expected())
                .isEqualTo("Layer2: REASON_CODE_MISMATCH, succeeded false, failure " + BROKEN_RULE);
        assertThat(findings.get(1).expected()).isEqualTo("REASON_CODE_MISMATCH, succeeded false");
    }

    /** N-OUT-3: single retry fields that name a retry other than the last model call's are pointed at. */
    @Test
    void singleRetryFieldsOtherThanTheLastModelCallsRetryArePointedAt() throws Exception {
        SealedEvidencePackage sealed = withDecision(seal("user prompt", "user prompt", Map.of()), n2aStages(),
                withRetries(singleFields("OUTPUT_TRUNCATED", false), n2aRetries()));

        PromptInspectionFinding finding = single(check(sealed));

        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
        assertThat(finding.sourceRef())
                .isEqualTo("sealedPackage.decisionJson.modelOutput.securityDecisionOutputRetryReason");
        assertThat(finding.expected()).isEqualTo("OUTPUT_TRUNCATED, succeeded false");
        assertThat(finding.actual()).isEqualTo("REASON_CODE_MISMATCH, succeeded false");
    }

    /**
     * N-OUT-3: single retry fields that name no retry are not compared: a later layer that did not call the model
     * cleared them, and the retries keep the first layer's.
     */
    @Test
    void singleRetryFieldsALaterLayerClearedAreNotCompared() throws Exception {
        SealedEvidencePackage sealed = withDecision(seal("user prompt", "user prompt", Map.of()),
                List.of(stage("Layer1", "user prompt", "OUTPUT_TRUNCATED", false, BROKEN_RULE)),
                withRetries(Map.of(), List.of(retry("Layer1", "OUTPUT_TRUNCATED", false, BROKEN_RULE))));

        PromptInspectionCheckResult check = check(sealed);

        assertThat(check.findings()).isEmpty();
        assertThat(check.matched()).isEqualTo(11);
    }

    /** N-OUT-3: the retries of a decision that recorded no model call stages cannot be compared and say so. */
    @Test
    void retriesWithoutModelCallStagesCannotBeComparedAndSaySo() throws Exception {
        SealedEvidencePackage sealed = withDecision(seal("user prompt", "user prompt", Map.of()), null,
                withRetries(singleFields("REASON_CODE_MISMATCH", false), n2aRetries()));

        PromptInspectionFinding finding = single(check(sealed));

        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(finding.entry()).isEqualTo("securityDecisionOutputRetries");
        assertThat(finding.sourceRef())
                .isEqualTo("sealedPackage.decisionJson.modelOutput.securityDecisionOutputRetries");
    }

    /** The N2A stages: the first layer's truncated retry and the second layer's corrective one, both failed. */
    private static List<Map<String, Object>> n2aStages() {
        return List.of(stage("Layer1", "first pass prompt", "OUTPUT_TRUNCATED", false, BROKEN_RULE),
                stage("Layer2", "user prompt", "REASON_CODE_MISMATCH", false, BROKEN_RULE));
    }

    private static List<Map<String, Object>> n2aRetries() {
        return List.of(retry("Layer1", "OUTPUT_TRUNCATED", false, BROKEN_RULE),
                retry("Layer2", "REASON_CODE_MISMATCH", false, BROKEN_RULE));
    }

    /** A model call stage as the event records it; one without a reason did not retry. */
    private static Map<String, Object> stage(String layer, String prompt, String reason, Boolean succeeded,
                                             String failureReason) {
        Map<String, Object> stage = new LinkedHashMap<>();
        stage.put("layer", layer);
        stage.put("userPromptHash", SealIntegrityCheck.sha256(prompt));
        if (reason != null) {
            stage.put("securityDecisionOutputRetryAttempted", true);
            stage.put("securityDecisionOutputRetryReason", reason);
            stage.put("securityDecisionOutputRetrySucceeded", succeeded);
            if (failureReason != null) {
                stage.put("securityDecisionOutputRetryFailureReason", failureReason);
            }
        }
        return stage;
    }

    private static Map<String, Object> retry(String layer, String reason, boolean succeeded, String failureReason) {
        Map<String, Object> retry = new LinkedHashMap<>();
        retry.put("layer", layer);
        retry.put("reason", reason);
        retry.put("succeeded", succeeded);
        if (failureReason != null) {
            retry.put("failureReason", failureReason);
        }
        return retry;
    }

    private static Map<String, Object> singleFields(String reason, boolean succeeded) {
        Map<String, Object> modelOutput = new LinkedHashMap<>();
        modelOutput.put("securityDecisionOutputRetryAttempted", true);
        modelOutput.put("securityDecisionOutputRetryReason", reason);
        modelOutput.put("securityDecisionOutputRetrySucceeded", succeeded);
        return modelOutput;
    }

    private static Map<String, Object> withRetries(Map<String, Object> modelOutput, List<Map<String, Object>> retries) {
        Map<String, Object> withList = new LinkedHashMap<>(modelOutput);
        withList.put(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES, retries);
        return withList;
    }

    /** The package with the decision's model call stages (none when null) and model output, sealed again. */
    private SealedEvidencePackage withDecision(SealedEvidencePackage sealed, List<Map<String, Object>> stages,
                                               Map<String, Object> modelOutput) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> decision = JSON.readValue(sealed.getDecisionJson(), Map.class);
        if (stages != null) {
            decision.put("modelCallStages", stages);
        }
        decision.put("modelOutput", modelOutput);
        sealed.setDecisionJson(JSON.writeValueAsString(decision));
        sealed.setPackageHash(integrity.computeHash(sealed));
        return sealed;
    }

    @Test
    void theCheckRunsOnEveryLayout() {
        assertThat(new SealIntegrityCheck(new SealedEvidencePackageIntegrity()).dictionaryPromptOnly()).isFalse();
    }

    private static PromptInspectionCheckResult check(SealedEvidencePackage sealed) {
        PromptInspectionResult result = INSPECTOR.inspect(sealed);
        assertThat(result.checks()).hasSize(1);
        assertThat(result.checks().get(0).checkCode()).isEqualTo(SealIntegrityCheck.CODE);
        return result.checks().get(0);
    }

    private static PromptInspectionFinding single(PromptInspectionCheckResult check) {
        assertThat(check.findings()).hasSize(1);
        return check.findings().get(0);
    }

    private SealedEvidencePackage seal(String rawUserPrompt, String userPrompt, Map<String, Object> promptMetadata) {
        SecurityEvent event = SecurityEvent.builder().eventId("evt-1").userId("alice").sessionId("s-1").build();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("requestId", "req-1");
        metadata.put("requestPath", "/api/orders");
        event.setMetadata(metadata);

        PromptGenerationResult promptResult = mock(PromptGenerationResult.class);
        when(promptResult.getSystemPrompt()).thenReturn("system prompt");
        when(promptResult.getUserPrompt()).thenReturn(userPrompt);
        when(promptResult.getRawSystemPrompt()).thenReturn("system prompt");
        when(promptResult.getRawUserPrompt()).thenReturn(rawUserPrompt);
        Map<String, Object> withHash = new HashMap<>(promptMetadata);
        withHash.put("promptHash", SealIntegrityCheck.sha256("system prompt\n---\n" + userPrompt));
        when(promptResult.getMetadata()).thenReturn(withHash);
        SecurityDecisionContext capture = mock(SecurityDecisionContext.class);
        when(capture.getSecurityEvent()).thenReturn(event);
        when(capture.getRelatedDocuments()).thenReturn(List.of());
        event.addMetadata("promptHash", SealIntegrityCheck.sha256("system prompt\n---\n" + userPrompt));
        traceStore.capture(capture, promptResult);
        traceStore.complete(event);

        SecurityEventContext context = new SecurityEventContext(event);
        ProcessingResult result = ProcessingResult.builder().success(true).build();
        result.setAction("ALLOW");
        context.addMetadata("processingResult", result);
        SealedEvidencePackage sealed = assembler.assemble(context);
        assertThat(sealed).isNotNull();
        return sealed;
    }
}

package io.contexa.contexacore.verification.inspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageAssembler;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
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
    private static final PromptInspector INSPECTOR = new PromptInspector(List.of(new SealIntegrityCheck()), JSON);

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

    @Test
    void theCheckRunsOnEveryLayout() {
        assertThat(new SealIntegrityCheck().dictionaryPromptOnly()).isFalse();
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

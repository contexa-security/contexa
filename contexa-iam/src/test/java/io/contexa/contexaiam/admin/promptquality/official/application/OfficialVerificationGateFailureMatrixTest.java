package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.adjudication.ScorecardCheckResult;
import io.contexa.contexacore.verification.adjudication.ScorecardResult;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.replay.DeterministicReplayResult;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationEventItemView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationGateCode;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationVerdict;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceGateResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeGovernanceDescriptorVerificationResult;
import io.contexa.contexaiam.admin.promptquality.official.common.DefaultPromptQualityMessageResolver;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.StaticMessageSource;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationGateFailureMatrixTest {

    private final OfficialVerificationVerdictFactory verdictFactory = new OfficialVerificationVerdictFactory();
    private final DefaultPromptQualityMessageResolver messageResolver = new DefaultPromptQualityMessageResolver(
            new StaticMessageSource());
    private final DefaultPromptQualityRuntimeCertificationPolicy policy =
            new DefaultPromptQualityRuntimeCertificationPolicy(
                    new ObjectMapper(),
                    (evidencePackage, metadata) -> RuntimeGovernanceDescriptorVerificationResult.empty(),
                    messageResolver);

    @Test
    void integrityFailureIsIneligible() {
        assertIneligible(evaluate(policy, packageWith(true, "raw-system", "raw-user", "system", "user", "prompt-hash"),
                false, passingScorecard(), passingReplay("prompt-hash"), passingMetrics()),
                passedConsistency(), OfficialVerificationGateCode.EVIDENCE_INTEGRITY);
    }

    @Test
    void unsealedEvidenceIsIneligible() {
        assertIneligible(evaluate(policy, packageWith(false, "raw-system", "raw-user", "system", "user", "prompt-hash"),
                true, passingScorecard(), passingReplay("prompt-hash"), passingMetrics()),
                passedConsistency(), OfficialVerificationGateCode.SEALED_EVIDENCE);
    }

    @Test
    void missingRawPromptsAreIneligible() {
        RuntimeEvidenceGateResult result = evaluate(policy,
                packageWith(true, "", "", "system", "user", "prompt-hash"),
                true, passingScorecard(), passingReplay("prompt-hash"), passingMetrics());

        assertIneligible(result, passedConsistency(), OfficialVerificationGateCode.RAW_SYSTEM_PROMPT);
        assertThat(verdict(result, passedConsistency()).failures())
                .extracting(failure -> failure.gateCode())
                .contains(OfficialVerificationGateCode.RAW_USER_PROMPT);
    }

    @Test
    void missingFinalPromptIsIneligible() {
        assertIneligible(evaluate(policy, packageWith(true, "raw-system", "raw-user", "", "", "prompt-hash"),
                true, passingScorecard(), passingReplay("prompt-hash"), passingMetrics()),
                passedConsistency(), OfficialVerificationGateCode.FINAL_LLM_PROMPT);
    }

    @Test
    void replayHashMismatchIsIneligible() {
        assertIneligible(evaluate(policy, validPackage(), true, passingScorecard(), passingReplay("other-hash"), passingMetrics()),
                passedConsistency(), OfficialVerificationGateCode.REPLAY_HASH);
    }

    @Test
    void partialReplayFailureIsIneligible() {
        DeterministicReplayResult replay = new DeterministicReplayResult(
                "sep-matrix", true, "prompt-hash", "prompt-hash", 2, 1,
                List.of("one replay check failed"), List.of(), List.of(), Instant.now());

        assertIneligible(evaluate(policy, validPackage(), true, passingScorecard(), replay, passingMetrics()),
                passedConsistency(), OfficialVerificationGateCode.DETERMINISTIC_REPLAY);
    }

    @Test
    void scorecardBelowNinetyFivePercentIsIneligible() {
        ScorecardResult scorecard = new ScorecardResult("scorecard", 20, 18, 90.0d, List.of());

        assertIneligible(evaluate(policy, validPackage(), true, scorecard, passingReplay("prompt-hash"), passingMetrics()),
                passedConsistency(), OfficialVerificationGateCode.PROMPT_SCORECARD);
    }

    @Test
    void governanceDescriptorFailureIsIneligible() {
        DefaultPromptQualityRuntimeCertificationPolicy governedPolicy =
                new DefaultPromptQualityRuntimeCertificationPolicy(new ObjectMapper(), (evidencePackage, metadata) ->
                        new RuntimeGovernanceDescriptorVerificationResult(
                                false,
                                List.of(new RuntimeEvidenceCheckResult(
                                        "MTR", "GOVERNANCE_RELEASE", "approved", "draft", false, "promptGovernance")),
                                List.of("Prompt governance release is not approved."),
                                List.of("Approve the prompt governance release.")),
                        messageResolver);

        assertIneligible(evaluate(governedPolicy, validPackage(), true, passingScorecard(),
                        passingReplay("prompt-hash"), passingMetrics()),
                passedConsistency(), OfficialVerificationGateCode.GOVERNANCE_DESCRIPTOR);
    }

    @Test
    void promptConsistencyFailureIsIneligible() {
        RuntimeEvidencePromptConsistencyResult consistency = new RuntimeEvidencePromptConsistencyResult(
                "BLOCKED",
                "Blocked",
                false,
                true,
                List.of(new RuntimeEvidenceCheckResult(
                        "PFR", "FINAL_PROMPT_CONSISTENCY", "consistent", "mismatch", false, "promptConsistency")),
                List.of("Final prompt consistency failed."),
                List.of("Capture new sealed prompt evidence."));

        assertIneligible(evaluate(policy, validPackage(), true, passingScorecard(),
                        passingReplay("prompt-hash"), passingMetrics()),
                consistency, OfficialVerificationGateCode.PROMPT_CONSISTENCY);
    }

    @Test
    void missingOrFailedRequiredMetricIsIneligible() {
        List<OfficialVerificationRunView> missing = passingMetrics().subList(0, 11);
        RuntimeEvidenceGateResult missingResult = evaluate(
                policy, validPackage(), true, passingScorecard(), passingReplay("prompt-hash"), missing);
        assertIneligible(missingResult, passedConsistency(), OfficialVerificationGateCode.REQUIRED_METRICS);

        List<OfficialVerificationRunView> failed = List.of(
                new StubRunView("EIR", "FAILED"),
                new StubRunView("CCR", "SUCCESS"),
                new StubRunView("CCSR", "SUCCESS"),
                new StubRunView("PFR", "SUCCESS"),
                new StubRunView("MTR", "SUCCESS"),
                new StubRunView("CoR", "SUCCESS"),
                new StubRunView("RAP", "SUCCESS"),
                new StubRunView("RPI", "SUCCESS"),
                new StubRunView("BMA", "SUCCESS"),
                new StubRunView("USNS", "SUCCESS"),
                new StubRunView("BSR", "SUCCESS"),
                new StubRunView("PRE", "SUCCESS"));
        RuntimeEvidenceGateResult failedResult = evaluate(
                policy, validPackage(), true, passingScorecard(), passingReplay("prompt-hash"), failed);
        assertIneligible(failedResult, passedConsistency(), OfficialVerificationGateCode.METRIC_RESULTS);
    }

    @Test
    void allRequiredGatesProduceOneEligibleVerdict() {
        RuntimeEvidenceGateResult result = evaluate(
                policy, validPackage(), true, passingScorecard(), passingReplay("prompt-hash"), passingMetrics());

        OfficialVerificationVerdict verdict = verdict(result, passedConsistency());

        assertThat(verdict.status()).isEqualTo(OfficialVerificationVerdict.Status.ELIGIBLE);
        assertThat(verdict.eligible()).isTrue();
        assertThat(verdict.packageId()).isEqualTo("sep-matrix");
        assertThat(verdict.aggregateRunId()).isEqualTo("agg-matrix");
        assertThat(verdict.failures()).isEmpty();
        assertThat(verdict.gates()).isNotEmpty().allMatch(gate -> gate.passed());
    }

    private void assertIneligible(
            RuntimeEvidenceGateResult result,
            RuntimeEvidencePromptConsistencyResult consistency,
            OfficialVerificationGateCode expectedGateCode) {
        OfficialVerificationVerdict verdict = verdict(result, consistency);
        assertThat(verdict.status()).isEqualTo(OfficialVerificationVerdict.Status.INELIGIBLE);
        assertThat(verdict.failures())
                .extracting(failure -> failure.gateCode())
                .contains(expectedGateCode);
        assertThat(verdict.failures())
                .allSatisfy(failure -> {
                    assertThat(failure.checkCode()).isNotBlank();
                    assertThat(failure.source()).isNotBlank();
                    assertThat(failure.expectedValue()).isNotBlank();
                    assertThat(failure.actualValue()).isNotBlank();
                    assertThat(failure.messageKey()).isEqualTo(failure.gateCode().messageKey());
                });
    }

    private RuntimeEvidenceGateResult evaluate(
            DefaultPromptQualityRuntimeCertificationPolicy evaluatedPolicy,
            SealedEvidencePackage evidencePackage,
            boolean integrityValid,
            ScorecardResult scorecard,
            DeterministicReplayResult replay,
            List<? extends OfficialVerificationRunView> metrics) {
        return evaluatedPolicy.evaluate(evidencePackage, integrityValid, scorecard, replay, metrics);
    }

    private OfficialVerificationVerdict verdict(
            RuntimeEvidenceGateResult result,
            RuntimeEvidencePromptConsistencyResult consistency) {
        return verdictFactory.create(
                "sep-matrix",
                "agg-matrix",
                "2026-07-15 00:00:00",
                result,
                consistency);
    }

    private RuntimeEvidencePromptConsistencyResult passedConsistency() {
        return new RuntimeEvidencePromptConsistencyResult(
                "PASSED", "Passed", true, false, List.of(), List.of(), List.of());
    }

    private SealedEvidencePackage validPackage() {
        return packageWith(true, "raw-system", "raw-user", "system", "user", "prompt-hash");
    }

    private SealedEvidencePackage packageWith(
            boolean sealed,
            String rawSystemPrompt,
            String rawUserPrompt,
            String systemPrompt,
            String userPrompt,
            String promptHash) {
        return SealedEvidencePackage.builder()
                .packageId("sep-matrix")
                .correlationId("corr-matrix")
                .tenantId("default")
                .userId("user-matrix")
                .capturedAt(Instant.now())
                .requestFactsJson("{\"requestPath\":\"/api/orders\",\"httpMethod\":\"GET\",\"resourceId\":\"orders.read\"}")
                .authStateJson("{}")
                .canonicalContextJson("{}")
                .baselineSnapshotJson("{}")
                .ragResultsJson("{}")
                .rawSystemPrompt(rawSystemPrompt)
                .rawUserPrompt(rawUserPrompt)
                .systemPromptText(systemPrompt)
                .userPromptText(userPrompt)
                .promptHash(promptHash)
                .promptExecutionMetadataJson("{}")
                .promptEvidenceManifestJson("{}")
                .decisionJson("{\"action\":\"ALLOW\",\"confidence\":0.99}")
                .packageHash("package-hash")
                .schemaVersion(1)
                .sealed(sealed)
                .build();
    }

    private ScorecardResult passingScorecard() {
        return ScorecardResult.of("scorecard", List.of(
                new ScorecardCheckResult("structure", true, "ok"),
                new ScorecardCheckResult("prompt", true, "ok")));
    }

    private DeterministicReplayResult passingReplay(String originalPromptHash) {
        return new DeterministicReplayResult(
                "sep-matrix", true, originalPromptHash, originalPromptHash,
                2, 2, List.of(), List.of(), List.of(), Instant.now());
    }

    private List<OfficialVerificationRunView> passingMetrics() {
        return List.of("EIR", "CCR", "CCSR", "PFR", "MTR", "CoR", "RAP", "RPI", "BMA", "USNS", "BSR", "PRE")
                .stream()
                .map(code -> new StubRunView(code, "SUCCESS"))
                .map(OfficialVerificationRunView.class::cast)
                .toList();
    }

    private record StubRunView(String endpointKey, String state) implements OfficialVerificationRunView {
        @Override public String runId() { return "run-" + endpointKey; }
        @Override public int round() { return 1; }
        @Override public String endpointLabel() { return endpointKey; }
        @Override public String requestId() { return "request-1"; }
        @Override public double score() { return 100.0d; }
        @Override public int passedChecks() { return 1; }
        @Override public int totalChecks() { return 1; }
        @Override public Long processingTimeMs() { return 1L; }
        @Override public String stateTone() { return "success"; }
        @Override public String message() { return "passed"; }
        @Override public String startedAt() { return "2026-07-15 00:00:00"; }
        @Override public String completedAt() { return "2026-07-15 00:00:01"; }
        @Override public List<? extends OfficialVerificationCheckResultView> checks() { return List.of(); }
        @Override public Map<String, String> requestFacts() { return Map.of(); }
        @Override public Map<String, String> eventFacts() { return Map.of(); }
        @Override public Map<String, String> promptFacts() { return Map.of(); }
        @Override public Map<String, String> analysisFacts() { return Map.of(); }
        @Override public List<? extends OfficialVerificationEventItemView> events() { return List.of(); }
        @Override public Map<String, Object> rawEvidence() { return Map.of(); }
    }
}

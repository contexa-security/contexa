package io.contexa.contexacore.verification.runtime.sealed;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.metric.OfficialMetricCheckObservation;
import io.contexa.contexacore.verification.metric.OfficialMetricEvaluationResult;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SealedEvidenceOfficialRunViewFactoryTest {

    @Test
    void sanitizesNullMetricStateAndFactValuesBeforeLedgerStorage() {
        SealedEvidencePackage evidencePackage = SealedEvidencePackage.builder()
                .packageId("sep-core-001")
                .correlationId("correlation-core-001")
                .capturedAt(Instant.parse("2026-07-12T00:00:00Z"))
                .userPromptHash("user-prompt-hash")
                .packageHash("package-hash")
                .build();
        OfficialVerificationMetricDefinition metric = new OfficialVerificationMetricDefinition(
                "BMA", "Baseline Maturity Accuracy", "RAG_AND_BASELINE", "Baseline quality",
                true, 95.0d, true);
        OfficialMetricEvaluationResult result = new OfficialMetricEvaluationResult(
                "BMA", 0.0d, 0, 1, null,
                List.of(new OfficialMetricCheckObservation(
                        "BMA_BASELINE_MATURITY", "Baseline maturity", "present", "missing", false,
                        "finalUserPrompt.personalWorkProfile.BaselineProfileStatus", "BLOCKING",
                        "PROMPT_QUALITY_CONTRACT_FAILED", "Baseline producer",
                        "Baseline maturity is missing from the final prompt.",
                        "Regenerate the final prompt with baseline maturity.",
                        "The next inspection must include baseline maturity.")));
        Map<String, String> requestFacts = new LinkedHashMap<>();
        requestFacts.put("requestId", "req-core-001");
        requestFacts.put("emptySlot", null);
        Map<String, String> promptFacts = new LinkedHashMap<>();
        promptFacts.put("contextHash", null);
        promptFacts.put("userPromptHash", evidencePackage.getUserPromptHash());

        OfficialVerificationMessageResolver messages = (key, args) -> key;
        SealedEvidenceOfficialRunView view = new SealedEvidenceOfficialRunViewFactory(messages).create(
                null, metric, evidencePackage, result, requestFacts, promptFacts,
                "/api/protected", true, null, null, Duration.ZERO);

        assertThat(view.runId()).isEqualTo("official-run-bma");
        assertThat(view.state()).isEqualTo("missing");
        assertThat(view.checks()).hasSize(1);
        assertThat(view.requestFacts()).containsEntry("requestId", "req-core-001");
        assertThat(view.requestFacts()).doesNotContainKey("emptySlot");
        assertThat(view.promptFacts()).containsEntry("userPromptHash", "user-prompt-hash");
        assertThat(view.promptFacts()).doesNotContainKey("contextHash");
        assertThat(view.rawEvidence()).doesNotContainKey("aggregateRunId");
    }
}

package io.contexa.contexacore.verification.runtime.request;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationPfrEvidenceFactoryTest {

    @Test
    void completePromptTelemetryKeepsAllExistingPfrChecksPassing() {
        OfficialVerificationPfrEvidenceFactory factory = new OfficialVerificationPfrEvidenceFactory();
        Map<String, Object> decisionMetadata = Map.of(
                "promptVersion", "v1",
                "promptHash", "prompt-hash",
                "templateKey", "template-1");
        Map<String, Object> telemetry = Map.ofEntries(
                Map.entry("promptVersion", "v1"),
                Map.entry("promptHash", "prompt-hash"),
                Map.entry("systemPromptHash", "system-hash"),
                Map.entry("userPromptHash", "user-hash"),
                Map.entry("templateKey", "template-1"),
                Map.entry("promptSectionSet", List.of("SYSTEM", "USER")),
                Map.entry("omittedSections", List.of()),
                Map.entry("omissionLedger", List.of()),
                Map.entry("promptOmissionCount", 0),
                Map.entry("promptEvidenceCompleteness", "COMPLETE"),
                Map.entry("systemPromptLength", 10),
                Map.entry("userPromptLength", 20),
                Map.entry("totalPromptLength", 30),
                Map.entry("rawSystemPromptLength", 10),
                Map.entry("rawUserPromptLength", 20),
                Map.entry("rawTotalPromptLength", 30),
                Map.entry("llmSystemPromptLength", 10),
                Map.entry("llmUserPromptLength", 20),
                Map.entry("llmTotalPromptLength", 30),
                Map.entry("promptTokenEstimator", "cl100k"),
                Map.entry("estimatedSystemTokens", 3),
                Map.entry("estimatedUserTokens", 5),
                Map.entry("estimatedTotalTokens", 8));

        var checks = factory.buildChecks(decisionMetadata, telemetry, Map.of(), Map.of(), Map.of());

        assertThat(checks).hasSize(18).allMatch(OfficialVerificationPfrExecutionService.PfrCheckResult::pass);
    }
}
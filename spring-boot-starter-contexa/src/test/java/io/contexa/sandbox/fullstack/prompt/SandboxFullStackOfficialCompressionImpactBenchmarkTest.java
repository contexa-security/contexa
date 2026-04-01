package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfSystemProperty(named = "sandbox.decision.real-llm", matches = "true")
class SandboxFullStackOfficialCompressionImpactBenchmarkTest extends AbstractSandboxFullStackRealLlmDecisionBenchmarkTest {

    @Test
    @DisplayName("실제 LLM 기준 compression-impact 실행은 프로필별 decision evidence와 통합 비교 산출물을 함께 생성해야 한다")
    void shouldProduceOfficialCompressionImpactArtifactsFromRealLlmReplayComparison() throws Exception {
        SandboxPromptCompressionImpactBenchmarkResult result = executeOfficialCompressionImpactSuite();

        assertThat(result.baseline().decisionRunResults()).isNotEmpty();
        assertThat(result.candidate().decisionRunResults()).isNotEmpty();

        Path reportDirectory = REPORT_DIRECTORY.resolve("compression-impact");
        assertThat(Files.exists(reportDirectory.resolve("compression-impact-summary.json"))).isTrue();
        assertThat(Files.exists(reportDirectory.resolve("compression-impact-summary.html"))).isTrue();
        assertThat(Files.exists(reportDirectory.resolve("compression-impact-profiles.ndjson"))).isTrue();
        assertThat(Files.exists(reportDirectory.resolve("compression-impact-runs.ndjson"))).isTrue();
        assertThat(Files.exists(reportDirectory.resolve("compression-impact-rounds.ndjson"))).isTrue();
        assertThat(Files.exists(reportDirectory.resolve("compression-performance-summary.json"))).isTrue();
        assertThat(Files.exists(reportDirectory.resolve("compression-performance-summary.html"))).isTrue();
        assertThat(Files.exists(reportDirectory.resolve("compression-performance-rounds.ndjson"))).isTrue();
        assertThat(Files.exists(reportDirectory.resolve("profile-comparison-summary.json"))).isTrue();
        assertThat(Files.exists(reportDirectory.resolve("profile-comparison-summary.html"))).isTrue();
        assertThat(Files.exists(reportDirectory.resolve("profile-comparison-rounds.ndjson"))).isTrue();

        String baselineProfileDirectory =
                SandboxPromptCompressionImpactBenchmarkRunner.profileDirectoryName(result.baseline().budgetProfile());
        String candidateProfileDirectory =
                SandboxPromptCompressionImpactBenchmarkRunner.profileDirectoryName(result.candidate().budgetProfile());
        assertThat(Files.exists(reportDirectory.resolve(baselineProfileDirectory).resolve("decision-summary.html"))).isTrue();
        assertThat(Files.exists(reportDirectory.resolve(candidateProfileDirectory).resolve("decision-summary.html"))).isTrue();
        assertThat(Files.exists(reportDirectory.resolve(candidateProfileDirectory).resolve("compression").resolve("compression-summary.json"))).isTrue();

        JsonNode summary = objectMapper.readTree(reportDirectory.resolve("compression-impact-summary.json").toFile());
        JsonNode baseline = summary.path("baseline");
        JsonNode candidate = summary.path("candidate");
        JsonNode delta = summary.path("delta");

        assertThat(candidate.path("averageLlmTotalPromptLength").asDouble())
                .isLessThan(baseline.path("averageLlmTotalPromptLength").asDouble());
        assertThat(candidate.path("averageEstimatedVendorCostLlm").asDouble())
                .isLessThanOrEqualTo(baseline.path("averageEstimatedVendorCostLlm").asDouble());
        assertThat(candidate.path("cdcMean").asDouble()).isGreaterThan(0.0d);
        assertThat(candidate.path("eraMean").asDouble()).isGreaterThan(0.0d);
        assertThat(candidate.path("suhrMean").asDouble()).isGreaterThan(0.0d);
        assertThat(delta.path("compressionGainPass").asBoolean()).isTrue();
        assertThat(delta.path("costGainPass").asBoolean()).isTrue();
        assertThat(delta.path("decisionRegressionPass").asBoolean()).isTrue();
    }
}

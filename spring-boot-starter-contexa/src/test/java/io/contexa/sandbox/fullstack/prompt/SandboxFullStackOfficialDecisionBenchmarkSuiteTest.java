package io.contexa.sandbox.fullstack.prompt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.nio.file.Files;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfSystemProperty(named = "sandbox.decision.real-llm", matches = "true")
class SandboxFullStackOfficialDecisionBenchmarkSuiteTest extends AbstractSandboxFullStackRealLlmDecisionBenchmarkTest {

    @Test
    @DisplayName("실제 LLM 공식 decision benchmark는 단일 replay 배치에서 CDC ERA SUHR 전체 산출물을 생성해야 한다")
    void shouldProduceOfficialDecisionSuiteArtifactsFromSingleReplayBatch() throws Exception {
        List<SandboxDecisionBenchmarkRunResult> runResults = executeOfficialSuite();

        assertThat(runResults).isNotEmpty();
        for (SandboxDecisionBenchmarkRunResult runResult : runResults) {
            for (SandboxDecisionMetric metric : SandboxDecisionMetric.values()) {
                assertThat(runResult.metrics().get(metric.key()))
                        .as("%s metric must satisfy official threshold", metric.key())
                        .isGreaterThanOrEqualTo(metric.successThreshold());
            }
        }

        assertThat(Files.exists(REPORT_DIRECTORY.resolve("decision-summary.json"))).isTrue();
        assertThat(Files.exists(REPORT_DIRECTORY.resolve("decision-summary.html"))).isTrue();
        assertThat(Files.exists(REPORT_DIRECTORY.resolve("decision-index.html"))).isTrue();
        assertThat(Files.exists(REPORT_DIRECTORY.resolve("CDC").resolve("CDC-summary.html"))).isTrue();
        assertThat(Files.exists(REPORT_DIRECTORY.resolve("ERA").resolve("ERA-summary.html"))).isTrue();
        assertThat(Files.exists(REPORT_DIRECTORY.resolve("SUHR").resolve("SUHR-summary.html"))).isTrue();
    }
}

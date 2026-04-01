package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxOfficialBenchmarkSubmissionReportWriterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("official submission writer는 prompt/decision summary를 결합해 14지표 제출 요약을 생성해야 한다")
    void shouldWriteIntegratedOfficialSubmissionSummary() throws Exception {
        Files.writeString(tempDir.resolve("summary.json"), """
                {
                  "benchmarkVersion": "SANDBOX_FULLSTACK_PROMPT_BENCHMARK_V2",
                  "generatedAt": "2026-03-31T10:00:00Z",
                  "metricSummaries": {
                    "Event Integrity Rate": {
                      "mean": 100.0,
                      "failureRatePercent": 0.0,
                      "ci95Low": 100.0,
                      "ci95High": 100.0,
                      "stabilityClass": "STABLE"
                    },
                    "Prompt Fidelity Rate": {
                      "mean": 99.0,
                      "failureRatePercent": 0.0,
                      "ci95Low": 98.0,
                      "ci95High": 100.0,
                      "stabilityClass": "STABLE"
                    }
                  }
                }
                """);
        Files.writeString(tempDir.resolve("decision-summary.json"), """
                {
                  "generatedAt": "2026-03-31T11:00:00Z",
                  "boundaryMode": "REAL_LLM",
                  "modelId": "qwen3:8b",
                  "goldVersion": "2026.03.31-d1.0",
                  "adjudicationVersion": "2026.03.31-a1.0",
                  "metrics": {
                    "Context-to-Decision Calibration": {
                      "mean": 98.0,
                      "failureRatePercent": 0.0,
                      "ci95Low": 97.0,
                      "ci95High": 99.0,
                      "stabilityClass": "STABLE"
                    },
                    "Evidence-Reason Alignment": {
                      "mean": 97.0,
                      "failureRatePercent": 0.0,
                      "ci95Low": 96.0,
                      "ci95High": 98.0,
                      "stabilityClass": "STABLE"
                    },
                    "Safe-Uncertainty Handling Rate": {
                      "mean": 96.0,
                      "failureRatePercent": 0.0,
                      "ci95Low": 95.0,
                      "ci95High": 97.0,
                      "stabilityClass": "STABLE"
                    }
                  }
                }
                """);

        new SandboxOfficialBenchmarkSubmissionReportWriter(objectMapper, tempDir).write();

        assertThat(tempDir.resolve("official-submission-summary.json")).exists();
        assertThat(tempDir.resolve("official-submission-summary.md")).exists();
        assertThat(tempDir.resolve("official-submission-summary.html")).exists();

        String summaryJson = Files.readString(tempDir.resolve("official-submission-summary.json"));
        String summaryHtml = Files.readString(tempDir.resolve("official-submission-summary.html"));
        assertThat(summaryJson)
                .contains("CONTEXA_OFFICIAL_14_METRIC_SUBMISSION")
                .contains("Context-to-Decision Calibration")
                .contains("Prompt Fidelity Rate")
                .contains("\"officialMetricPassState\" : \"INCOMPLETE\"")
                .contains("failingImplementedOfficialMetrics");
        assertThat(summaryHtml)
                .contains("prompt summary")
                .contains("decision summary")
                .contains("decision index");
    }
}

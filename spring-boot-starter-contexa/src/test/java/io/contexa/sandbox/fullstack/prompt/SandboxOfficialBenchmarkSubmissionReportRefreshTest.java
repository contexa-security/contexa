package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfSystemProperty(named = "sandbox.official.submission.refresh", matches = "true")
class SandboxOfficialBenchmarkSubmissionReportRefreshTest {

    @Test
    @DisplayName("실제 산출된 prompt summary와 decision summary를 결합해 최종 제출용 통합 보고서를 생성해야 한다")
    void shouldRefreshIntegratedOfficialSubmissionSummaryFromActualArtifacts() {
        Path reportDirectory = Path.of("build", "reports", "sandbox-fullstack-benchmark");
        new SandboxOfficialBenchmarkSubmissionReportWriter(new ObjectMapper(), reportDirectory).write();

        assertThat(reportDirectory.resolve("official-submission-summary.json")).exists();
        assertThat(reportDirectory.resolve("official-submission-summary.md")).exists();
        assertThat(reportDirectory.resolve("official-submission-summary.html")).exists();
    }
}

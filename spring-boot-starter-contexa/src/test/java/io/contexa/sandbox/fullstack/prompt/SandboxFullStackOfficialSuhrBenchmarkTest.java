package io.contexa.sandbox.fullstack.prompt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfSystemProperty(named = "sandbox.decision.real-llm", matches = "true")
@EnabledIfSystemProperty(named = "sandbox.decision.single-metric", matches = "true")
class SandboxFullStackOfficialSuhrBenchmarkTest extends AbstractSandboxFullStackRealLlmDecisionBenchmarkTest {

    @Test
    @DisplayName("실제 LLM uncertainty replay로 SUHR 제출 산출물을 생성해야 한다")
    void shouldProduceOfficialSuhrArtifacts() {
        List<SandboxDecisionBenchmarkRunResult> runResults = executeMetric(SandboxDecisionMetric.SUHR);
        assertThat(runResults).isNotEmpty();
        for (SandboxDecisionBenchmarkRunResult runResult : runResults) {
            assertThat(runResult.metrics().get(SandboxDecisionMetric.SUHR.key()))
                    .isGreaterThanOrEqualTo(SandboxDecisionMetric.SUHR.successThreshold());
        }
    }
}

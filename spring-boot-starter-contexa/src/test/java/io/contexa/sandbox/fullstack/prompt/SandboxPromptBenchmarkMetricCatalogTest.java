package io.contexa.sandbox.fullstack.prompt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxPromptBenchmarkMetricCatalogTest {

    @Test
    @DisplayName("공식 metric catalog는 14개 목표 지표와 현재 구현/보류 경계를 명확히 고정해야 한다")
    void shouldExposeOfficialMetricCatalogWithImplementedAndPendingBoundaries() {
        // 공식 benchmark는 매번 지표 이름이 바뀌는 느슨한 목록이어서는 안 된다.
        // 지금 단계에서 구현된 컨텍스트/프롬프트 지표와, 아직 LLM 책임 구간이라 보류된 지표를 명확히 분리해야
        // 고객과 심사기관에게 어떤 수치가 현재 실측치인지 설명할 수 있다.
        assertThat(SandboxPromptBenchmarkMetricCatalog.officialMetrics()).hasSize(14);
        assertThat(SandboxPromptBenchmarkMetricCatalog.implementedOfficialMetrics())
                .extracting(SandboxPromptBenchmarkMetricCatalog::metricName)
                .contains(
                        "Event Integrity Rate",
                        "Prompt Fidelity Rate",
                        "User-Specific Novelty Sensitivity",
                        "Behavioral Surprise Resolution");
        assertThat(SandboxPromptBenchmarkMetricCatalog.pendingOfficialMetrics())
                .extracting(SandboxPromptBenchmarkMetricCatalog::metricName)
                .containsExactly(
                        "Context-to-Decision Calibration",
                        "Evidence-Reason Alignment",
                        "Safe-Uncertainty Handling Rate");
    }
}

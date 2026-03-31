package io.contexa.sandbox.fullstack.prompt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxPromptDefectClassifierTest {

    @Test
    @DisplayName("필드 누락과 섹션 불일치는 구현 결함으로 분류되어야 한다")
    void shouldClassifyMissingPromptFactsAsImplementationDefects() {
        SandboxPromptQualityScorecard scorecard = SandboxPromptQualityScorecard.of(
                "1차 full-stack prompt 점검",
                List.of(new SandboxPromptQualityScorecard.CheckResult(
                        "userPrompt는 BRIDGE RESOLUTION CONTEXT 섹션을 포함해야 한다",
                        false,
                        "userPrompt missing bridge section")));

        List<SandboxPromptDefectFinding> findings = SandboxPromptDefectClassifier.classifyScorecardFailures(
                "benchmark-run-1",
                "alice@example.com",
                scorecard);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).category()).isEqualTo(SandboxPromptDefectCategory.IMPLEMENTATION_DEFECT);
    }

    @Test
    @DisplayName("얇은 baseline과 provisional evidence 경고는 LLM 해석 영역으로 분리되어야 한다")
    void shouldClassifyThinBaselineWarningsAsLlmEvaluableGaps() {
        SandboxPromptQualityScorecard scorecard = SandboxPromptQualityScorecard.of(
                "3차 full-stack prompt 점검",
                List.of(new SandboxPromptQualityScorecard.CheckResult(
                        "3차 userPrompt는 baseline이 아직 provisional임을 보여야 한다",
                        false,
                        "baseline remains thin and provisional")));

        List<SandboxPromptDefectFinding> findings = SandboxPromptDefectClassifier.classifyScorecardFailures(
                "benchmark-run-1",
                "alice@example.com",
                scorecard);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).category()).isEqualTo(SandboxPromptDefectCategory.LLM_EVALUABLE_GAP);
    }
}

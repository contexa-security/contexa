package io.contexa.sandbox.fullstack.prompt;

import java.util.List;
import java.util.Map;

/**
 * sandbox benchmark 1회 실행 결과.
 *
 * 하나의 실행은 동일 사용자에 대한 N회 replay와,
 * 각 round별 scorecard / trace contract / artifact integrity / 전체 지표 / 결함을 함께 보존한다.
 */
public record SandboxPromptBenchmarkRunResult(
        String benchmarkRunId,
        String username,
        SandboxPromptReplayRun replayRun,
        List<SandboxPromptQualityScorecard> roundScorecards,
        SandboxPromptQualityScorecard progressionScorecard,
        List<SandboxPromptTraceContractAssessment> traceContractAssessments,
        List<SandboxPromptFidelityAssessment> promptFidelityAssessments,
        List<SandboxPromptArtifactIntegrityAssessment> artifactIntegrityAssessments,
        Map<String, Double> metrics,
        List<SandboxPromptDefectFinding> defectFindings) {

    public SandboxPromptBenchmarkRunResult {
        roundScorecards = roundScorecards == null ? List.of() : List.copyOf(roundScorecards);
        traceContractAssessments = traceContractAssessments == null ? List.of() : List.copyOf(traceContractAssessments);
        promptFidelityAssessments = promptFidelityAssessments == null ? List.of() : List.copyOf(promptFidelityAssessments);
        artifactIntegrityAssessments = artifactIntegrityAssessments == null ? List.of() : List.copyOf(artifactIntegrityAssessments);
        metrics = metrics == null ? Map.of() : Map.copyOf(metrics);
        defectFindings = defectFindings == null ? List.of() : List.copyOf(defectFindings);
    }

    public SandboxPromptQualityScorecard firstRoundScorecard() {
        return roundScorecards.get(0);
    }

    public SandboxPromptQualityScorecard secondRoundScorecard() {
        return roundScorecards.get(1);
    }

    public SandboxPromptQualityScorecard thirdRoundScorecard() {
        return roundScorecards.get(2);
    }

    public SandboxPromptTraceContractAssessment firstTraceContractAssessment() {
        return traceContractAssessments.get(0);
    }

    public SandboxPromptTraceContractAssessment secondTraceContractAssessment() {
        return traceContractAssessments.get(1);
    }

    public SandboxPromptTraceContractAssessment thirdTraceContractAssessment() {
        return traceContractAssessments.get(2);
    }

    public SandboxPromptFidelityAssessment firstPromptFidelityAssessment() {
        return promptFidelityAssessments.get(0);
    }

    public SandboxPromptFidelityAssessment secondPromptFidelityAssessment() {
        return promptFidelityAssessments.get(1);
    }

    public SandboxPromptFidelityAssessment thirdPromptFidelityAssessment() {
        return promptFidelityAssessments.get(2);
    }

    public SandboxPromptArtifactIntegrityAssessment firstArtifactIntegrityAssessment() {
        return artifactIntegrityAssessments.get(0);
    }

    public SandboxPromptArtifactIntegrityAssessment secondArtifactIntegrityAssessment() {
        return artifactIntegrityAssessments.get(1);
    }

    public SandboxPromptArtifactIntegrityAssessment thirdArtifactIntegrityAssessment() {
        return artifactIntegrityAssessments.get(2);
    }
}

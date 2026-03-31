package io.contexa.sandbox.fullstack.prompt;

import java.util.List;

/**
 * 한 round의 relatedDocuments 무결성 감사 결과.
 */
public record SandboxPromptArtifactIntegrityAssessment(
        double integrityRate,
        List<SandboxPromptDefectFinding> findings) {

    public SandboxPromptArtifactIntegrityAssessment {
        findings = findings == null ? List.of() : List.copyOf(findings);
    }
}

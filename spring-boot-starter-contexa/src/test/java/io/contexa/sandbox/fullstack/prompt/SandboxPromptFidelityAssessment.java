package io.contexa.sandbox.fullstack.prompt;

import java.util.List;

/**
 * full-stack replay에서 생성된 prompt fidelity 감사 결과.
 *
 * 목적:
 * - 실제 WebClient replay가 만든 prompt와 metadata가 템플릿 계약을 얼마나 충실하게 지켰는지 수치화한다.
 * - sectionSet / omittedSections / omissionLedger / hash / length / 실제 prompt 본문이 서로 일치하는지 기록한다.
 */
public record SandboxPromptFidelityAssessment(
        String source,
        double fidelityRate,
        List<String> metadataSectionKeys,
        List<String> executionSectionKeys,
        List<String> omittedSections,
        int omissionLedgerCount,
        List<SandboxPromptDefectFinding> findings) {

    public SandboxPromptFidelityAssessment {
        metadataSectionKeys = metadataSectionKeys == null ? List.of() : List.copyOf(metadataSectionKeys);
        executionSectionKeys = executionSectionKeys == null ? List.of() : List.copyOf(executionSectionKeys);
        omittedSections = omittedSections == null ? List.of() : List.copyOf(omittedSections);
        findings = findings == null ? List.of() : List.copyOf(findings);
    }
}

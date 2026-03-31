package io.contexa.sandbox.fullstack.prompt;

import java.util.List;

/**
 * requestId 기준 trace 계약 준수도 평가 결과.
 *
 * 목적:
 * - replay가 회수한 trace가 benchmark의 공식 입력 계약을 얼마나 충실히 만족하는지 수치화한다.
 * - 누락/빈값/메타데이터 단절은 LLM 이전의 구현 결함으로 본다.
 */
public record SandboxPromptTraceContractAssessment(
        String source,
        double complianceRate,
        List<SandboxPromptDefectFinding> findings) {

    public SandboxPromptTraceContractAssessment {
        findings = findings == null ? List.of() : List.copyOf(findings);
    }
}

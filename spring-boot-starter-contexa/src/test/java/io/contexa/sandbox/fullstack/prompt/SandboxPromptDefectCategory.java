package io.contexa.sandbox.fullstack.prompt;

/**
 * sandbox full-stack benchmark에서 발견된 결함의 책임 영역.
 *
 * 목적:
 * - 구현 결함과 데이터 품질 결함을 LLM 해석 영역과 분리한다.
 * - "무엇이 고장났는가"를 사람 해석 없이도 통계로 누적한다.
 */
public enum SandboxPromptDefectCategory {
    IMPLEMENTATION_DEFECT,
    DATA_QUALITY_DEFECT,
    LLM_EVALUABLE_GAP,
    OBSERVABILITY_DEFECT
}

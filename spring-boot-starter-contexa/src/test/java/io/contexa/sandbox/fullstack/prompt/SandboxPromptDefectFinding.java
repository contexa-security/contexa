package io.contexa.sandbox.fullstack.prompt;

/**
 * benchmark 한 건에서 식별된 구조화된 결함 레코드.
 *
 * 이 레코드는 개별 round/check/metric 수준까지 내려가서
 * "왜 실패했는가"를 재현 가능한 형태로 남긴다.
 */
public record SandboxPromptDefectFinding(
        String benchmarkRunId,
        String username,
        String source,
        String code,
        SandboxPromptDefectCategory category,
        String summary,
        String detail) {
}

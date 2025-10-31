package io.contexa.contexaidentity.security.core.mfa.policy;

import lombok.Builder;
import lombok.Getter;
import java.util.List;

/**
 * Phase 2: MFA 완료 여부 결정 결과
 *
 * <p>
 * PolicyProvider의 결정 로직과 실행 로직을 분리하기 위한 DTO.
 * PolicyProvider는 이 객체를 반환하며, 실제 Context 수정은 State Machine Action에서 수행.
 * </p>
 *
 * @since Phase 2
 */
@Getter
@Builder
public class CompletionDecision {
    private final boolean completed;
    private final boolean needsFactorSelection;
    private final int attemptCount;
    private final String errorMessage;
    private final List<String> missingRequiredStepIds;

    /**
     * 모든 필수 팩터 완료
     */
    public static CompletionDecision completed() {
        return CompletionDecision.builder()
            .completed(true)
            .needsFactorSelection(false)
            .build();
    }

    /**
     * 팩터 선택 필요
     */
    public static CompletionDecision needsFactorSelection(int attemptCount) {
        return CompletionDecision.builder()
            .completed(false)
            .needsFactorSelection(true)
            .attemptCount(attemptCount)
            .build();
    }

    /**
     * 미완료 (필수 팩터 누락)
     */
    public static CompletionDecision incomplete(List<String> missingSteps) {
        return CompletionDecision.builder()
            .completed(false)
            .needsFactorSelection(true)
            .missingRequiredStepIds(missingSteps)
            .build();
    }

    /**
     * 완료 확인 중 에러 발생
     */
    public static CompletionDecision error(String message) {
        return CompletionDecision.builder()
            .completed(false)
            .needsFactorSelection(false)
            .errorMessage(message)
            .build();
    }
}

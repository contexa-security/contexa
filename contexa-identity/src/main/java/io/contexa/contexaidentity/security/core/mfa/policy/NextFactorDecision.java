package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexacommon.enums.AuthType;
import lombok.Builder;
import lombok.Getter;

/**
 * Phase 2: 다음 팩터 결정 결과
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
public class NextFactorDecision {
    private final boolean hasNextFactor;
    private final AuthType nextFactorType;
    private final String nextStepId;
    private final boolean allFactorsCompleted;
    private final String errorMessage;

    /**
     * 더 이상 처리할 팩터가 없음 (모든 팩터 완료)
     */
    public static NextFactorDecision noMoreFactors() {
        return NextFactorDecision.builder()
            .hasNextFactor(false)
            .allFactorsCompleted(true)
            .build();
    }

    /**
     * 다음 팩터가 결정됨
     */
    public static NextFactorDecision nextFactor(AuthType type, String stepId) {
        return NextFactorDecision.builder()
            .hasNextFactor(true)
            .nextFactorType(type)
            .nextStepId(stepId)
            .allFactorsCompleted(false)
            .build();
    }

    /**
     * 결정 중 에러 발생
     */
    public static NextFactorDecision error(String message) {
        return NextFactorDecision.builder()
            .hasNextFactor(false)
            .allFactorsCompleted(false)
            .errorMessage(message)
            .build();
    }
}

package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.enums.AuthType;

/**
 * MFA 정책 제공자 인터페이스
 */
public interface MfaPolicyProvider {

    /**
     * 초기 MFA 요구사항 평가 (읽기 전용)
     *
     * <p>
     * PolicyProvider의 결정 로직과 실행 로직을 분리.
     * 이 메서드는 Context를 수정하지 않고 MfaDecision만 반환합니다.
     * 실제 Context 수정과 이벤트 전송은 State Machine Action에서 수행됩니다.
     * </p>
     *
     * @param ctx 읽기 전용 FactorContext
     * @return MFA 정책 평가 결과
     * @since Phase 2
     */
    MfaDecision evaluateInitialMfaRequirement(FactorContext ctx);

    /**
     * Phase 2: 다음 팩터 평가 (읽기 전용)
     *
     * <p>
     * PolicyProvider의 결정 로직과 실행 로직을 분리.
     * 이 메서드는 Context를 수정하지 않고 결정만 반환합니다.
     * 실제 Context 수정은 State Machine Action에서 수행됩니다.
     * </p>
     *
     * @param ctx 읽기 전용 FactorContext
     * @return 다음 팩터 결정 결과
     * @since Phase 2
     */
    NextFactorDecision evaluateNextFactor(FactorContext ctx);

    /**
     * 특정 팩터가 사용자에게 사용 가능한지 확인
     */
    boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx);


    /**
     * Phase 2: 완료 여부 평가 (읽기 전용)
     *
     * <p>
     * PolicyProvider의 결정 로직과 실행 로직을 분리.
     * 이 메서드는 Context를 수정하지 않고 결정만 반환합니다.
     * 실제 Context 수정은 State Machine Action에서 수행됩니다.
     * </p>
     *
     * @param ctx 읽기 전용 FactorContext
     * @param mfaFlowConfig MFA 플로우 설정
     * @return 완료 여부 결정 결과
     * @since Phase 2
     */
    CompletionDecision evaluateCompletion(FactorContext ctx, AuthenticationFlowConfig mfaFlowConfig);

    /**
     * 필요한 팩터 수 가져오기
     */
    default Integer getRequiredFactorCount(String userId, String flowType) {
        // 기본 구현: flowType에 따라 결정
        if ("mfa".equalsIgnoreCase(flowType)) {
            return 2;
        } else if ("mfa-stepup".equalsIgnoreCase(flowType)) {
            return 1;
        }
        return 1;
    }
}
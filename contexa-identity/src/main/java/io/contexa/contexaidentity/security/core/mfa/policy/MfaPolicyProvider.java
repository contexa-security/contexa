package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.mfa.RetryPolicy;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.enums.AuthType;

/**
 * MFA 정책 제공자 인터페이스
 */
public interface MfaPolicyProvider {

    /**
     * 1차 인증 후 MFA 필요 여부 평가 및 초기 단계 결정
     */
    void evaluateMfaRequirementAndDetermineInitialStep(FactorContext ctx);

    /**
     * 다음 처리할 팩터 결정
     */
    void determineNextFactorToProcess(FactorContext ctx);

    /**
     * 특정 팩터의 재시도 정책 가져오기
     */
    RetryPolicy getRetryPolicyForFactor(AuthType factorType, FactorContext ctx);

    /**
     * 특정 팩터가 사용자에게 사용 가능한지 확인
     */
    boolean isFactorAvailableForUser(String username, AuthType factorType, FactorContext ctx);

    /**
     * 재시도 정책 가져오기
     */
    RetryPolicy getRetryPolicy(FactorContext factorContext, AuthenticationStepConfig step);

    void checkAllFactorsCompleted(FactorContext ctx, AuthenticationFlowConfig mfaFlowConfig);

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
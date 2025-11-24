package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexacommon.enums.AuthType;
import org.springframework.lang.Nullable;

import java.util.List;

/**
 * MFA 정책 평가자 인터페이스
 * 
 * MFA 정책을 평가하고 결정을 내리는 핵심 인터페이스입니다.
 * 이 인터페이스의 구현체는 다양한 정책 평가 전략을 제공할 수 있습니다.
 * 
 * 구현 예시:
 * - DefaultMfaPolicyEvaluator: 규칙 기반 정책 평가
 * - AIAdaptivePolicyEvaluator: AI 기반 적응형 정책 평가
 * - RiskBasedPolicyEvaluator: 위험도 기반 정책 평가
 * 
 * @author contexa
 * @since 1.0
 */
public interface MfaPolicyEvaluator {
    
    /**
     * MFA 정책을 평가하고 결정을 반환합니다.
     * 
     * 이 메서드는 주어진 컨텍스트를 기반으로 MFA 요구사항을 평가하고,
     * 어떤 유형의 MFA가 필요한지, 몇 개의 팩터가 필요한지 등을 결정합니다.
     * 
     * @param context 평가할 팩터 컨텍스트 (사용자 정보, 세션 정보 등 포함)
     * @return MFA 결정 (필요 여부, 팩터 수, 유형 등)
     * @throws IllegalArgumentException context가 null인 경우
     */
    MfaDecision evaluatePolicy(FactorContext context);
    
    /**
     * 특정 사용자에 대해 MFA가 필요한지 평가합니다.
     * 
     * @param username 사용자명
     * @param context 팩터 컨텍스트
     * @return MFA 필요 여부
     */
    default boolean isMfaRequired(String username, @Nullable FactorContext context) {
        if (context == null) {
            // 컨텍스트가 없으면 보수적으로 평가
            return true;
        }
        MfaDecision decision = evaluatePolicy(context);
        return decision.isRequired();
    }
    
    /**
     * 필요한 MFA 팩터 수를 결정합니다.
     * 
     * @param context 팩터 컨텍스트
     * @return 필요한 팩터 수 (0 = MFA 불필요, 1+ = 필요한 팩터 수)
     */
    default int getRequiredFactorCount(FactorContext context) {
        MfaDecision decision = evaluatePolicy(context);
        return decision.getFactorCount();
    }
    
    /**
     * 사용 가능한 팩터 목록에서 필수 팩터를 결정합니다.
     * 
     * @param availableFactors 사용 가능한 팩터 목록
     * @param context 팩터 컨텍스트
     * @return 필수 팩터 목록 (비어있을 수 있음)
     */
    default List<AuthType> determineRequiredFactors(
            List<AuthType> availableFactors, 
            FactorContext context) {
        MfaDecision decision = evaluatePolicy(context);
        List<AuthType> requiredFactors = decision.getRequiredFactors();
        
        // 필수 팩터가 지정되지 않은 경우 사용 가능한 팩터 중에서 선택
        if (requiredFactors == null || requiredFactors.isEmpty()) {
            return availableFactors;
        }
        
        // 필수 팩터 중 사용 가능한 것만 반환
        return requiredFactors.stream()
            .filter(availableFactors::contains)
            .toList();
    }
    
    /**
     * 이 평가자가 주어진 컨텍스트를 지원하는지 확인합니다.
     * Composite 패턴을 위한 핵심 메서드입니다.
     * 
     * @param context 평가할 팩터 컨텍스트
     * @return 지원 여부
     */
    default boolean supports(FactorContext context) {
        return isAvailable();
    }
    
    /**
     * 평가자가 사용 가능한 상태인지 확인합니다.
     * 
     * @return 사용 가능 여부
     */
    default boolean isAvailable() {
        return true;
    }
    
    /**
     * 평가자의 우선순위를 반환합니다.
     * 숫자가 높을수록 우선순위가 높습니다.
     * 
     * @return 우선순위 (기본값: 0)
     */
    default int getPriority() {
        return 0;
    }
    
    /**
     * 평가자의 이름을 반환합니다.
     * 
     * @return 평가자 이름
     */
    default String getName() {
        return this.getClass().getSimpleName();
    }
}
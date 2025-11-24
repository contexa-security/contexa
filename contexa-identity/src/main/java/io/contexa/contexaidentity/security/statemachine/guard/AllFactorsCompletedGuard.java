package io.contexa.contexaidentity.security.statemachine.guard;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

/**
 * 모든 필수 팩터가 완료되었는지 확인하는 Guard
 * Phase 3: PolicyProvider를 필수로 변경, 복잡한 Fallback 제거
 */
@Slf4j
public class AllFactorsCompletedGuard extends AbstractMfaStateGuard {

    private final MfaPolicyProvider mfaPolicyProvider;

    public AllFactorsCompletedGuard(MfaPolicyProvider mfaPolicyProvider) {
        this.mfaPolicyProvider = mfaPolicyProvider;
    }

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        // Phase 2: FactorContext null 체크 추가
        if (factorContext == null) {
            log.error("[AllFactorsCompletedGuard] ⚠️ FactorContext is NULL! Cannot evaluate. Returning false.");
            return false; // Reactive Stream 완료 보장
        }

        String sessionId = factorContext.getMfaSessionId();

        try {
            log.debug("[AllFactorsCompletedGuard] Guard 평가 시작 - Session: {}, CurrentState: {}",
                     sessionId, factorContext.getCurrentState());

            // 완료된 팩터 수 (null 안전)
            int completedCount = factorContext.getCompletedFactors() != null ?
                    factorContext.getCompletedFactors().size() : 0;

            // 필요한 팩터 수 (다중 Fallback 전략 적용)
            int requiredCount = getRequiredFactorCount(factorContext);

            // 추가: 유효성 검증
            if (requiredCount <= 0) {
                log.error("[AllFactorsCompletedGuard] Invalid required factor count ({}) for session: {}. Defaulting to 1.",
                        requiredCount, sessionId);
                requiredCount = 1;
            }

            log.debug("[AllFactorsCompletedGuard] Session {}: completed factors={}, required factors={} ({})",
                    sessionId, completedCount, requiredCount,
                    completedCount >= requiredCount ? "SATISFIED" : "NOT_SATISFIED");

            boolean allCompleted = completedCount >= requiredCount;

            if (allCompleted) {
                log.info("[AllFactorsCompletedGuard] ✅ All required factors completed for session: {} ({}/{})",
                        sessionId, completedCount, requiredCount);
            } else {
                log.debug("[AllFactorsCompletedGuard] More factors required for session: {} ({}/{})",
                        sessionId, completedCount, requiredCount);
            }

            log.debug("[AllFactorsCompletedGuard] Guard 평가 완료 - Session: {}, Result: {}",
                     sessionId, allCompleted);

            return allCompleted;

        } catch (Exception e) {
            log.error("[AllFactorsCompletedGuard] ⚠️ Exception during guard evaluation for session: {}. Returning false to complete Reactive Stream.",
                     sessionId, e);
            return false; // 오류 시 안전하게 false 반환 (Reactive Stream 완료 보장)
        }
    }

    /**
     * Phase 3: Fallback 단순화 - PolicyProvider 필수
     */
    private int getRequiredFactorCount(FactorContext factorContext) {
        String userId = factorContext.getUsername();
        String flowType = factorContext.getFlowTypeName();

        Integer requiredFactors = mfaPolicyProvider.getRequiredFactorCount(userId, flowType);

        if (requiredFactors != null && requiredFactors > 0) {
            log.debug("Policy requires {} factors for user: {} in flow: {}",
                    requiredFactors, userId, flowType);
            return requiredFactors;
        }

        // 안전한 기본값 (PolicyProvider 설정 오류 시)
        log.warn("PolicyProvider returned null/invalid for user: {}, flow: {}. Using default: 1",
                userId, flowType);
        return 1;
    }

    @Override
    public String getFailureReason() {
        return "Not all required MFA factors have been completed. Check factor requirements and completion status.";
    }

    /**
     * 특정 팩터 타입이 완료되었는지 확인
     */
    public boolean isFactorTypeCompleted(FactorContext factorContext, String factorType) {
        if (factorContext.getCompletedFactors() == null || factorType == null) {
            return false;
        }

        return factorContext.getCompletedFactors().stream()
                .anyMatch(factor -> factorType.equalsIgnoreCase(factor.getType()));
    }

    /**
     * 추가 팩터가 필요한지 확인
     */
    public boolean needsMoreFactors(FactorContext factorContext) {
        return !doEvaluate(null, factorContext);
    }

    @Override
    public String getGuardName() {
        return "AllFactorsCompletedGuard";
    }
}
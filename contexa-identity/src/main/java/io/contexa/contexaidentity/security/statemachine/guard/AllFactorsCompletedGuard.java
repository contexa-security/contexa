package io.contexa.contexaidentity.security.statemachine.guard;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

/**
 * 모든 필수 팩터가 완료되었는지 확인하는 Guard
 */
@Slf4j
@Component
public class AllFactorsCompletedGuard extends AbstractMfaStateGuard {

    private final ApplicationContext applicationContext;
    private MfaPolicyProvider  mfaPolicyProvider;

    public AllFactorsCompletedGuard(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    private MfaPolicyProvider getMfaPolicyProvider() {
        if (mfaPolicyProvider == null) {
            try {
                mfaPolicyProvider = applicationContext.getBean(MfaPolicyProvider.class);
            } catch (Exception e) {
                log.warn("Failed to get MfaPolicyProvider, using direct calculation", e);
                return null;
            }
        }
        return mfaPolicyProvider;
    }

    @Override
    protected boolean doEvaluate(StateContext<MfaState, MfaEvent> context,
                                 FactorContext factorContext) {
        String sessionId = factorContext.getMfaSessionId();

        try {
            // 완료된 팩터 수 (null 안전)
            int completedCount = factorContext.getCompletedFactors() != null ?
                    factorContext.getCompletedFactors().size() : 0;

            // 필요한 팩터 수 (다중 Fallback 전략 적용)
            int requiredCount = getRequiredFactorCount(factorContext);

            // 추가: 유효성 검증
            if (requiredCount <= 0) {
                log.error("Invalid required factor count ({}) for session: {}. Defaulting to 1.",
                        requiredCount, sessionId);
                requiredCount = 1;
            }

            log.debug("Session {}: completed factors={}, required factors={} ({})",
                    sessionId, completedCount, requiredCount,
                    completedCount >= requiredCount ? "SATISFIED" : "NOT_SATISFIED");

            boolean allCompleted = completedCount >= requiredCount;

            if (allCompleted) {
                log.info("All required factors completed for session: {} ({}/{})",
                        sessionId, completedCount, requiredCount);
            } else {
                log.debug("More factors required for session: {} ({}/{})",
                        sessionId, completedCount, requiredCount);
            }

            return allCompleted;

        } catch (Exception e) {
            log.error("Error evaluating all factors completed for session: {}. Defaulting to false.", sessionId, e);
            return false; // 오류 시 안전하게 false 반환
        }
    }

    /**
     * NPE 방지 및 다중 Fallback 전략
     */
    private int getRequiredFactorCount(FactorContext factorContext) {
        // 1차: 정책 제공자를 통한 조회
        try {
            MfaPolicyProvider policyProvider = getMfaPolicyProvider();
            if (policyProvider != null) {
                String userId = factorContext.getUsername();
                String flowType = factorContext.getFlowTypeName();

                Integer requiredFactors = policyProvider.getRequiredFactorCount(userId, flowType);
                if (requiredFactors != null && requiredFactors >= 0) { // 0도 유효한 값
                    log.debug("Policy requires {} factors for user: {} in flow: {}",
                            requiredFactors, userId, flowType);
                    return requiredFactors;
                }
            }
        } catch (Exception e) {
            log.warn("Error getting required factor count from policy for user: {}, using fallback: {}",
                    factorContext.getUsername(), e.getMessage());
        }

        // 2차: 사용자 역할 기반 Fallback
        try {
            int roleBasedCount = getRequiredFactorCountByUserRole(factorContext);
            if (roleBasedCount > 0) {
                log.debug("Using role-based factor count: {} for user: {}",
                        roleBasedCount, factorContext.getUsername());
                return roleBasedCount;
            }
        } catch (Exception e) {
            log.debug("Role-based factor count lookup failed: {}", e.getMessage());
        }

        // 3차: 등록된 팩터 수 기반 Fallback
        try {
            int registeredCount = factorContext.getRegisteredMfaFactors().size();
            if (registeredCount > 0) {
                // 등록된 팩터의 절반 이상 완료를 요구 (최소 1개)
                int requiredCount = Math.max(1, registeredCount / 2);
                log.debug("Using registered factors-based count: {} (from {} registered) for user: {}",
                        requiredCount, registeredCount, factorContext.getUsername());
                return requiredCount;
            }
        } catch (Exception e) {
            log.debug("Registered factors-based count lookup failed: {}", e.getMessage());
        }

        // 4차: 플로우 타입 기반 기본값 (최종 Fallback)
        int defaultCount = getDefaultRequiredFactorCount(factorContext.getFlowTypeName());
        log.info("Using default factor count: {} for flow: {} and user: {}",
                defaultCount, factorContext.getFlowTypeName(), factorContext.getUsername());
        return defaultCount;
    }

    /**
     * 추가: 사용자 역할 기반 필수 팩터 수 결정
     */
    private int getRequiredFactorCountByUserRole(FactorContext factorContext) {
        try {
            // Spring Security Authentication 에서 권한 정보 추출
            var authorities = factorContext.getPrimaryAuthentication().getAuthorities();

            if (authorities != null) {
                for (var authority : authorities) {
                    String role = authority.getAuthority();

                    // 역할별 정책
                    switch (role.toUpperCase()) {
                        case "ROLE_ADMIN":
                        case "ROLE_PRIVILEGED_USER":
                            return 2; // 관리자는 2팩터 필수
                        case "ROLE_POWER_USER":
                            return 2; // 고급 사용자도 2팩터
                        case "ROLE_USER":
                            return 1; // 일반 사용자는 1팩터
                        case "ROLE_GUEST":
                            return 1; // 게스트도 1팩터
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Failed to determine factor count by user role: {}", e.getMessage());
        }

        return 0; // 역할 기반 결정 실패
    }

    /**
     * 플로우 타입별 기본 필수 팩터 수
     */
    private int getDefaultRequiredFactorCount(String flowType) {
        if (flowType == null || flowType.trim().isEmpty()) {
            return 1; // 안전한 기본값
        }

        return switch (flowType.toLowerCase().trim()) {
            case "mfa", "mfa-strict" -> 2; // 엄격한 MFA는 2개 팩터
            case "mfa-standard" -> 2; // 표준 MFA도 2개
            case "mfa-stepup" -> 1; // Step-up 인증은 1개 추가
            case "mfa-transactional", "mfa-payment" -> 1; // 거래 인증은 1개
            case "mfa-light", "mfa-optional" -> 1; // 가벼운 MFA는 1개
            default -> {
                log.warn("Unknown flow type '{}', using default factor count: 1", flowType);
                yield 1; // 알 수 없는 플로우는 안전하게 1개
            }
        };
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
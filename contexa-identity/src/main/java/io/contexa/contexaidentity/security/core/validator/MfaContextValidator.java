package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

/**
 * MFA 컨텍스트 검증 유틸리티
 * 중복된 검증 로직을 통합하여 일관성과 성능 향상
 */
@Slf4j
public class MfaContextValidator {

    /**
     * 기본 MFA 컨텍스트 유효성 검증
     */
    public static ValidationResult validateMfaContext(FactorContext ctx,
                                                      MfaSessionRepository sessionRepository) {
        ValidationResult result = new ValidationResult();

        // 1. FactorContext null 체크
        if (ctx == null) {
            result.addError("FactorContext is null");
            return result;
        }

        // 2. 세션 ID 체크
        if (!StringUtils.hasText(ctx.getMfaSessionId())) {
            result.addError("MFA session ID is null or empty");
            return result;
        }

        // 3. 플로우 타입 체크
        if (!"MFA".equalsIgnoreCase(ctx.getFlowTypeName())) {
            result.addError("Invalid flow type: " + ctx.getFlowTypeName() + " (expected: MFA)");
        }

        // 4. Repository를 통한 세션 존재 확인
        if (sessionRepository != null && !sessionRepository.existsSession(ctx.getMfaSessionId())) {
            result.addError("MFA session not found in repository: " + ctx.getMfaSessionId());
        }

        // 5. 터미널 상태 체크
        if (ctx.getCurrentState().isTerminal()) {
            result.addWarning("Context is in terminal state: " + ctx.getCurrentState());
        }

        // 6. 사용자명 체크
        if (!StringUtils.hasText(ctx.getUsername())) {
            result.addError("Username is null or empty");
        }

        return result;
    }

    /**
     * 팩터 처리 컨텍스트 검증 (MfaStepFilterWrapper용)
     */
    public static ValidationResult validateFactorProcessingContext(FactorContext ctx,
                                                                   MfaSessionRepository sessionRepository) {
        ValidationResult result = validateMfaContext(ctx, sessionRepository);

        if (result.hasErrors()) {
            return result; // 기본 검증 실패 시 더 이상 검증하지 않음
        }

        // 7. 현재 처리 중인 팩터 체크
        if (ctx.getCurrentProcessingFactor() == null) {
            result.addError("No factor is currently being processed");
        }

        // 8. 팩터 처리 가능한 상태인지 체크
        MfaState currentState = ctx.getCurrentState();
        if (!isFactorProcessingState(currentState)) {
            result.addError("Invalid state for factor processing: " + currentState);
        }

        // 9. 현재 단계 ID 체크
        if (!StringUtils.hasText(ctx.getCurrentStepId())) {
            result.addWarning("Current step ID is null or empty");
        }

        return result;
    }

    /**
     * 팩터 선택 컨텍스트 검증 (MfaContinuationFilter용)
     */
    public static ValidationResult validateFactorSelectionContext(FactorContext ctx,
                                                                  MfaSessionRepository sessionRepository) {
        ValidationResult result = validateMfaContext(ctx, sessionRepository);

        if (result.hasErrors()) {
            return result;
        }

        // 10. 팩터 선택 가능한 상태인지 체크
        MfaState currentState = ctx.getCurrentState();
        if (!isFactorSelectionOrProcessingState(currentState)) {
            result.addError("Invalid state for factor selection: " + currentState);
        }

        // 11. 사용 가능한 팩터 존재 여부 체크
        if (ctx.getAvailableFactors().isEmpty()) {
            result.addWarning("No available MFA factors found");
        }

        return result;
    }

    /**
     * 챌린지 시작 컨텍스트 검증
     */
    public static ValidationResult validateChallengeInitiationContext(FactorContext ctx,
                                                                      MfaSessionRepository sessionRepository) {
        ValidationResult result = validateMfaContext(ctx, sessionRepository);

        if (result.hasErrors()) {
            return result;
        }

        // 12. 챌린지 시작 가능한 상태인지 체크
        MfaState currentState = ctx.getCurrentState();
        if (currentState != MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION) {
            result.addError("Invalid state for challenge initiation: " + currentState);
        }

        // 13. 현재 처리 팩터 확인
        if (ctx.getCurrentProcessingFactor() == null) {
            result.addError("No factor selected for challenge initiation");
        }

        return result;
    }

    /**
     * 팩터 검증 컨텍스트 검증
     */
    public static ValidationResult validateFactorVerificationContext(FactorContext ctx,
                                                                     MfaSessionRepository sessionRepository) {
        ValidationResult result = validateMfaContext(ctx, sessionRepository);

        if (result.hasErrors()) {
            return result;
        }

        // 14. 검증 가능한 상태인지 체크
        MfaState currentState = ctx.getCurrentState();
        if (!isFactorVerificationState(currentState)) {
            result.addError("Invalid state for factor verification: " + currentState);
        }

        // 15. 챌린지 만료 시간 체크
        Object challengeTime = ctx.getAttribute("challengeInitiatedAt");
        if (challengeTime instanceof Long) {
            long elapsed = System.currentTimeMillis() - (Long) challengeTime;
            if (elapsed > 300000) { // 5분 초과
                result.addWarning("Challenge may have expired (elapsed: " + elapsed + "ms)");
            }
        }

        return result;
    }

    // === 헬퍼 메서드들 ===

    private static boolean isFactorProcessingState(MfaState state) {
        return state == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                state == MfaState.FACTOR_VERIFICATION_PENDING ||
                state == MfaState.FACTOR_VERIFICATION_IN_PROGRESS;
    }

    private static boolean isFactorSelectionOrProcessingState(MfaState state) {
        return state == MfaState.AWAITING_FACTOR_SELECTION ||
                state == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                state == MfaState.PRIMARY_AUTHENTICATION_COMPLETED;
    }

    private static boolean isFactorVerificationState(MfaState state) {
        return state == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                state == MfaState.FACTOR_VERIFICATION_PENDING;
    }
}
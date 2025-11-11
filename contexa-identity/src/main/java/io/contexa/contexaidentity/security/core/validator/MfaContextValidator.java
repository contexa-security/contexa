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

        // 3. 터미널 상태 체크 (Warning → Error 변경, Phase 2 최적화)
        if (ctx.getCurrentState().isTerminal()) {
            result.addError("Context is in terminal state: " + ctx.getCurrentState());
            return result; // 터미널 상태에서는 더 이상 진행 불가
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

        // 9. 현재 단계 ID 체크 (Warning → Error 변경, Phase 2 최적화)
        if (!StringUtils.hasText(ctx.getCurrentStepId())) {
            result.addError("Current step ID is null or empty");
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

        // Phase 2 최적화: 챌린지 만료 시간 체크 제거 (MfaStepFilterWrapper가 처리)

        return result;
    }

    // === 헬퍼 메서드들 ===

    // Phase 2 최적화: Option 2 변경에 맞춰 상태 목록 수정
    private static boolean isFactorProcessingState(MfaState state) {
        return state == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                state == MfaState.FACTOR_VERIFICATION_PENDING;
    }

    private static boolean isFactorSelectionOrProcessingState(MfaState state) {
        return state == MfaState.AWAITING_FACTOR_SELECTION ||
                state == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION ||
                state == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                state == MfaState.PRIMARY_AUTHENTICATION_COMPLETED;
    }

    private static boolean isFactorVerificationState(MfaState state) {
        return state == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                state == MfaState.FACTOR_VERIFICATION_PENDING;
    }
}
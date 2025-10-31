package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
public class CompleteMfaAction extends AbstractMfaStateAction {

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();
        log.info("Completing MFA for session: {}", sessionId);

        // 완료된 팩터 목록 로깅
        logCompletedFactors(factorContext);

        // MFA 완료 시간 설정
        factorContext.setAttribute("completedAt", LocalDateTime.now());

        // Phase 2 개선: State Machine이 상태 전이를 담당
        // ALL_FACTORS_VERIFIED_PROCEED_TO_TOKEN 이벤트로 인한 전이가
        // 이미 MFA_SUCCESSFUL로 상태를 변경하므로 여기서 중복 호출 불필요

        // 추가 완료 처리 로직
        performCompletionTasks(factorContext);

        // 이벤트 메타데이터 추가
        updateEventMetadata(context);

        log.info("MFA successfully completed for session: {}", sessionId);
    }

    private void logCompletedFactors(FactorContext factorContext) {
        List<AuthenticationStepConfig> completedFactors = factorContext.getCompletedFactors();
        if (completedFactors != null && !completedFactors.isEmpty()) {
            String completedFactorTypes = completedFactors.stream()
                    .map(AuthenticationStepConfig::getType)
                    .collect(Collectors.joining(", "));
            log.info("MFA completed with factors: {} for session: {}",
                    completedFactorTypes, factorContext.getMfaSessionId());
        }
    }

    private void performCompletionTasks(FactorContext factorContext) {
        // 감사 로그 기록을 위한 준비
        factorContext.setAttribute("completionTimestamp", System.currentTimeMillis());

        // 완료된 팩터들의 상세 정보 저장
        if (factorContext.getCompletedFactors() != null) {
            factorContext.setAttribute("totalFactorsCompleted",
                    factorContext.getCompletedFactors().size());
        }

        // 세션 지속 시간 계산
        long createdAt = factorContext.getCreatedAt();
        long durationSeconds = (System.currentTimeMillis() - createdAt) / 1000;
        factorContext.setAttribute("mfaDurationSeconds", durationSeconds);
    }

    private void updateEventMetadata(StateContext<MfaState, MfaEvent> context) {
        context.getExtendedState().getVariables().put("mfaCompletedAt", LocalDateTime.now());
        context.getExtendedState().getVariables().put("completionStatus", "SUCCESS");
    }
}
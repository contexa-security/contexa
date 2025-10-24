package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Optional;

@Slf4j
@Component
public class VerifyFactorAction extends AbstractMfaStateAction {

    private final ApplicationContext applicationContext;

    public VerifyFactorAction(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context, FactorContext factorContext){
        String sessionId = factorContext.getMfaSessionId();
        String currentStepId = factorContext.getCurrentStepId();

        if (currentStepId == null || currentStepId.isEmpty()) {
            log.error("Cannot verify factor: currentStepId is null or empty for session: {}. Transitioning to SYSTEM_ERROR.", sessionId);
            factorContext.setLastError("currentStepId is missing during factor verification.");
            // 시스템 에러 이벤트를 보내거나 상태를 직접 변경 (상태 머신 설정에 따라 다름)
            // 여기서는 상태를 직접 변경하는 대신, 예외를 발생시켜 AbstractMfaStateAction의 에러 핸들링 로직을 타도록 유도 가능
            throw new IllegalStateException("currentStepId is null or empty for session: " + sessionId);
        }

        log.info("Verifying factor for step: {} in session: {}", currentStepId, sessionId);

        String factorType = factorContext.getCurrentProcessingFactor() != null ?
                factorContext.getCurrentProcessingFactor().name() : null;
        if (factorType == null) {
            // currentStepId 로부터 factorType 추론 시도 (Robustness)
            PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
            Optional<AuthenticationFlowConfig> flowConfigOpt = platformConfig.getFlows().stream()
                    .filter(f -> f.getTypeName().equalsIgnoreCase(factorContext.getFlowTypeName()))
                    .findFirst();
            if (flowConfigOpt.isPresent()) {
                Optional<AuthenticationStepConfig> stepConfOpt = flowConfigOpt.get().getStepConfigs().stream()
                        .filter(s -> currentStepId.equals(s.getStepId()))
                        .findFirst();
                if (stepConfOpt.isPresent()) {
                    factorType = stepConfOpt.get().getType();
                }
            }
            if (factorType == null) {
                log.error("Cannot determine factor type for verification. currentProcessingFactor is null and could not be derived from stepId {} in session {}", currentStepId, sessionId);
                throw new IllegalStateException("Factor type for verification cannot be determined. Session: " + sessionId + ", StepId: " + currentStepId);
            }
            log.warn("currentProcessingFactor was null for session {}, derived factorType {} from stepId {}", sessionId, factorType, currentStepId);
        }


        AuthenticationStepConfig completedStep = createCompletedStep(
                currentStepId,
                factorType, // 이제 factorType이 null이 아님을 보장 (위 로직)
                factorContext
        );

        factorContext.addCompletedFactor(completedStep); // addCompletedFactor는 내부적으로 버전 증가
        updateVerificationSuccess(factorContext, completedStep);
        factorContext.setRetryCount(0); // 해당 팩터에 대한 재시도 횟수 초기화
        factorContext.setAttribute("needsDetermineNextFactor", true);

        log.info("Factor {} (StepId: {}) verified successfully for session: {}", factorType, currentStepId, sessionId);
    }

    private AuthenticationStepConfig createCompletedStep(String stepId,
                                                         String factorType,
                                                         FactorContext factorContext) {
        PlatformConfig platformConfig = applicationContext.getBean(PlatformConfig.class);
        AuthenticationFlowConfig currentFlow = platformConfig.getFlows().stream()
                .filter(f -> f.getTypeName().equalsIgnoreCase(factorContext.getFlowTypeName()))
                .findFirst()
                .orElse(null);

        AuthenticationStepConfig originalStepConfig = null;
        if (currentFlow != null) {
            originalStepConfig = currentFlow.getStepConfigs().stream()
                    .filter(s -> stepId.equals(s.getStepId()))
                    .findFirst()
                    .orElse(null);
        }

        if (originalStepConfig == null) {
            log.warn("Original AuthenticationStepConfig not found for stepId '{}' in flow '{}'. Creating a default completed step. Session: {}",
                    stepId, factorContext.getFlowTypeName(), factorContext.getMfaSessionId());
            AuthenticationStepConfig fallbackStep = new AuthenticationStepConfig();
            fallbackStep.setStepId(stepId);
            fallbackStep.setType(factorType); // Ensure factorType is not null here
            fallbackStep.setOrder(factorContext.getCompletedFactors().size() + 1); // Approximate order
            fallbackStep.setRequired(true); // Default to required
            return fallbackStep;
        }

        AuthenticationStepConfig completed = new AuthenticationStepConfig();
        completed.setStepId(originalStepConfig.getStepId());
        completed.setType(originalStepConfig.getType()); // Use type from original config
        completed.setOrder(originalStepConfig.getOrder());
        completed.setRequired(originalStepConfig.isRequired());
        return completed;
    }

    private void updateVerificationSuccess(FactorContext factorContext,
                                           AuthenticationStepConfig completedStep) {
        factorContext.setAttribute(
                "lastVerificationTime_" + completedStep.getStepId(), // stepId를 사용해 더 고유하게
                LocalDateTime.now().toString()
        );

        Integer successCount = (Integer) factorContext.getAttribute("verificationSuccessCount");
        factorContext.setAttribute("verificationSuccessCount", (successCount == null ? 0 : successCount) + 1);
    }
}
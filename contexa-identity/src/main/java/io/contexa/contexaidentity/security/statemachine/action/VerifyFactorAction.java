package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class VerifyFactorAction extends AbstractMfaStateAction {

    private final PlatformConfig platformConfig;

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context, FactorContext factorContext){
        String sessionId = factorContext.getMfaSessionId();
        String currentStepId = factorContext.getCurrentStepId();

        log.info("Verifying factor for step: {} in session: {}", currentStepId, sessionId);

        String factorType = factorContext.getCurrentProcessingFactor() != null ?
                factorContext.getCurrentProcessingFactor().name() : null;
        if (factorType == null) {
            // currentStepId 로부터 factorType 추론 시도 (Robustness)
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
                String errorMsg = "Factor type for verification cannot be determined. Session: " + sessionId + ", StepId: " + currentStepId;
                log.error("Cannot determine factor type for verification. currentProcessingFactor is null and could not be derived from stepId {} in session {}", currentStepId, sessionId);
                factorContext.setLastError(errorMsg);
                factorContext.setAttribute(FactorContextAttributes.StateControl.ERROR_EVENT_RECOMMENDATION, MfaEvent.SYSTEM_ERROR);
                throw new IllegalStateException(errorMsg);
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

        log.info("Factor {} (StepId: {}) verified successfully for session: {}", factorType, currentStepId, sessionId);
    }

    private AuthenticationStepConfig createCompletedStep(String stepId,
                                                         String factorType,
                                                         FactorContext factorContext) {
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
        Integer successCount = (Integer) factorContext.getAttribute(FactorContextAttributes.StateControl.VERIFICATION_SUCCESS_COUNT);
        factorContext.setAttribute(FactorContextAttributes.StateControl.VERIFICATION_SUCCESS_COUNT, (successCount == null ? 0 : successCount) + 1);
    }
}
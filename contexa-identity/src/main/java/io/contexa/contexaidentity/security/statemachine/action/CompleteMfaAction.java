package io.contexa.contexaidentity.security.statemachine.action;

import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateContext;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class CompleteMfaAction extends AbstractMfaStateAction {

    @Override
    protected void doExecute(StateContext<MfaState, MfaEvent> context,
                             FactorContext factorContext) throws Exception {
        String sessionId = factorContext.getMfaSessionId();

        logCompletedFactors(factorContext);

        performCompletionTasks(factorContext);

        updateEventMetadata(context);

            }

    private void logCompletedFactors(FactorContext factorContext) {
        List<AuthenticationStepConfig> completedFactors = factorContext.getCompletedFactors();
        if (completedFactors != null && !completedFactors.isEmpty()) {
            String completedFactorTypes = completedFactors.stream()
                    .map(AuthenticationStepConfig::getType)
                    .collect(Collectors.joining(", "));
                    }
    }

    private void performCompletionTasks(FactorContext factorContext) {

    }

    private void updateEventMetadata(StateContext<MfaState, MfaEvent> context) {

    }
}
package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.CollectionUtils;

import java.util.List;

@Slf4j
public class MfaFlowStructureValidator implements Validator<AuthenticationFlowConfig> {

    @Override
    public ValidationResult validate(AuthenticationFlowConfig flow) {
        ValidationResult result = new ValidationResult();
        if (flow == null || !"mfa".equalsIgnoreCase(flow.getTypeName())) {
            return result;
        }

        String flowIdentifier = String.format("MFA Flow (type: '%s', order: %d)", flow.getTypeName(), flow.getOrder());

        List<AuthenticationStepConfig> steps = flow.getStepConfigs();
        if (CollectionUtils.isEmpty(steps)) {
            result.addError(String.format("Critical error: No authentication steps (stepConfigs) defined in %s. MFA flow must include primary authentication and at least one secondary authentication factor.", flowIdentifier));
            return result;
        }

        AuthenticationStepConfig firstStep = steps.get(0);
        if (firstStep.getOrder() != 0 ||
                ! ("mfa_form".equalsIgnoreCase(firstStep.getType()) || "mfa_rest".equalsIgnoreCase(firstStep.getType())) ) {
            result.addError(String.format("Critical error: The first authentication step of %s must be 'mfa_form' or 'mfa_rest' type with order 0. Current: type='%s', order=%d",
                    flowIdentifier, firstStep.getType(), firstStep.getOrder()));
        }

        if (steps.size() < 2) {
            result.addError(String.format("Critical error: %s requires at least one secondary authentication factor in addition to primary authentication. Current total steps: %d",
                    flowIdentifier, steps.size()));
        }

        if (result.hasErrors()){
            log.error("DSL VALIDATION ERROR for {}: {}", flowIdentifier, result.getErrors());
        }
        return result;
    }
}

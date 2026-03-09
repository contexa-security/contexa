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

        List<AuthenticationStepConfig> steps = flow.getStepConfigs();
        if (CollectionUtils.isEmpty(steps)) {
            return result;
        }

        String flowIdentifier = String.format("MFA Flow (type: '%s', order: %d)", flow.getTypeName(), flow.getOrder());

        AuthenticationStepConfig firstStep = steps.getFirst();
        if (firstStep.getOrder() != 0 ||
                !("mfa_form".equalsIgnoreCase(firstStep.getType()) || "mfa_rest".equalsIgnoreCase(firstStep.getType()))) {
            result.addError(String.format("The first authentication step of %s must be 'mfa_form' or 'mfa_rest' type with order 0. Current: type='%s', order=%d",
                    flowIdentifier, firstStep.getType(), firstStep.getOrder()));
            log.error("DSL VALIDATION ERROR for {}: {}", flowIdentifier, result.getErrors());
        }

        return result;
    }
}

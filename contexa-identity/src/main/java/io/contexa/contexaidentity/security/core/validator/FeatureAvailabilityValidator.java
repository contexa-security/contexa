package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.bootstrap.AdapterRegistry;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class FeatureAvailabilityValidator implements Validator<AuthenticationStepConfig> {

    private final AdapterRegistry adapterRegistry;

    @Override
    public ValidationResult validate(AuthenticationStepConfig step) {
        ValidationResult result = new ValidationResult();
        if (step == null || step.getType() == null) {
            result.addError("Critical error: Authentication step or step type is null. Please check DSL configuration.");
            return result;
        }

        String stepType = step.getType().toLowerCase();
        if (adapterRegistry.getAuthenticationAdapter(stepType) == null) {
            result.addError(String.format("Critical platform error: No AuthenticationFeature implementation registered in FeatureRegistry for authentication type '%s' defined in DSL. (Step order: %d)",
                    step.getType(), step.getOrder()));
            log.error("DSL VALIDATION ERROR: AuthenticationFeature not found for type '{}'", step.getType());
        }
        return result;
    }
}

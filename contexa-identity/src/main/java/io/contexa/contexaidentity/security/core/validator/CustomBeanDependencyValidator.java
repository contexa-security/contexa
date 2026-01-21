package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;

@Slf4j
@RequiredArgsConstructor
public class CustomBeanDependencyValidator implements Validator<AuthenticationStepConfig> {

    private final ApplicationContext applicationContext;

    @Override
    public ValidationResult validate(AuthenticationStepConfig step) {
        ValidationResult result = new ValidationResult();
        if (step == null || step.getOptions() == null) {
            return result;
        }

        String stepIdentifier = String.format("Step (type: '%s', order: %d)", step.getType(), step.getOrder());
        Object optionsObject = step.getOptions().get("_options");

        if (optionsObject instanceof AuthenticationProcessingOptions) {
            AuthenticationProcessingOptions processingOptions = (AuthenticationProcessingOptions) optionsObject;

        }

        return result;
    }
}
package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.exception.DslConfigurationException;

public class DslValidatorService {

    private final DslValidator dslValidator; 

    public DslValidatorService(DslValidator dslValidator) {
        this.dslValidator = dslValidator;
    }

    public void validate(PlatformConfig platformConfig, String dslSourceName) throws DslConfigurationException {
        if (platformConfig == null) {
            
            ValidationResult nullConfigResult = new ValidationResult();
            nullConfigResult.addError("PlatformConfig is null. Unable to load DSL configuration.");
            ValidationReportReporter.reportAndPotentiallyExit(nullConfigResult, dslSourceName);
            return; 
        }

        ValidationResult result = dslValidator.validate(platformConfig); 
        ValidationReportReporter.reportAndPotentiallyExit(result, dslSourceName);
    }
}

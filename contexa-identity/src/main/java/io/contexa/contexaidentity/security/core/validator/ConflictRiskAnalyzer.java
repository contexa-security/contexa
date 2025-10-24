package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.context.FlowContext;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

@Slf4j
public class ConflictRiskAnalyzer implements Validator<List<FlowContext>> {

    @Override
    public ValidationResult validate(List<FlowContext> flows) {
        return new ValidationResult();
    }
}


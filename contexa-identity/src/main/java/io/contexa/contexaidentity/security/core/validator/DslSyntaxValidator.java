package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.context.FlowContext;

import java.util.List;

public class DslSyntaxValidator implements Validator<List<FlowContext>> {
    @Override
    public ValidationResult validate(List<FlowContext> flows) {
        return new ValidationResult();
    }
}


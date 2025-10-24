package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.context.FlowContext;

import java.util.List;

/**
 * DSL 문법 수준 검증
 */
public class DslSyntaxValidator implements Validator<List<FlowContext>> {
    @Override
    public ValidationResult validate(List<FlowContext> flows) {
        return new ValidationResult();
    }
}


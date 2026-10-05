/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.security.xacml.pdp.evaluation;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.SpelNode;
import org.springframework.expression.spel.ast.Assign;
import org.springframework.expression.spel.ast.BeanReference;
import org.springframework.expression.spel.ast.ConstructorReference;
import org.springframework.expression.spel.ast.Indexer;
import org.springframework.expression.spel.ast.MethodReference;
import org.springframework.expression.spel.ast.PropertyOrFieldReference;
import org.springframework.expression.spel.ast.StringLiteral;
import org.springframework.expression.spel.ast.TypeReference;
import org.springframework.expression.spel.standard.SpelExpression;
import org.springframework.expression.spel.standard.SpelExpressionParser;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Save-time and load-time validation for policy condition expressions.
 *
 * <p>An expression is accepted only when it parses as SpEL and contains none of the constructs
 * that {@link PolicyExpressionSandbox} rejects at evaluation time: type references other than the
 * allowed {@code java.time} value types, constructor invocation, bean references, assignments,
 * and method or property names used to reach reflection, class loading or process execution.</p>
 */
public final class PolicyExpressionValidator {

    private static final SpelExpressionParser PARSER = new SpelExpressionParser();
    private static final Pattern STRING_PLACEHOLDER = Pattern.compile("%(\\d+\\$)?s");
    private static final Pattern NUMBER_PLACEHOLDER = Pattern.compile("%(\\d+\\$)?d");

    private PolicyExpressionValidator() {
    }

    /**
     * Rejects an expression that cannot be parsed or uses a forbidden construct.
     *
     * @throws UnsafePolicyExpressionException when the expression is rejected
     */
    public static void validate(String expression) {
        UnsafePolicyExpressionException violation = inspect(expression);
        if (violation != null) {
            throw violation;
        }
    }

    /**
     * Validates every condition expression of a policy.
     *
     * @throws UnsafePolicyExpressionException for the first rejected condition
     */
    public static void validatePolicy(Policy policy) {
        if (policy == null || policy.getRules() == null) {
            return;
        }
        for (PolicyRule rule : policy.getRules()) {
            if (rule == null || rule.getConditions() == null) {
                continue;
            }
            for (PolicyCondition condition : rule.getConditions()) {
                if (condition != null) {
                    validate(condition.getExpression());
                }
            }
        }
    }

    /**
     * Returns the rejection reason for an expression, or empty when the expression is acceptable.
     */
    public static Optional<String> findViolation(String expression) {
        return Optional.ofNullable(inspect(expression)).map(UnsafePolicyExpressionException::getReason);
    }

    /**
     * Returns the rejection reason for an already parsed expression, or empty when acceptable.
     */
    public static Optional<String> findViolation(Expression expression) {
        if (!(expression instanceof SpelExpression spelExpression)) {
            return Optional.of("Unsupported expression type");
        }
        return Optional.ofNullable(findForbiddenConstruct(spelExpression.getAST()));
    }

    /**
     * Validates a condition template whose parameters are filled with {@link String#format}.
     * Placeholders are replaced with literals before the template is checked.
     *
     * @throws UnsafePolicyExpressionException when the template is rejected
     */
    public static void validateTemplate(String template) {
        validate(fillPlaceholders(template));
    }

    /**
     * Returns the rejection reason for a condition template, or empty when acceptable.
     */
    public static Optional<String> findTemplateViolation(String template) {
        return findViolation(fillPlaceholders(template));
    }

    private static String fillPlaceholders(String template) {
        if (template == null) {
            return null;
        }
        String filled = STRING_PLACEHOLDER.matcher(template).replaceAll("'0'");
        filled = NUMBER_PLACEHOLDER.matcher(filled).replaceAll("0");
        return filled.replace("%%", "%");
    }

    private static UnsafePolicyExpressionException inspect(String expression) {
        if (expression == null || expression.isBlank()) {
            return new UnsafePolicyExpressionException(expression, "Expression is empty", true);
        }
        Expression parsed;
        try {
            parsed = PARSER.parseExpression(expression);
        } catch (RuntimeException e) {
            return new UnsafePolicyExpressionException(expression,
                    "Expression cannot be parsed: " + e.getMessage(), true);
        }
        return findViolation(parsed)
                .map(reason -> new UnsafePolicyExpressionException(expression, reason, false))
                .orElse(null);
    }

    private static String findForbiddenConstruct(SpelNode node) {
        if (node == null) {
            return null;
        }
        String violation = inspectNode(node);
        if (violation != null) {
            return violation;
        }
        for (int index = 0; index < node.getChildCount(); index++) {
            String childViolation = findForbiddenConstruct(node.getChild(index));
            if (childViolation != null) {
                return childViolation;
            }
        }
        return null;
    }

    private static String inspectNode(SpelNode node) {
        if (node instanceof TypeReference) {
            String ast = node.toStringAST();
            String typeName = ast.substring(2, ast.length() - 1);
            return PolicyExpressionSandbox.isAllowedTypeName(typeName)
                    ? null : "Type reference is not permitted: " + typeName;
        }
        if (node instanceof ConstructorReference) {
            return "Constructor invocation is not permitted";
        }
        if (node instanceof BeanReference) {
            return "Bean reference is not permitted: " + node.toStringAST();
        }
        if (node instanceof Assign) {
            return "Assignment is not permitted";
        }
        if (node instanceof MethodReference method && PolicyExpressionSandbox.isDeniedMethodName(method.getName())) {
            return "Method is not permitted: " + method.getName();
        }
        if (node instanceof PropertyOrFieldReference property
                && PolicyExpressionSandbox.isDeniedPropertyName(property.getName())) {
            return "Property is not permitted: " + property.getName();
        }
        if (node instanceof Indexer && node.getChildCount() > 0
                && node.getChild(0) instanceof StringLiteral literal) {
            String key = String.valueOf(literal.getLiteralValue().getValue());
            if (PolicyExpressionSandbox.isDeniedPropertyName(key)) {
                return "Property is not permitted: " + key;
            }
        }
        return null;
    }
}

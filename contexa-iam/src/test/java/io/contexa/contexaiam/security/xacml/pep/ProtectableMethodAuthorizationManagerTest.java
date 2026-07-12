/*
 * Copyright 2026 The Contexa Project
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.MethodPolicyPlan;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.util.List;
import java.util.function.Supplier;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ProtectableMethodAuthorizationManagerTest {

    private final SpelExpressionParser parser = new SpelExpressionParser();

    @Test
    void denyOverridesEvaluatesAllPolicies() {
        ProtectableMethodAuthorizationManager manager = manager(new MethodPolicyPlan(
                List.of(parser.parseExpression("true"), parser.parseExpression("false")),
                CombiningAlgorithm.DENY_OVERRIDES,
                NoPolicyDecision.PERMIT));

        assertThatThrownBy(() -> manager.protectable(() -> mock(Authentication.class), mock(MethodInvocation.class)))
                .isInstanceOf(AuthorizationDeniedException.class);
    }

    @Test
    void permitOverridesEvaluatesAllPolicies() {
        ProtectableMethodAuthorizationManager manager = manager(new MethodPolicyPlan(
                List.of(parser.parseExpression("false"), parser.parseExpression("true")),
                CombiningAlgorithm.PERMIT_OVERRIDES,
                NoPolicyDecision.PERMIT));

        assertThatCode(() -> manager.protectable(() -> mock(Authentication.class), mock(MethodInvocation.class)))
                .doesNotThrowAnyException();
    }

    @Test
    void missingPolicyUsesConfiguredPermit() {
        ProtectableMethodAuthorizationManager manager = manager(new MethodPolicyPlan(
                List.of(), CombiningAlgorithm.DENY_OVERRIDES, NoPolicyDecision.PERMIT));

        assertThatCode(() -> manager.protectable(() -> mock(Authentication.class), mock(MethodInvocation.class)))
                .doesNotThrowAnyException();
    }

    private ProtectableMethodAuthorizationManager manager(MethodPolicyPlan plan) {
        MethodSecurityExpressionHandler handler = mock(MethodSecurityExpressionHandler.class);
        StandardEvaluationContext context = new StandardEvaluationContext(new Object());
        context.setVariable("methodPolicyPlan", plan);
        when(handler.createEvaluationContext(ArgumentMatchers.<Supplier<Authentication>>any(),
                ArgumentMatchers.any(MethodInvocation.class))).thenReturn(context);
        return new ProtectableMethodAuthorizationManager(handler, new PolicyCombiningEvaluator());
    }
}

/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.MethodPolicyEvaluation;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.MethodPolicyMetadata;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.MethodPolicyPlan;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.Test;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MethodPolicyEvaluationTraceTest {

    @Test
    void recordsPolicyIdentityEffectPriorityResultAndFinalDecision() {
        SpelExpressionParser parser = new SpelExpressionParser();
        MethodPolicyPlan plan = new MethodPolicyPlan(
                List.of(parser.parseExpression("true"), parser.parseExpression("false")),
                CombiningAlgorithm.PERMIT_OVERRIDES,
                NoPolicyDecision.PERMIT,
                List.of(
                        new MethodPolicyMetadata(10L, Policy.Effect.ALLOW, 1),
                        new MethodPolicyMetadata(20L, Policy.Effect.DENY, 2)));
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("methodPolicyPlan", plan);
        MethodSecurityExpressionHandler handler = mock(MethodSecurityExpressionHandler.class);
        when(handler.createEvaluationContext(any(Supplier.class), any(MethodInvocation.class)))
                .thenReturn(context);

        new ProtectableMethodAuthorizationManager(handler, new PolicyCombiningEvaluator())
                .protectable(() -> mock(Authentication.class), mock(MethodInvocation.class));

        assertThat((List<MethodPolicyEvaluation>) context.lookupVariable("methodPolicyEvaluationTrace"))
                .containsExactly(
                        new MethodPolicyEvaluation(10L, Policy.Effect.ALLOW, 1, true),
                        new MethodPolicyEvaluation(20L, Policy.Effect.DENY, 2, false));
        assertThat(context.lookupVariable("methodPolicyFinalDecision")).isNotNull();
    }
}

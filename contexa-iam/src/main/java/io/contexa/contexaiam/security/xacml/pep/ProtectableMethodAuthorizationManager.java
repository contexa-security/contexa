/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.PolicyExpressionSandbox;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.MethodPolicyEvaluation;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.MethodPolicyMetadata;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.MethodPolicyPlan;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * Method policy enforcement point for {@code @Protectable} invocations.
 *
 * <p>Each plan expression is the policy condition. ALLOW policies yield Permit or Deny; DENY policies
 * yield Deny when the condition holds and NotApplicable otherwise. Policy expressions are evaluated in
 * a {@link PolicyExpressionSandbox} so database-stored conditions cannot reach reflection, class
 * loading, bean lookup or process execution.</p>
 */
@Slf4j
@RequiredArgsConstructor
public class ProtectableMethodAuthorizationManager {

    private final MethodSecurityExpressionHandler expressionHandler;
    private final PolicyCombiningEvaluator policyCombiningEvaluator;

    public void protectable(Supplier<Authentication> authentication, MethodInvocation mi) {
        EvaluationContext context = expressionHandler.createEvaluationContext(authentication, mi);
        Object value = context.lookupVariable("methodPolicyPlan");
        if (!(value instanceof MethodPolicyPlan plan)) {
            throw new AuthorizationDeniedException("Access is denied - method policy plan not found");
        }

        if (!plan.policyExpressions().isEmpty()) {
            restrict(context);
        }

        List<MethodPolicyEvaluation> trace = new ArrayList<>();
        // One entry per policy; null marks a NotApplicable DENY policy.
        List<AuthorizationDecision> decisions = new ArrayList<>();
        for (int index = 0; index < plan.policyExpressions().size(); index++) {
            boolean conditionSatisfied = ExpressionUtils.evaluateAsBoolean(
                    plan.policyExpressions().get(index), context);
            AuthorizationDecision decision = PolicyCombiningEvaluator.applyEffect(effectOf(plan, index), conditionSatisfied);
            decisions.add(decision);
            trace.add(toEvaluation(plan, index, decision));
        }

        AuthorizationDecision finalDecision = policyCombiningEvaluator.evaluate(
                decisions, plan.combiningAlgorithm(), plan.missingPolicyDecision());
        List<MethodPolicyEvaluation> immutableTrace = List.copyOf(trace);
        context.setVariable("methodPolicyEvaluationTrace", immutableTrace);
        context.setVariable("methodPolicyFinalDecision", finalDecision);
        String methodDescription = mi.getMethod() != null
                ? mi.getMethod().toGenericString() : "unknown";
        log.debug("Method policy evaluation: method={}, algorithm={}, policies={}, granted={}",
                methodDescription, plan.combiningAlgorithm(), immutableTrace, finalDecision.isGranted());

        if (!finalDecision.isGranted()) {
            throw new AuthorizationDeniedException("Access is denied by method policies: " + immutableTrace);
        }
    }

    private void restrict(EvaluationContext context) {
        if (!(context instanceof StandardEvaluationContext standardContext)) {
            throw new AuthorizationDeniedException(
                    "Access is denied - method policy evaluation context cannot be restricted");
        }
        PolicyExpressionSandbox.apply(standardContext);
    }

    private Policy.Effect effectOf(MethodPolicyPlan plan, int index) {
        return plan.policyMetadata().isEmpty() ? null : plan.policyMetadata().get(index).effect();
    }

    private MethodPolicyEvaluation toEvaluation(MethodPolicyPlan plan, int index,
                                                AuthorizationDecision decision) {
        boolean applicable = decision != null;
        boolean granted = applicable && decision.isGranted();
        if (plan.policyMetadata().isEmpty()) {
            return new MethodPolicyEvaluation(null, null, index, granted, applicable);
        }
        MethodPolicyMetadata metadata = plan.policyMetadata().get(index);
        return new MethodPolicyEvaluation(
                metadata.policyId(), metadata.effect(), metadata.priority(), granted, applicable);
    }
}

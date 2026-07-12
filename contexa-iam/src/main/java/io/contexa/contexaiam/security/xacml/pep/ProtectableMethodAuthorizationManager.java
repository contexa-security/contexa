/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.MethodPolicyEvaluation;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.MethodPolicyMetadata;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.MethodPolicyPlan;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

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

        List<MethodPolicyEvaluation> trace = new ArrayList<>();
        List<AuthorizationDecision> decisions = new ArrayList<>();
        for (int index = 0; index < plan.policyExpressions().size(); index++) {
            AuthorizationDecision decision = new AuthorizationDecision(
                    ExpressionUtils.evaluateAsBoolean(plan.policyExpressions().get(index), context));
            decisions.add(decision);
            trace.add(toEvaluation(plan, index, decision));
        }

        AuthorizationDecision finalDecision = decisions.isEmpty()
                ? new AuthorizationDecision(plan.missingPolicyDecision().isGranted())
                : policyCombiningEvaluator.evaluate(decisions, plan.combiningAlgorithm());
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

    private MethodPolicyEvaluation toEvaluation(MethodPolicyPlan plan, int index,
                                                AuthorizationDecision decision) {
        if (plan.policyMetadata().isEmpty()) {
            return new MethodPolicyEvaluation(null, null, index, decision.isGranted());
        }
        MethodPolicyMetadata metadata = plan.policyMetadata().get(index);
        return new MethodPolicyEvaluation(
                metadata.policyId(), metadata.effect(), metadata.priority(), decision.isGranted());
    }
}

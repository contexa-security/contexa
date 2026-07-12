/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import org.springframework.expression.Expression;

import java.util.List;

/** Immutable per-invocation plan for all executable database method policies. */
public record MethodPolicyPlan(
        List<Expression> policyExpressions,
        CombiningAlgorithm combiningAlgorithm,
        NoPolicyDecision missingPolicyDecision,
        List<MethodPolicyMetadata> policyMetadata) {

    public MethodPolicyPlan(List<Expression> policyExpressions,
                            CombiningAlgorithm combiningAlgorithm,
                            NoPolicyDecision missingPolicyDecision) {
        this(policyExpressions, combiningAlgorithm, missingPolicyDecision, List.of());
    }

    public MethodPolicyPlan {
        policyExpressions = List.copyOf(policyExpressions);
        policyMetadata = List.copyOf(policyMetadata);
        if (!policyMetadata.isEmpty() && policyMetadata.size() != policyExpressions.size()) {
            throw new IllegalArgumentException("Policy metadata and expression counts must match");
        }
    }
}

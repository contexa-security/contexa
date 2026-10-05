/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexaiam.domain.entity.policy.Policy;

/**
 * Auditable result of evaluating one database method policy.
 * {@code applicable} is false when a DENY policy condition was not satisfied (NotApplicable);
 * such a result is excluded from combining and {@code granted} is false.
 */
public record MethodPolicyEvaluation(
        Long policyId,
        Policy.Effect effect,
        int priority,
        boolean granted,
        boolean applicable) {

    public MethodPolicyEvaluation(Long policyId, Policy.Effect effect, int priority, boolean granted) {
        this(policyId, effect, priority, granted, true);
    }
}

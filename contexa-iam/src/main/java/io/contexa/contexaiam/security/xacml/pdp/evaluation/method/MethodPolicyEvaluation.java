/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexaiam.domain.entity.policy.Policy;

/** Auditable result of evaluating one database method policy. */
public record MethodPolicyEvaluation(
        Long policyId,
        Policy.Effect effect,
        int priority,
        boolean granted) {
}

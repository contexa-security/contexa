/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexaiam.domain.entity.policy.Policy;

/** Stable identity and ordering data for one executable method policy. */
public record MethodPolicyMetadata(Long policyId, Policy.Effect effect, int priority) {
}

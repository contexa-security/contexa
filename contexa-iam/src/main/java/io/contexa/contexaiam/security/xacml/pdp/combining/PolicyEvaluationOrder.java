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
package io.contexa.contexaiam.security.xacml.pdp.combining;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;

import java.util.Comparator;

/**
 * Which policies an enforcement point evaluates and in which order. The URL and method enforcement
 * points and the policy simulator share these rules, so a simulated decision walks the same
 * policies in the same order as an enforced one.
 */
public final class PolicyEvaluationOrder {

    private static final String METHOD_TARGET = "METHOD";

    private static final Comparator<Policy> URL_ORDER = Comparator.comparingInt(Policy::getPriority);

    private PolicyEvaluationOrder() {
    }

    /**
     * A policy takes part in enforcement only when it is active and approved or exempt from approval.
     */
    public static boolean isExecutable(Policy policy) {
        if (policy == null || !policy.getIsActive()) {
            return false;
        }
        Policy.ApprovalStatus status = policy.getApprovalStatus();
        return status == Policy.ApprovalStatus.APPROVED || status == Policy.ApprovalStatus.NOT_REQUIRED;
    }

    /**
     * URL enforcement order: ascending priority. Callers sort stably, so policies with the same
     * priority keep the order in which the policy retrieval point returned them.
     */
    public static Comparator<Policy> urlOrder() {
        return URL_ORDER;
    }

    /**
     * Method enforcement order for one method: the lowest order of the policy targets bound to the
     * method, then ascending priority, then ascending id with unsaved policies last.
     */
    public static Comparator<Policy> methodOrder(String methodIdentifier) {
        return Comparator.<Policy>comparingInt(policy -> lowestTargetOrder(policy, METHOD_TARGET, methodIdentifier))
                .thenComparingInt(Policy::getPriority)
                .thenComparing(Policy::getId, Comparator.nullsLast(Long::compareTo));
    }

    /**
     * Returns the lowest target order among the policy targets of the given type, restricted to the
     * given identifier when it is not {@code null}, or {@link Integer#MAX_VALUE} when there is none.
     */
    public static int lowestTargetOrder(Policy policy, String targetType, String targetIdentifier) {
        return policy.getTargets().stream()
                .filter(target -> targetType.equals(target.getTargetType()))
                .filter(target -> targetIdentifier == null || targetIdentifier.equals(target.getTargetIdentifier()))
                .mapToInt(PolicyTarget::getTargetOrder)
                .min()
                .orElse(Integer.MAX_VALUE);
    }
}

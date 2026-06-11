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
package io.contexa.contexaiam.admin.web.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.contexaiam.domain.entity.policy.Policy;

import java.util.List;

public final class AffectedPolicyDtos {

    private AffectedPolicyDtos() {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AffectedPoliciesResponse(
            String entityName,
            List<AffectedPolicyResponse> policies,
            int policyCount,
            Long roleCount
    ) {
        public static AffectedPoliciesResponse forPermission(
                String entityName,
                List<AffectedPolicyResponse> policies,
                long roleCount) {
            return new AffectedPoliciesResponse(entityName, policies, policies.size(), roleCount);
        }

        public static AffectedPoliciesResponse forRole(
                String entityName,
                List<AffectedPolicyResponse> policies) {
            return new AffectedPoliciesResponse(entityName, policies, policies.size(), null);
        }
    }

    public record AffectedPolicyResponse(
            Long id,
            String name,
            String effect,
            Boolean active
    ) {
        public static AffectedPolicyResponse from(Policy policy) {
            return new AffectedPolicyResponse(
                    policy.getId(),
                    policy.getName(),
                    policy.getEffect() != null ? policy.getEffect().name() : null,
                    policy.getIsActive()
            );
        }
    }
}

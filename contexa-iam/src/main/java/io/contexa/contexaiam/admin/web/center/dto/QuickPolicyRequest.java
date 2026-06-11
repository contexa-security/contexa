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
package io.contexa.contexaiam.admin.web.center.dto;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import lombok.Data;

import java.util.Set;

@Data
public class QuickPolicyRequest {
    private String policyName;
    private String description;
    private Set<Long> roleIds;
    private Set<Long> permissionIds;
    private Set<String> crudPermissions; // READ, WRITE, UPDATE, DELETE
    private Policy.Effect effect = Policy.Effect.ALLOW;

    // Manual target fields (used when sourceType = "MANUAL")
    private String manualTargetType;
    private String manualTargetIdentifier;
    private String manualHttpMethod;
    private int manualTargetOrder = 1;
    private String sourceType = "RESOURCE";  // RESOURCE or MANUAL

    // SpEL expression permission (mutually exclusive with roleIds/permissionIds)
    private Long spelId;
}

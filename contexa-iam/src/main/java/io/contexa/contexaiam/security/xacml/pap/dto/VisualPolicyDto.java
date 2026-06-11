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
package io.contexa.contexaiam.security.xacml.pap.dto;

import io.contexa.contexaiam.domain.entity.policy.Policy;

import java.util.Map;
import java.util.Set;

public record VisualPolicyDto(
        String name,
        String description,
        Policy.Effect effect,
        Set<SubjectIdentifier> subjects,
        Set<PermissionIdentifier> permissions,
        Set<ConditionIdentifier> conditions
) {
    public record SubjectIdentifier(Long id, String type) {}
    public record PermissionIdentifier(Long id) {}
    public record ConditionIdentifier(String conditionKey, Map<String, Object> params) {}
}

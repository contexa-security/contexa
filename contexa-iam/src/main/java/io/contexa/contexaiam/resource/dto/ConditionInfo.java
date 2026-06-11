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
package io.contexa.contexaiam.resource.dto;

import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.resource.service.CompatibilityResult;

public class ConditionInfo {
    public final Long id;
    public final String name;
    public final String description;
    public final ConditionTemplate.ConditionClassification classification;
    public final Integer complexityScore;
    public final Boolean approvalRequired;
    public final String compatibilityReason;

    public ConditionInfo(ConditionTemplate condition, CompatibilityResult result) {
        this.id = condition.getId();
        this.name = condition.getName();
        this.description = condition.getDescription();
        this.classification = condition.getClassification();
        this.complexityScore = condition.getComplexityScore();
        this.approvalRequired = condition.getApprovalRequired();
        this.compatibilityReason = result.getReason();
    }
} 
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
package io.contexa.contexaiam.domain.dto;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PolicyDto {
    private Long id;
    private String name;
    private String description;
    private Policy.Effect effect;
    private int priority;

    @Builder.Default
    private List<TargetDto> targets = new ArrayList<>();

    @Builder.Default
    private List<RuleDto> rules = new ArrayList<>();

    private Policy.PolicySource source;
    private Policy.ApprovalStatus approvalStatus;
    private Boolean isActive;

    private String friendlyDescription;
    private String approvedBy;
    private LocalDateTime approvedAt;
    private Double confidenceScore;
    private String aiModel;
    private String reasoning;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String changeReason;

    public boolean isAIGenerated() {
        return source == Policy.PolicySource.AI_GENERATED || source == Policy.PolicySource.AI_EVOLVED;
    }
}
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

import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
public class PolicyCenterPolicyRequest {
    private Long id;
    private String name;
    private String description;
    private String effect;
    private int priority;
    private List<TargetRequest> targets = new ArrayList<>();
    private List<RuleRequest> rules = new ArrayList<>();
    private String source;
    private String approvalStatus;
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

    public static PolicyCenterPolicyRequest emptyForForm() {
        PolicyCenterPolicyRequest request = new PolicyCenterPolicyRequest();
        request.getTargets().add(new TargetRequest());
        request.getRules().add(new RuleRequest());
        return request;
    }

    public PolicyDto toPolicyDto() {
        PolicyDto dto = new PolicyDto();
        dto.setId(id);
        dto.setName(name);
        dto.setDescription(description);
        dto.setEffect(enumValue(Policy.Effect.class, effect));
        dto.setPriority(priority);
        dto.setTargets(targets == null
                ? null
                : new ArrayList<>(targets.stream().map(TargetRequest::toTargetDto).toList()));
        dto.setRules(rules == null
                ? null
                : new ArrayList<>(rules.stream().map(RuleRequest::toRuleDto).toList()));
        dto.setSource(enumValue(Policy.PolicySource.class, source));
        dto.setApprovalStatus(enumValue(Policy.ApprovalStatus.class, approvalStatus));
        dto.setIsActive(isActive);
        dto.setFriendlyDescription(friendlyDescription);
        dto.setApprovedBy(approvedBy);
        dto.setApprovedAt(approvedAt);
        dto.setConfidenceScore(confidenceScore);
        dto.setAiModel(aiModel);
        dto.setReasoning(reasoning);
        dto.setCreatedAt(createdAt);
        dto.setUpdatedAt(updatedAt);
        dto.setChangeReason(changeReason);
        return dto;
    }

    private static <E extends Enum<E>> E enumValue(Class<E> enumType, String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return Enum.valueOf(enumType, value);
    }

    @Data
    public static class TargetRequest {
        private String targetType;
        private String targetIdentifier;
        private String httpMethod;
        private int targetOrder = 0;
        private String sourceType = "RESOURCE";

        private TargetDto toTargetDto() {
            return TargetDto.builder()
                    .targetType(targetType)
                    .targetIdentifier(targetIdentifier)
                    .httpMethod(httpMethod)
                    .targetOrder(targetOrder)
                    .sourceType(sourceType)
                    .build();
        }
    }

    @Data
    public static class RuleRequest {
        private String description;
        private List<ConditionRequest> conditions = new ArrayList<>();

        private RuleDto toRuleDto() {
            return RuleDto.builder()
                    .description(description)
                    .conditions(conditions == null
                            ? null
                            : new ArrayList<>(conditions.stream().map(ConditionRequest::toConditionDto).toList()))
                    .build();
        }
    }

    @Data
    public static class ConditionRequest {
        private String expression;
        private String authorizationPhase;

        private ConditionDto toConditionDto() {
            return ConditionDto.builder()
                    .expression(expression)
                    .authorizationPhase(enumValue(
                            PolicyCondition.AuthorizationPhase.class,
                            authorizationPhase))
                    .build();
        }
    }
}

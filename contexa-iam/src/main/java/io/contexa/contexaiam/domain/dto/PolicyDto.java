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

    public boolean isAIGenerated() {
        return source == Policy.PolicySource.AI_GENERATED || source == Policy.PolicySource.AI_EVOLVED;
    }
}
package io.contexa.contexaiam.resource.dto;

import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.resource.service.CompatibilityResult;


public class ConditionInfo {
    public final Long id;
    public final String name;
    public final String description;
    public final ConditionTemplate.ConditionClassification classification;
    public final ConditionTemplate.RiskLevel riskLevel;
    public final Integer complexityScore;
    public final Boolean approvalRequired;
    public final String compatibilityReason;

    public ConditionInfo(ConditionTemplate condition, CompatibilityResult result) {
        this.id = condition.getId();
        this.name = condition.getName();
        this.description = condition.getDescription();
        this.classification = condition.getClassification();
        this.riskLevel = condition.getRiskLevel();
        this.complexityScore = condition.getComplexityScore();
        this.approvalRequired = condition.getApprovalRequired();
        this.compatibilityReason = result.getReason();
    }
} 
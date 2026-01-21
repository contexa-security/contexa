package io.contexa.contexaiam.resource.dto;

import io.contexa.contexaiam.domain.entity.ConditionTemplate;

public class ClassificationUpdateRequest {
    public ConditionTemplate.ConditionClassification classification;
    public ConditionTemplate.RiskLevel riskLevel;
    public Boolean approvalRequired;
    public Boolean contextDependent;
    public Integer complexityScore;
} 
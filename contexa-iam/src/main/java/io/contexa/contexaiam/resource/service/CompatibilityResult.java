package io.contexa.contexaiam.resource.service;

import io.contexa.contexaiam.domain.entity.ConditionTemplate;

import java.util.Collections;
import java.util.Set;

/**
 * 호환성 검사 결과 클래스
 * SRP 준수: 호환성 결과 정보만 담당
 */
public class CompatibilityResult {
    private final boolean compatible;
    private final String reason;
    private final Set<String> missingVariables;
    private final Set<String> availableVariables;
    private final ConditionTemplate.ConditionClassification classification;
    private final boolean requiresAiValidation;

    public CompatibilityResult(boolean compatible, String reason, 
                             Set<String> missingVariables, Set<String> availableVariables,
                             ConditionTemplate.ConditionClassification classification,
                             boolean requiresAiValidation) {
        this.compatible = compatible;
        this.reason = reason;
        this.missingVariables = missingVariables != null ? missingVariables : Collections.emptySet();
        this.availableVariables = availableVariables != null ? availableVariables : Collections.emptySet();
        this.classification = classification;
        this.requiresAiValidation = requiresAiValidation;
    }

    public boolean isCompatible() { return compatible; }
    public String getReason() { return reason; }
    public Set<String> getMissingVariables() { return missingVariables; }
    public Set<String> getAvailableVariables() { return availableVariables; }
    public ConditionTemplate.ConditionClassification getClassification() { return classification; }
    public boolean requiresAiValidation() { return requiresAiValidation; }
} 
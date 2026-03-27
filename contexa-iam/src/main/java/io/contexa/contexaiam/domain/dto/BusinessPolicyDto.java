package io.contexa.contexaiam.domain.dto;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import lombok.Data;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Data
public class BusinessPolicyDto {
    private String policyName;
    private String description;
    private Set<Long> roleIds;
    private Set<Long> permissionIds;
    private Map<Long, List<String>> conditions;
    private boolean aiActionEnabled;
    private List<String> allowedActions;
    private String customConditionSpel;
    private Policy.Effect effect = Policy.Effect.ALLOW;

    // Manual target (when sourceType = "MANUAL")
    private String manualTargetType;
    private String manualTargetIdentifier;
    private String manualHttpMethod;
    private int manualTargetOrder = 1;
    private String sourceType = "RESOURCE";

    // AI metadata
    private String reasoning;
    private Double confidenceScore;
    private String aiModel;
    private Policy.PolicySource source;

    // SpEL expression permission (mutually exclusive with roleIds/permissionIds)
    private Long spelId;
}
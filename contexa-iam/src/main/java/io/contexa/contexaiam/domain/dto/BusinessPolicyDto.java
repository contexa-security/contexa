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

    
    private boolean conditional;

    
    private Map<Long, List<String>> conditions; 
    private boolean aiRiskAssessmentEnabled; 
    private double requiredTrustScore; 
    private String customConditionSpel; 
    private Policy.Effect effect = Policy.Effect.ALLOW; 
}
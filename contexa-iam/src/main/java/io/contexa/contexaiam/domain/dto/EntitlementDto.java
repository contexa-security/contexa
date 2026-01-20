package io.contexa.contexaiam.domain.dto;

import java.util.List;
import java.util.Map;


public record EntitlementDto(
        Long policyId,
        String subjectName,      
        String subjectType,      
        String resourceName,     
        List<String> actions,    
        List<String> conditions  
) {}


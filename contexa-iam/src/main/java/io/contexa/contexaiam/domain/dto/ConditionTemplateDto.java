package io.contexa.contexaiam.domain.dto;

import java.util.Set;

public record ConditionTemplateDto(
        Long id,
        String name,
        String description,
        Set<String> requiredVariables, 
        boolean isCompatible,          
        String spelTemplate           
) {}
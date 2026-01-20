package io.contexa.contexaiam.security.xacml.pap.dto;

import io.contexa.contexaiam.domain.dto.PolicyDto;


public record PolicyTemplateDto(
        String templateId,
        String name, 
        String description, 
        PolicyDto policyDraft 
) {}

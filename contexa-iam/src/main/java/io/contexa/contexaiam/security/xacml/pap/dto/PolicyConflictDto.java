package io.contexa.contexaiam.security.xacml.pap.dto;


public record PolicyConflictDto(
        Long newPolicyId,
        String newPolicyName, Long existingPolicyId,
        String existingPolicyName,
        String conflictDescription) {}

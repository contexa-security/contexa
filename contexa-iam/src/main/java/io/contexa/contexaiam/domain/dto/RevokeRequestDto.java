package io.contexa.contexaiam.domain.dto;

public record RevokeRequestDto(
        Long policyId,               
        String revokeReason          
) {}

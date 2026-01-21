package io.contexa.contexaiam.admin.web.studio.dto;

import io.contexa.contexaiam.domain.dto.PolicyDto;

public record SimulationRequestDto(
        ActionType actionType,
        PolicyDto policyDraft 
) {
    public enum ActionType {
        CREATE,
        UPDATE,
        DELETE
    }
}
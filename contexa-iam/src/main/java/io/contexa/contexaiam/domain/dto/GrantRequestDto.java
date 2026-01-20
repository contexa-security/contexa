package io.contexa.contexaiam.domain.dto;

import java.util.List;

public record GrantRequestDto(
        List<SubjectDto> subjects,
        List<Long> resourceIds,
        List<Long> actionIds, 
        String grantReason
) {
    public record SubjectDto(Long id, String type) {}
}

package io.contexa.contexaiam.domain.dto;

import java.util.List;

public record GrantRequestDto(
        List<SubjectDto> subjects,
        List<Long> resourceIds,
        List<Long> actionIds, // 이제 이름이 아닌 ID로 받음
        String grantReason
) {
    public record SubjectDto(Long id, String type) {}
}

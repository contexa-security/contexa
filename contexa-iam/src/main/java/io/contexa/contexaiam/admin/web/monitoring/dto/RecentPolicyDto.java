package io.contexa.contexaiam.admin.web.monitoring.dto;

import java.time.LocalDateTime;

public record RecentPolicyDto(
        Long id,
        String name,
        String effect,
        String source,
        String approvalStatus,
        LocalDateTime createdAt
) {}

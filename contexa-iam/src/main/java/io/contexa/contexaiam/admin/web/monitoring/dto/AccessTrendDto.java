package io.contexa.contexaiam.admin.web.monitoring.dto;

public record AccessTrendDto(
        String period,
        long allowCount,
        long denyCount,
        long totalCount
) {}

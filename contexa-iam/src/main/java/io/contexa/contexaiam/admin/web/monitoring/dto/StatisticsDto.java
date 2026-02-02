package io.contexa.contexaiam.admin.web.monitoring.dto;

public record StatisticsDto(
        long totalUsers,
        long totalGroups,
        long totalRoles,
        long totalPermissions,
        long totalPolicies,
        long activePolicies,
        long mfaEnabledUsers,
        long mfaDisabledUsers
) {}

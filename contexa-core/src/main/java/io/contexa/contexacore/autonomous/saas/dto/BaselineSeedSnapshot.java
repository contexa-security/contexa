package io.contexa.contexacore.autonomous.saas.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public record BaselineSeedSnapshot(
        String tenantId,
        boolean featureEnabled,
        boolean sharingEnabled,
        boolean seedAvailable,
        String cohortLabel,
        String industryCategory,
        String region,
        int cohortTenantCount,
        long sampleUserBaselineCount,
        List<Integer> topAccessHours,
        List<Integer> topAccessDays,
        List<String> topOperatingSystems,
        Map<String, Long> accessHoursDistribution,
        Map<String, Long> accessDaysDistribution,
        Map<String, Long> operatingSystemDistribution,
        LocalDate snapshotDate,
        LocalDateTime generatedAt) {

    public BaselineSeedSnapshot {
        topAccessHours = topAccessHours == null ? List.of() : List.copyOf(topAccessHours);
        topAccessDays = topAccessDays == null ? List.of() : List.copyOf(topAccessDays);
        topOperatingSystems = topOperatingSystems == null ? List.of() : List.copyOf(topOperatingSystems);
        accessHoursDistribution = accessHoursDistribution == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(accessHoursDistribution));
        accessDaysDistribution = accessDaysDistribution == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(accessDaysDistribution));
        operatingSystemDistribution = operatingSystemDistribution == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(operatingSystemDistribution));
    }

    public static BaselineSeedSnapshot empty() {
        return new BaselineSeedSnapshot(
                null,
                false,
                false,
                false,
                null,
                null,
                null,
                0,
                0L,
                List.of(),
                List.of(),
                List.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                null,
                null);
    }
}

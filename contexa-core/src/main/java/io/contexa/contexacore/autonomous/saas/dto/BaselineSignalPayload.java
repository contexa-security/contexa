package io.contexa.contexacore.autonomous.saas.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BaselineSignalPayload {

    private String signalId;
    private LocalDate periodStart;
    private String industryCategory;
    private long organizationBaselineCount;
    private long userBaselineCount;

    @Builder.Default
    private Map<String, Long> accessHoursDistribution = new LinkedHashMap<>();

    @Builder.Default
    private Map<String, Long> accessDaysDistribution = new LinkedHashMap<>();

    @Builder.Default
    private Map<String, Long> operatingSystemDistribution = new LinkedHashMap<>();

    private LocalDateTime generatedAt;
}

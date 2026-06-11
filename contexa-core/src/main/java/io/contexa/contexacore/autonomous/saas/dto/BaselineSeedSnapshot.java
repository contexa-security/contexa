/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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

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
package io.contexa.contexacore.autonomous.learning.evidence;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * A baseline as the decision evidence reads it.
 *
 * @param elementFrequencies how many learned requests held each value, by the baseline's own keys ({@code ip:},
 *                           {@code device:}, {@code auth:} and so on); empty when the baseline keeps none (W2-5)
 */
public record BaselineEvidenceSnapshot(
        LearningEvidenceScope scope,
        boolean available,
        boolean established,
        Long updateCount,
        Double averageTrustScore,
        List<String> networks,
        List<String> accessHours,
        List<String> accessDays,
        List<String> browsers,
        List<String> operatingSystems,
        List<String> pathFamilies,
        List<String> authenticationTypes,
        List<String> actionFamilies,
        List<String> resourceFamilies,
        String summary,
        BaselineEvidenceStatus status,
        String diagnostic,
        List<String> devices,
        Map<String, Long> elementFrequencies) {

    /** The snapshot without element frequencies, as before W2-5. */
    public BaselineEvidenceSnapshot(
            LearningEvidenceScope scope,
            boolean available,
            boolean established,
            Long updateCount,
            Double averageTrustScore,
            List<String> networks,
            List<String> accessHours,
            List<String> accessDays,
            List<String> browsers,
            List<String> operatingSystems,
            List<String> pathFamilies,
            List<String> authenticationTypes,
            List<String> actionFamilies,
            List<String> resourceFamilies,
            String summary,
            BaselineEvidenceStatus status,
            String diagnostic,
            List<String> devices) {
        this(scope, available, established, updateCount, averageTrustScore, networks, accessHours, accessDays, browsers,
                operatingSystems, pathFamilies, authenticationTypes, actionFamilies, resourceFamilies, summary, status,
                diagnostic, devices, Map.of());
    }

    /** The snapshot without device pairs, as before W2-4. */
    public BaselineEvidenceSnapshot(
            LearningEvidenceScope scope,
            boolean available,
            boolean established,
            Long updateCount,
            Double averageTrustScore,
            List<String> networks,
            List<String> accessHours,
            List<String> accessDays,
            List<String> browsers,
            List<String> operatingSystems,
            List<String> pathFamilies,
            List<String> authenticationTypes,
            List<String> actionFamilies,
            List<String> resourceFamilies,
            String summary,
            BaselineEvidenceStatus status,
            String diagnostic) {
        this(scope, available, established, updateCount, averageTrustScore, networks, accessHours, accessDays, browsers,
                operatingSystems, pathFamilies, authenticationTypes, actionFamilies, resourceFamilies, summary, status,
                diagnostic, List.of());
    }

    public BaselineEvidenceSnapshot {
        networks = immutable(networks);
        accessHours = immutable(accessHours);
        accessDays = immutable(accessDays);
        browsers = immutable(browsers);
        operatingSystems = immutable(operatingSystems);
        pathFamilies = immutable(pathFamilies);
        authenticationTypes = immutable(authenticationTypes);
        actionFamilies = immutable(actionFamilies);
        resourceFamilies = immutable(resourceFamilies);
        summary = summary == null ? "" : summary;
        status = status == null ? defaultStatus(available) : status;
        diagnostic = diagnostic == null ? "" : diagnostic;
        devices = immutable(devices);
        elementFrequencies = frequencies(elementFrequencies);
    }

    public BaselineEvidenceSnapshot(
            LearningEvidenceScope scope,
            boolean available,
            boolean established,
            Long updateCount,
            Double averageTrustScore,
            List<String> networks,
            List<String> accessHours,
            List<String> accessDays,
            List<String> browsers,
            List<String> operatingSystems,
            List<String> pathFamilies,
            List<String> authenticationTypes,
            List<String> actionFamilies,
            List<String> resourceFamilies,
            String summary) {
        this(
                scope,
                available,
                established,
                updateCount,
                averageTrustScore,
                networks,
                accessHours,
                accessDays,
                browsers,
                operatingSystems,
                pathFamilies,
                authenticationTypes,
                actionFamilies,
                resourceFamilies,
                summary,
                defaultStatus(available),
                "");
    }

    public boolean hasAnyObservedFacts() {
        return !networks.isEmpty()
                || !accessHours.isEmpty()
                || !accessDays.isEmpty()
                || !browsers.isEmpty()
                || !operatingSystems.isEmpty()
                || !pathFamilies.isEmpty()
                || !authenticationTypes.isEmpty()
                || !actionFamilies.isEmpty()
                || !resourceFamilies.isEmpty()
                || !devices.isEmpty();
    }

    public boolean indicatesUnavailableState() {
        return status != BaselineEvidenceStatus.AVAILABLE;
    }

    public String renderSummaryOrDiagnostic() {
        if (summary != null && !summary.isBlank()) {
            return summary;
        }
        if (diagnostic != null && !diagnostic.isBlank()) {
            return diagnostic;
        }
        return switch (status) {
            case AVAILABLE -> "";
            case NO_DATA -> "personal baseline unavailable";
            case SERVICE_UNAVAILABLE -> "baseline service unavailable";
            case MISSING_USER_ID -> "missing user identifier for baseline lookup";
            case ANALYSIS_UNAVAILABLE -> "baseline analysis unavailable";
        };
    }

    /**
     * The share, in whole percent, of the learned values of one dimension that held this value (its frequency over the
     * frequencies of the dimension's prefix), null when the snapshot carries no counts of the dimension (W5-10 D7).
     */
    public Integer sharePercent(String prefix, String value) {
        if (prefix == null || value == null || elementFrequencies == null) {
            return null;
        }
        long total = 0L;
        for (Map.Entry<String, Long> frequency : elementFrequencies.entrySet()) {
            if (frequency.getKey().startsWith(prefix) && frequency.getValue() != null) {
                total += frequency.getValue();
            }
        }
        if (total <= 0L) {
            return null;
        }
        Long held = elementFrequencies.get(prefix + value);
        return (int) Math.round((held != null ? held : 0L) * 100.0 / total);
    }

    private static Map<String, Long> frequencies(Map<String, Long> values) {
        Map<String, Long> sorted = new TreeMap<>();
        if (values != null) {
            values.forEach((key, count) -> {
                if (key != null && count != null) {
                    sorted.put(key, count);
                }
            });
        }
        return Collections.unmodifiableMap(sorted);
    }

    private static List<String> immutable(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    private static BaselineEvidenceStatus defaultStatus(boolean available) {
        return available ? BaselineEvidenceStatus.AVAILABLE : BaselineEvidenceStatus.NO_DATA;
    }
}

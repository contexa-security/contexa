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

import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;

import java.util.List;

public record ObservedPatternSnapshot(
        List<String> networks,
        List<String> accessHours,
        List<String> accessDays,
        List<String> browsers,
        List<String> operatingSystems,
        List<String> pathFamilies,
        List<String> authenticationTypes,
        List<String> actionFamilies,
        List<String> resourceFamilies,
        List<String> devices) {

    /** The patterns without device pairs, as before W2-4. */
    public ObservedPatternSnapshot(
            List<String> networks,
            List<String> accessHours,
            List<String> accessDays,
            List<String> browsers,
            List<String> operatingSystems,
            List<String> pathFamilies,
            List<String> authenticationTypes,
            List<String> actionFamilies,
            List<String> resourceFamilies) {
        this(networks, accessHours, accessDays, browsers, operatingSystems, pathFamilies, authenticationTypes,
                actionFamilies, resourceFamilies, List.of());
    }

    public ObservedPatternSnapshot {
        networks = immutable(networks);
        accessHours = immutable(accessHours);
        accessDays = immutable(accessDays);
        browsers = immutable(browsers);
        operatingSystems = immutable(operatingSystems);
        pathFamilies = immutable(pathFamilies);
        authenticationTypes = immutable(authenticationTypes);
        actionFamilies = immutable(actionFamilies);
        resourceFamilies = immutable(resourceFamilies);
        devices = immutable(devices);
    }

    /**
     * Whether the patterns hold the request's device (W2-4): by the learned device pairs when there are any, else by
     * the browser and the system one by one, as the baselines learned before device pairs allow. Null when the
     * request has no device or nothing compares with it.
     */
    public Boolean holdsDevice(String browser, String operatingSystem) {
        return holdsDevice(devices, browsers, operatingSystems, browser, operatingSystem);
    }

    /** The rule of {@link #holdsDevice(String, String)} for patterns given dimension by dimension. */
    public static Boolean holdsDevice(
            List<String> devices,
            List<String> browsers,
            List<String> operatingSystems,
            String browser,
            String operatingSystem) {
        String device = SecuritySemanticNormalizer.device(browser, operatingSystem);
        if (device == null) {
            return null;
        }
        if (devices != null && !devices.isEmpty()) {
            return SecuritySemanticNormalizer.deviceSeen(devices, device);
        }
        String system = SecuritySemanticNormalizer.normalizeOperatingSystem(operatingSystem);
        boolean browserComparable = browsers != null && !browsers.isEmpty();
        boolean systemComparable = system != null && operatingSystems != null && !operatingSystems.isEmpty();
        if (!browserComparable && !systemComparable) {
            return null;
        }
        boolean browserSeen = !browserComparable || browsers.stream()
                .anyMatch(value -> value != null && value.trim().equalsIgnoreCase(browser.trim()));
        boolean systemSeen = !systemComparable || operatingSystems.stream()
                .anyMatch(value -> system.equals(SecuritySemanticNormalizer.normalizeOperatingSystem(value)));
        return browserSeen && systemSeen;
    }

    private static List<String> immutable(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}

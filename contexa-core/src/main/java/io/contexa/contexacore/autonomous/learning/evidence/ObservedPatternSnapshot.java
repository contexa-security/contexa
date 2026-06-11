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
        List<String> resourceFamilies) {

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
    }

    private static List<String> immutable(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}

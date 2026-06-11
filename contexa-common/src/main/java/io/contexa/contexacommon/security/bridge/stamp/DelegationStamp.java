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
package io.contexa.contexacommon.security.bridge.stamp;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public record DelegationStamp(
        String subjectId,
        String agentId,
        boolean delegated,
        String objectiveId,
        String objectiveFamily,
        String objectiveSummary,
        List<String> allowedOperations,
        List<String> allowedResources,
        Boolean approvalRequired,
        Boolean privilegedExportAllowed,
        Boolean containmentOnly,
        Instant expiresAt,
        Map<String, Object> attributes
) {

    public DelegationStamp {
        allowedOperations = allowedOperations == null ? List.of() : List.copyOf(new LinkedHashSet<>(allowedOperations));
        allowedResources = allowedResources == null ? List.of() : List.copyOf(new LinkedHashSet<>(allowedResources));
        attributes = attributes == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(attributes));
    }

    public DelegationStamp(
            String subjectId,
            String agentId,
            boolean delegated,
            String objectiveId,
            String objectiveSummary,
            List<String> allowedOperations,
            List<String> allowedResources,
            Boolean approvalRequired,
            Boolean containmentOnly,
            Instant expiresAt,
            Map<String, Object> attributes) {
        this(
                subjectId,
                agentId,
                delegated,
                objectiveId,
                null,
                objectiveSummary,
                allowedOperations,
                allowedResources,
                approvalRequired,
                null,
                containmentOnly,
                expiresAt,
                attributes);
    }
}

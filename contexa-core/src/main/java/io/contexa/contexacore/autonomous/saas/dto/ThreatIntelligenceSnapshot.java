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

import java.time.LocalDateTime;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ThreatIntelligenceSnapshot(
        String tenantId,
        boolean featureEnabled,
        boolean sharingEnabled,
        List<ThreatSignalItem> signals,
        LocalDateTime generatedAt) {

    public ThreatIntelligenceSnapshot {
        signals = signals == null ? List.of() : List.copyOf(signals);
    }

    public static ThreatIntelligenceSnapshot empty() {
        return new ThreatIntelligenceSnapshot(null, false, false, List.of(), null);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ThreatSignalItem(
            String signalKey,
            String status,
            String canonicalThreatClass,
            String geoCountry,
            List<String> mitreTacticHints,
            List<String> targetSurfaceHints,
            List<String> signalTags,
            int affectedTenantCount,
            int observationCount,
            LocalDateTime firstObservedAt,
            LocalDateTime lastObservedAt,
            LocalDateTime expiresAt,
            String summary) {

        public ThreatSignalItem {
            mitreTacticHints = mitreTacticHints == null ? List.of() : List.copyOf(mitreTacticHints);
            targetSurfaceHints = targetSurfaceHints == null ? List.of() : List.copyOf(targetSurfaceHints);
            signalTags = signalTags == null ? List.of() : List.copyOf(signalTags);
        }
    }
}

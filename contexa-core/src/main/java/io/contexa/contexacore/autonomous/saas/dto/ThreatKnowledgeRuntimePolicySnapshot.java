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
public record ThreatKnowledgeRuntimePolicySnapshot(
        String tenantId,
        boolean featureEnabled,
        boolean sharingEnabled,
        boolean runtimeAllowed,
        boolean killSwitchActive,
        String policyState,
        long approvedArtifactCount,
        long withdrawnArtifactCount,
        long reviewOnlyArtifactCount,
        List<ArtifactPolicyItem> artifacts,
        LocalDateTime generatedAt) {

    public ThreatKnowledgeRuntimePolicySnapshot {
        artifacts = artifacts == null ? List.of() : List.copyOf(artifacts);
    }

    public static ThreatKnowledgeRuntimePolicySnapshot empty() {
        return new ThreatKnowledgeRuntimePolicySnapshot(
                null,
                false,
                false,
                false,
                false,
                "DISABLED",
                0,
                0,
                0,
                List.of(),
                null);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ArtifactPolicyItem(
            String signalKey,
            String knowledgeKey,
            String artifactVersion,
            String governanceState,
            String tevvState,
            String rollbackState,
            boolean runtimeApproved,
            boolean withdrawn,
            String deploymentAction,
            List<String> policyFacts,
            String summary) {

        public ArtifactPolicyItem {
            policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
        }
    }
}

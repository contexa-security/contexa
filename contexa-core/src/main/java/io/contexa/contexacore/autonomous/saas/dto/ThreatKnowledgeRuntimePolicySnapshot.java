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

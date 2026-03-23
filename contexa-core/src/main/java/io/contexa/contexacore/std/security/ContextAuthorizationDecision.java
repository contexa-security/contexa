package io.contexa.contexacore.std.security;

import java.util.List;

public record ContextAuthorizationDecision(
        boolean allowed,
        String decision,
        boolean purposeMatch,
        String sourceType,
        String accessScope,
        boolean tenantBound,
        String artifactId,
        String artifactVersion,
        String provenanceSummary,
        ContextProvenanceRecord provenanceRecord,
        String promptSafetyDecision,
        List<String> promptSafetyFlags,
        String promptQuarantineState,
        String memoryReadDecision,
        String knowledgeQuarantineState,
        String knowledgeIncidentSummary,
        List<String> knowledgeIncidentFacts,
        String runtimeText) {

    public ContextAuthorizationDecision {
        promptSafetyFlags = promptSafetyFlags == null ? List.of() : List.copyOf(promptSafetyFlags);
        knowledgeIncidentFacts = knowledgeIncidentFacts == null ? List.of() : List.copyOf(knowledgeIncidentFacts);
    }
}

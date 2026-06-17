package io.contexa.contexaiam.admin.promptquality.official.domain;

import java.util.List;
import java.util.Map;

public record ContextEvidenceBundle(
        String bundleId,
        String sourceType,
        String sourceLabel,
        String tenantId,
        String subjectUserId,
        String resourceUrl,
        String resourceId,
        String httpMethod,
        Map<String, Object> sourceRequestContext,
        List<Map<String, Object>> learnedContexts,
        Map<String, Object> currentRequestContext,
        Map<String, Object> finalPromptEvidence,
        String readinessState,
        String readinessSummary,
        List<String> findings,
        List<ContextEvidenceFinding> findingDetails,
        String createdAt) {

    public ContextEvidenceBundle {
        findingDetails = findingDetails == null ? List.of() : List.copyOf(findingDetails);
    }

    public boolean readyForPromptVerification() {
        return "READY".equalsIgnoreCase(readinessState)
                && sourceRequestContext != null && !sourceRequestContext.isEmpty()
                && learnedContexts != null && !learnedContexts.isEmpty()
                && currentRequestContext != null && !currentRequestContext.isEmpty()
                && finalPromptEvidence != null && !finalPromptEvidence.isEmpty();
    }
}

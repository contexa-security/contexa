package io.contexa.contexacore.std.security;

import lombok.Builder;

@Builder
public record AuthorizedPromptContextItem(
        String contextType,
        String sourceType,
        String artifactId,
        String artifactVersion,
        String authorizationDecision,
        boolean purposeMatch,
        String provenanceSummary,
        boolean includedInPrompt,
        String promptSafetyDecision,
        String memoryReadDecision,
        String accessScope,
        boolean tenantBound,
        Double similarityScore) {
}

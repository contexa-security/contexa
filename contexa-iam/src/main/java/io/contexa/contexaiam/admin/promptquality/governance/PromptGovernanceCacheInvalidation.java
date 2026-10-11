package io.contexa.contexaiam.admin.promptquality.governance;

public record PromptGovernanceCacheInvalidation(
        String eventId,
        String registryScope,
        String promptKey,
        String promptVersion,
        String reason,
        String publishedBy,
        String publishedAt,
        boolean consumed
) {
}

package io.contexa.contexaiam.admin.promptquality.inspection;

import java.util.Optional;

/** The prompt release registry as the bundle trace check reads it: one release by its identity. */
@FunctionalInterface
public interface PromptReleaseLookup {

    /**
     * A release of the registry.
     *
     * @param approvalReference the reference of the release approval, null when the release has none
     * @param releaseStatus     the release state now; it says nothing of the state when a prompt was sealed
     */
    record PromptRelease(String promptVersion, String contractVersion, String artifactHash, String approvalReference,
                         String releaseStatus) {
    }

    Optional<PromptRelease> find(String registryScope, String promptKey, String templateKey, String promptVersion);
}

package io.contexa.contexaiam.admin.promptquality.governance;


import java.util.List;

public interface PromptGovernanceRuntimeCacheInvalidationService {

    PromptGovernanceCacheInvalidation publish(
            String registryScope,
            String promptKey,
            String promptVersion,
            String reason,
            String publishedBy);

    List<PromptGovernanceCacheInvalidation> recentInvalidations(int limit);
}

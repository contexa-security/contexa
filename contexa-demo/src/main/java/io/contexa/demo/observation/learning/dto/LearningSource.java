package io.contexa.demo.observation.learning.dto;

import java.util.UUID;

public record LearningSource(UUID invocationId, UUID requestId, String eventId, String processingGeneration,
        String username, String nativeAction) {
}

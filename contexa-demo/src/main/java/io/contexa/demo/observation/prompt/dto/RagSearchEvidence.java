package io.contexa.demo.observation.prompt.dto;

public record RagSearchEvidence(
        String sourceBoundary,
        String state,
        Boolean searchExecuted,
        Integer queryCount,
        Integer candidateCount,
        Integer authorizedCount,
        Integer deniedCount,
        Boolean projectedToPrompt) {
}

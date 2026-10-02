package io.contexa.demo.observation.prompt.dto;

public record SessionHistoryEvidence(
        Integer requestCount,
        Integer sessionAgeMinutes,
        String authenticationMethod) {
}

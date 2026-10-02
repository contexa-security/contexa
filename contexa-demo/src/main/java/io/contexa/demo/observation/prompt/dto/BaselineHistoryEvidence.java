package io.contexa.demo.observation.prompt.dto;

public record BaselineHistoryEvidence(
        boolean personalAvailable,
        boolean personalEstablished,
        boolean organizationAvailable,
        boolean organizationEstablished,
        Long updateCount) {
}

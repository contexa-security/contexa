package io.contexa.demo.comparison.variation.dto;

public record ConditionDelta(String arm, String condition, String provenance, String state,
        String previousSha256, String currentSha256) {
}

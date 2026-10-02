package io.contexa.demo.comparison.history.dto;

public record HistorySequenceFingerprint(String state, Integer observedEntries, int readLimit, String sha256) {
}

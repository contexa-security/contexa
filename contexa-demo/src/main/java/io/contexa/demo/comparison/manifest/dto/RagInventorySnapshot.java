package io.contexa.demo.comparison.manifest.dto;

import java.time.Instant;

public record RagInventorySnapshot(String state, String source, Instant capturedAt, Integer documentsObserved,
        int documentLimit, String inventorySha256, String scope) {
}

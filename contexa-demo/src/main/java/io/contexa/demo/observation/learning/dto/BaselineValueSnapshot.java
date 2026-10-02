package io.contexa.demo.observation.learning.dto;

import java.time.Instant;

public record BaselineValueSnapshot(String state, String sha256, Long updates, Instant lastUpdated) {
}

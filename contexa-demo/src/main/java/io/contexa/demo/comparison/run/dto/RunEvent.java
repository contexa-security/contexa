package io.contexa.demo.comparison.run.dto;

import java.time.Instant;
import java.util.UUID;

public record RunEvent(long sequence, UUID stepId, String kind, Instant occurredAt, String detail) {
}

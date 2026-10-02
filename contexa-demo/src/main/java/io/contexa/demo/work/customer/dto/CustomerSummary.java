package io.contexa.demo.work.customer.dto;

import io.contexa.demo.work.shared.dto.WorkText;

import java.time.Instant;

public record CustomerSummary(
        String id,
        int version,
        String projectId,
        WorkText name,
        WorkText industry,
        WorkText region,
        String sensitivity,
        Instant updatedAt) {
}

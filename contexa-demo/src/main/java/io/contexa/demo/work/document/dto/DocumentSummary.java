package io.contexa.demo.work.document.dto;

import io.contexa.demo.work.shared.dto.WorkText;

import java.time.Instant;

public record DocumentSummary(
        String id,
        int version,
        String projectId,
        WorkText title,
        WorkText summary,
        String sensitivity,
        String author,
        Instant updatedAt
) {
}

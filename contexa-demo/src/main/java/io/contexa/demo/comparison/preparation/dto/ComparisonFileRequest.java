package io.contexa.demo.comparison.preparation.dto;

import io.contexa.demo.work.download.dto.DocumentLanguage;

import java.util.UUID;

public record ComparisonFileRequest(UUID commandId, DocumentLanguage language) {
}

package io.contexa.demo.work.document.dto;

import io.contexa.demo.work.shared.dto.WorkText;

public record DocumentBody(DocumentSummary summary, WorkText content) {
}

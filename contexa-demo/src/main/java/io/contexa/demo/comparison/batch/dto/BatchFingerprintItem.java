package io.contexa.demo.comparison.batch.dto;

import io.contexa.demo.work.shared.dto.WorkText;

public record BatchFingerprintItem(String id, String state, Integer version, String projectId,
        WorkText title, String sourceSha256) {
}

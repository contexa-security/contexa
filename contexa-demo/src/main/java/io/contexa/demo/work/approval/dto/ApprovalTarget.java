package io.contexa.demo.work.approval.dto;

import io.contexa.demo.work.shared.dto.WorkText;

public record ApprovalTarget(
        String id,
        int version,
        String projectId,
        WorkText label) {
}

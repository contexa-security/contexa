package io.contexa.demo.work.project.dto;

import io.contexa.demo.work.shared.dto.WorkText;

public record ProjectView(
        String id,
        String code,
        WorkText title,
        WorkText summary,
        String department,
        boolean assigned,
        int documentCount
) {
}

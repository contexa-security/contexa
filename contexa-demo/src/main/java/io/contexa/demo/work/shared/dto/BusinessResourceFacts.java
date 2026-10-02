package io.contexa.demo.work.shared.dto;

import java.util.List;

public record BusinessResourceFacts(
        String id,
        String type,
        String label,
        String sensitivity,
        String projectId,
        int version,
        List<String> allowedActions) {

    public BusinessResourceFacts {
        allowedActions = List.copyOf(allowedActions);
    }
}

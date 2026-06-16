package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record PromptQualityStateDescriptor(
        String dimension,
        String processStage,
        String code,
        String label,
        String tone,
        String aggregateGroup,
        List<String> allowedActions,
        String nextAction,
        int order) {
}


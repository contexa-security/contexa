package io.contexa.contexacore.verification.runtime.prompt;

import java.util.List;

public record FinalPromptSemanticGroup(
        String section,
        String groupKey,
        String groupLabel,
        int startLineNumber,
        int endLineNumber,
        List<String> fieldLabels,
        List<String> bulletTexts,
        List<String> narrativeTexts,
        String securityRelevance,
        String attackSignalRole
) {

    public FinalPromptSemanticGroup {
        fieldLabels = fieldLabels == null ? List.of() : List.copyOf(fieldLabels);
        bulletTexts = bulletTexts == null ? List.of() : List.copyOf(bulletTexts);
        narrativeTexts = narrativeTexts == null ? List.of() : List.copyOf(narrativeTexts);
    }
}

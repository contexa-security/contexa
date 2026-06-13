package io.contexa.contexacore.verification.runtime.prompt;

import java.util.List;

public record FinalPromptIssue(
        String issueKey,
        String promptSection,
        String promptLabel,
        String promptValueExcerpt,
        String reason,
        String remediation,
        List<String> metricCodes
) {

    public FinalPromptIssue {
        metricCodes = metricCodes == null ? List.of() : List.copyOf(metricCodes);
    }
}

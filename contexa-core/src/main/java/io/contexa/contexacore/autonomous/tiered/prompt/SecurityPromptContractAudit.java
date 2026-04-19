package io.contexa.contexacore.autonomous.tiered.prompt;

import java.util.List;
import java.util.Map;

public record SecurityPromptContractAudit(
        Map<String, Object> renderedRequestSnapshot,
        Map<String, Object> renderedLearningSnapshot,
        Map<String, Object> renderedLabelMatrix,
        Map<String, Integer> compactedLineCountBySection,
        List<String> violations) {
}

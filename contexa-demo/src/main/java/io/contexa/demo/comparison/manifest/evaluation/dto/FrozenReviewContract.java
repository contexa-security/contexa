package io.contexa.demo.comparison.manifest.evaluation.dto;

import java.util.List;

public record FrozenReviewContract(
        String version,
        String applicablePlan,
        List<EvidenceReviewRule> rules,
        String missingSourceMeaning,
        String securityEffectivenessVerdict,
        boolean transmittedToModel
) {
}

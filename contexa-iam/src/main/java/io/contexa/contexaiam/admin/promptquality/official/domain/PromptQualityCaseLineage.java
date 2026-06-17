package io.contexa.contexaiam.admin.promptquality.official.domain;

import java.util.List;

public record PromptQualityCaseLineage(
        PromptQualityAssuranceCase assuranceCase,
        List<PromptQualityAssuranceStage> stages) {

    public PromptQualityCaseLineage {
        stages = stages == null ? List.of() : List.copyOf(stages);
    }
}

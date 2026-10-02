package io.contexa.demo.comparison.variation.dto;

import java.util.List;
import java.util.UUID;

public record RunVariation(UUID parentRunId, String parentManifestSha256, List<ConditionDelta> conditions,
        String interpretation, String inputBoundary) {
}

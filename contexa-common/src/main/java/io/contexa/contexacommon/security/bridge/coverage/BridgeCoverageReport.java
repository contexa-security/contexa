package io.contexa.contexacommon.security.bridge.coverage;

import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public record BridgeCoverageReport(
        BridgeCoverageLevel level,
        int score,
        Set<MissingBridgeContext> missingContexts,
        String summary,
        List<String> remediationHints
) {

    public BridgeCoverageReport {
        level = level == null ? BridgeCoverageLevel.NONE : level;
        missingContexts = missingContexts == null ? Set.of() : Set.copyOf(new LinkedHashSet<>(missingContexts));
        summary = summary == null ? "" : summary.trim();
        remediationHints = remediationHints == null ? List.of() : List.copyOf(new LinkedHashSet<>(remediationHints));
    }

    public String purpose() {
        return BridgeSemanticBoundaryPolicy.BRIDGE_COMPLETENESS_ONLY;
    }
}

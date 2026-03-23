package io.contexa.contexacommon.security.bridge.coverage;

import java.util.LinkedHashSet;
import java.util.Set;

public record BridgeCoverageReport(
        BridgeCoverageLevel level,
        int score,
        Set<MissingBridgeContext> missingContexts
) {

    public BridgeCoverageReport {
        level = level == null ? BridgeCoverageLevel.NONE : level;
        missingContexts = missingContexts == null ? Set.of() : Set.copyOf(new LinkedHashSet<>(missingContexts));
    }
}

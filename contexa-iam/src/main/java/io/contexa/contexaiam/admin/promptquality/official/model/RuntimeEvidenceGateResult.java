package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record RuntimeEvidenceGateResult(
        boolean passed,
        List<RuntimeEvidenceCheckResult> checks,
        List<String> findings,
        List<String> nextActions) {
}

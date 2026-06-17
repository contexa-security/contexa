package io.contexa.contexacore.verification.adjudication;

import java.util.List;

/**
 * Aggregated scorecard result with pass rate.
 */
public record ScorecardResult(
        String label,
        int checksRun,
        int checksPassed,
        double passRatePercent,
        List<ScorecardCheckResult> checks
) {

    public static ScorecardResult of(String label, List<ScorecardCheckResult> checks) {
        int total = checks.size();
        int passed = (int) checks.stream().filter(ScorecardCheckResult::passed).count();
        double rate = total > 0 ? (passed * 100.0) / total : 0.0;
        return new ScorecardResult(label, total, passed, rate, List.copyOf(checks));
    }
}

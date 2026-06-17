package io.contexa.contexacore.verification.adjudication;

/**
 * Result of a single scorecard check item.
 * Adapted from TDD source: OfficialVerificationPromptQualityScorecard.CheckResult
 */
public record ScorecardCheckResult(
        String label,
        boolean passed,
        String evidence
) {
}

package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationBmaExecutionService.BmaCheckResult;
import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationBmaExecutionService.RoundSnapshot;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class OfficialVerificationBmaCheckEvaluator {

    private static final int MIN_BEHAVIORAL_ROUNDS = 3;
    private final OfficialVerificationLongHorizonEvidenceValues values =
            new OfficialVerificationLongHorizonEvidenceValues();
    List<BmaCheckResult> buildChecks(List<RoundSnapshot> rounds) {
        List<BmaCheckResult> checks = new ArrayList<>();
        if (rounds.isEmpty()) {
            checks.add(check("baseline maturity rounds are captured", ">= 3", "0", false, "rounds"));
            return List.copyOf(checks);
        }

        checks.add(check(
                "round 1 baseline remains provisional",
                "true",
                Boolean.toString(provisionalBaseline(rounds.get(0))),
                provisionalBaseline(rounds.get(0)),
                "rounds[0].decisionOutbox.payload.workProfileSummary"
        ));

        for (int index = 1; index < rounds.size(); index++) {
            RoundSnapshot previous = rounds.get(index - 1);
            RoundSnapshot current = rounds.get(index);
            checks.add(check(
                    "round " + (index + 1) + " baseline context is present",
                    "true",
                    Boolean.toString(current.baselineContextPresent()),
                    current.baselineContextPresent(),
                    "rounds[" + index + "].decisionOutbox.payload.workProfileSummary"
            ));
            checks.add(check(
                    "round " + (index + 1) + " observation evidence does not regress",
                    ">=" + previous.observationCount(),
                    previous.observationCount() + " -> " + current.observationCount(),
                    observationEvidenceMaintained(previous, current),
                    "rounds[" + index + "].decisionOutbox.payload.workProfileSummary"
            ));
        }
        return List.copyOf(checks);
    }

    private BmaCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new BmaCheckResult(label, values.value(expected), values.value(actual), pass, source);
    }

    boolean relatedDocumentsNonDecreasing(List<RoundSnapshot> rounds) {
        for (int index = 1; index < rounds.size(); index++) {
            if (rounds.get(index).relatedDocumentsCount() < rounds.get(index - 1).relatedDocumentsCount()) {
                return false;
            }
        }
        return true;
    }

    boolean observationCountsNonDecreasing(List<RoundSnapshot> rounds) {
        for (int index = 1; index < rounds.size(); index++) {
            if (!observationEvidenceMaintained(rounds.get(index - 1), rounds.get(index))) {
                return false;
            }
        }
        return true;
    }

    private boolean observationEvidenceMaintained(RoundSnapshot previous, RoundSnapshot current) {
        if (previous == null || current == null) {
            return false;
        }
        if (current.observationCount() < 0) {
            return current.baselineContextPresent();
        }
        if (previous.observationCount() < 0) {
            return current.baselineContextPresent() && current.observationCount() > 0;
        }
        if (current.observationCount() >= previous.observationCount()) {
            return true;
        }
        return previous.baselineContextPresent()
                && current.baselineContextPresent()
                && current.observationCount() > 0;
    }

    boolean provisionalBaseline(RoundSnapshot round) {
        if (round == null) {
            return false;
        }
        String workProfileSummary = round.workProfileSummary();
        if (StringUtils.hasText(workProfileSummary)) {
            String normalizedSummary = workProfileSummary.toUpperCase(Locale.ROOT);
            if (normalizedSummary.contains("EVIDENCE STATE PROVISIONAL")) {
                return true;
            }
            if (normalizedSummary.contains("EVIDENCE STATE ESTABLISHED")
                    || normalizedSummary.contains("EVIDENCE STATE MATURE")) {
                return false;
            }
        }
        return !round.baselineContextPresent() || round.observationCount() <= 0;
    }

    String buildMessage(double score, List<RoundSnapshot> rounds) {
        if (rounds.size() < MIN_BEHAVIORAL_ROUNDS) {
            return "BMA could not capture enough repeated rounds to validate baseline maturity.";
        }
        if (score < 95.0d) {
            return "BMA detected immature or regressing baseline evidence across repeated enterprise rounds.";
        }
        return "BMA confirms that baseline evidence starts provisional and matures into observed work pattern context across repeated enterprise rounds.";
    }

}

package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationResult;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunLedgerConsistency;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

final class OfficialRunLedgerConsistencyEvaluator {

    private final int expectedMetricCount;
    private final OfficialRunMetricSummaryCalculator summaryCalculator;
    private final PromptQualityMessageResolver messageResolver;

    OfficialRunLedgerConsistencyEvaluator(
            int expectedMetricCount,
            OfficialRunMetricSummaryCalculator summaryCalculator,
            PromptQualityMessageResolver messageResolver) {
        this.expectedMetricCount = Math.max(expectedMetricCount, 0);
        this.summaryCalculator = Objects.requireNonNull(summaryCalculator, "summaryCalculator");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    OfficialRunLedgerConsistency evaluate(
            OfficialSealedEvidenceVerificationResult officialResult,
            List<OfficialVerificationMetricTrace> runs) {
        List<OfficialVerificationMetricTrace> safeRuns = runs == null ? List.of() : runs;
        int actualRunCount = safeRuns.size();
        int storedCheckRowCount = safeRuns.stream().mapToInt(this::storedCheckRowCount).sum();
        int declaredCheckCount = safeRuns.stream()
                .mapToInt(run -> run.checks() != null && !run.checks().isEmpty()
                        ? storedCheckRowCount(run)
                        : Math.max(run.totalChecks(), storedCheckRowCount(run)))
                .sum();
        int totalCheckCount = storedCheckRowCount;
        int missingSourceCheckCount = (int) safeRuns.stream()
                .flatMap(run -> run.checks().stream())
                .filter(check -> "MISSING_SOURCE".equals(normalize(check.source())))
                .count();
        int abstractSourceCheckCount = (int) safeRuns.stream()
                .flatMap(run -> run.checks().stream())
                .filter(check -> sourceNeedsDetail(check.source()))
                .count();
        int rawArtifactRunCount = (int) safeRuns.stream()
                .filter(run -> run.rawEvidence() != null && !run.rawEvidence().isEmpty())
                .count();
        int factBackedRunCount = (int) safeRuns.stream()
                .filter(run -> !run.requestFacts().isEmpty()
                        && !run.promptFacts().isEmpty()
                        && !run.analysisFacts().isEmpty())
                .count();
        boolean aggregateRunIdPresent = officialResult != null && StringUtils.hasText(officialResult.aggregateRunId());
        boolean metricCountMatched = expectedMetricCount == 0 || expectedMetricCount == actualRunCount;
        boolean checkCountMatched = declaredCheckCount == storedCheckRowCount;
        List<String> warnings = warnings(
                aggregateRunIdPresent, metricCountMatched, expectedMetricCount, actualRunCount,
                missingSourceCheckCount, abstractSourceCheckCount, checkCountMatched,
                declaredCheckCount, storedCheckRowCount, factBackedRunCount, rawArtifactRunCount);
        boolean ready = aggregateRunIdPresent
                && metricCountMatched
                && totalCheckCount > 0
                && checkCountMatched
                && missingSourceCheckCount == 0
                && abstractSourceCheckCount == 0
                && rawArtifactRunCount == actualRunCount
                && factBackedRunCount == actualRunCount;
        return new OfficialRunLedgerConsistency(
                expectedMetricCount, actualRunCount, metricCountMatched, totalCheckCount,
                declaredCheckCount, storedCheckRowCount, checkCountMatched,
                missingSourceCheckCount, abstractSourceCheckCount, rawArtifactRunCount,
                factBackedRunCount, aggregateRunIdPresent, ready, List.copyOf(warnings));
    }

    private List<String> warnings(
            boolean aggregateRunIdPresent,
            boolean metricCountMatched,
            int expectedMetricCount,
            int actualRunCount,
            int missingSourceCheckCount,
            int abstractSourceCheckCount,
            boolean checkCountMatched,
            int declaredCheckCount,
            int storedCheckRowCount,
            int factBackedRunCount,
            int rawArtifactRunCount) {
        List<String> warnings = new ArrayList<>();
        if (!aggregateRunIdPresent) {
            warnings.add(message("enterprise.pqa.officialRun.ledgerConsistency.warning.aggregateMissing"));
        }
        if (!metricCountMatched) {
            warnings.add(message("enterprise.pqa.officialRun.ledgerConsistency.warning.metricCountTpl",
                    expectedMetricCount, actualRunCount));
        }
        if (missingSourceCheckCount > 0 || abstractSourceCheckCount > 0) {
            warnings.add(message("enterprise.pqa.officialRun.ledgerConsistency.warning.sourceTpl",
                    missingSourceCheckCount + abstractSourceCheckCount));
        }
        if (!checkCountMatched) {
            warnings.add(message("enterprise.pqa.officialRun.ledgerConsistency.warning.checkCountTpl",
                    declaredCheckCount, storedCheckRowCount));
        }
        if (factBackedRunCount < actualRunCount) {
            warnings.add(message("enterprise.pqa.officialRun.ledgerConsistency.warning.factLedger"));
        }
        if (rawArtifactRunCount < actualRunCount) {
            warnings.add(message("enterprise.pqa.officialRun.ledgerConsistency.warning.rawArtifact"));
        }
        return warnings;
    }

    private int storedCheckRowCount(OfficialVerificationMetricTrace run) {
        if (run == null) {
            return 0;
        }
        if (run.checks() != null && !run.checks().isEmpty()) {
            return summaryCalculator.evaluatedChecks(run).size();
        }
        if (run.totalChecks() <= 0 || run.purposeEvidence() == null || run.purposeEvidence().isEmpty()) {
            return 0;
        }
        return (int) run.purposeEvidence().stream().filter(Objects::nonNull).count();
    }

    private boolean sourceNeedsDetail(String source) {
        String normalized = normalize(source);
        return !StringUtils.hasText(source)
                || "MISSING_SOURCE".equals(normalized)
                || "COREEVIDENCEREPLAY".equals(normalized)
                || "EVIDENCEREPLAY".equals(normalized);
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }
}
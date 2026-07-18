package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunAttemptSummary;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class OfficialRunAttemptSummaryFactory {

    private static final Set<String> PASS_STATES = Set.of("SUCCESS", "PASS", "PASSED");
    private static final Set<String> NOT_APPLICABLE_STATES = Set.of("NOT_APPLICABLE", "NOT_APPLICABLE_METRIC");

    private final OfficialRunDetailPresentation presentation;

    OfficialRunAttemptSummaryFactory(OfficialRunDetailPresentation presentation) {
        this.presentation = Objects.requireNonNull(presentation, "presentation");
    }

    List<OfficialRunAttemptSummary> summaries(
            List<OfficialVerificationRunView> runs,
            String latestAggregateRunId,
            String packageId,
            int expectedMetricCount) {
        if (runs == null || runs.isEmpty()) {
            return List.of();
        }
        Map<String, List<OfficialVerificationRunView>> byAggregate = new LinkedHashMap<>();
        for (OfficialVerificationRunView run : runs) {
            if (run != null) {
                byAggregate.computeIfAbsent(aggregateRunId(run), ignored -> new ArrayList<>()).add(run);
            }
        }
        List<AttemptGroup> groups = byAggregate.entrySet().stream()
                .map(entry -> group(entry.getKey(), packageId, entry.getValue(), latestAggregateRunId, expectedMetricCount))
                .sorted(Comparator.comparing(AttemptGroup::completedAt).thenComparing(AttemptGroup::aggregateRunId))
                .toList();
        List<OfficialRunAttemptSummary> result = new ArrayList<>();
        for (int i = 0; i < groups.size(); i++) {
            AttemptGroup group = groups.get(i);
            result.add(new OfficialRunAttemptSummary(
                    group.aggregateRunId(), group.packageId(), i + 1, group.startedAt(), group.completedAt(),
                    group.totalRunCount(), group.passedRunCount(), group.failedRunCount(),
                    group.state(), group.stateLabel(), group.latest()));
        }
        return List.copyOf(result);
    }

    String aggregateRunId(OfficialVerificationRunView run) {
        if (run == null) {
            return null;
        }
        String aggregateRunId = raw(run.rawEvidence(), "aggregateRunId");
        if (StringUtils.hasText(aggregateRunId)) {
            return aggregateRunId.trim();
        }
        String runId = run.runId();
        String metricCode = run.endpointKey();
        if (StringUtils.hasText(runId) && StringUtils.hasText(metricCode)) {
            String suffix = "-" + metricCode.trim().toLowerCase(Locale.ROOT);
            if (runId.toLowerCase(Locale.ROOT).endsWith(suffix)) {
                return runId.substring(0, runId.length() - suffix.length());
            }
        }
        return runId;
    }

    private AttemptGroup group(
            String aggregateRunId,
            String packageId,
            List<OfficialVerificationRunView> runs,
            String latestAggregateRunId,
            int expectedMetricCount) {
        List<OfficialVerificationRunView> safeRuns = runs == null
                ? List.of()
                : runs.stream().filter(Objects::nonNull).toList();
        int total = safeRuns.size();
        int passed = (int) safeRuns.stream().filter(run -> PASS_STATES.contains(normalize(run.state()))).count();
        int failed = (int) safeRuns.stream().filter(run -> failedState(run.state())).count();
        String state = total == 0 ? "PENDING" : failed == 0 && total >= expectedMetricCount ? "SUCCESS" : "FAILED";
        return new AttemptGroup(
                aggregateRunId, packageId, minTime(safeRuns), maxTime(safeRuns), total, passed, failed,
                state, presentation.stateLabel(state), same(aggregateRunId, latestAggregateRunId));
    }

    private String minTime(List<OfficialVerificationRunView> runs) {
        return runs.stream()
                .map(OfficialVerificationRunView::startedAt)
                .filter(StringUtils::hasText)
                .min(String::compareTo)
                .orElse("");
    }

    private String maxTime(List<OfficialVerificationRunView> runs) {
        return runs.stream()
                .map(run -> firstNonBlank(run.completedAt(), run.startedAt()))
                .filter(StringUtils::hasText)
                .max(String::compareTo)
                .orElse("");
    }

    private boolean failedState(String state) {
        String normalized = normalize(state);
        return StringUtils.hasText(normalized)
                && !PASS_STATES.contains(normalized)
                && !NOT_APPLICABLE_STATES.contains(normalized);
    }

    private boolean same(String left, String right) {
        return StringUtils.hasText(left) && StringUtils.hasText(right) && left.trim().equalsIgnoreCase(right.trim());
    }

    private String raw(Map<String, Object> raw, String key) {
        return raw == null || raw.get(key) == null ? null : String.valueOf(raw.get(key));
    }

    private String firstNonBlank(String... values) {
        if (values != null) {
            for (String value : values) {
                if (StringUtils.hasText(value)) {
                    return value.trim();
                }
            }
        }
        return "";
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private record AttemptGroup(
            String aggregateRunId,
            String packageId,
            String startedAt,
            String completedAt,
            int totalRunCount,
            int passedRunCount,
            int failedRunCount,
            String state,
            String stateLabel,
            boolean latest) {
    }
}
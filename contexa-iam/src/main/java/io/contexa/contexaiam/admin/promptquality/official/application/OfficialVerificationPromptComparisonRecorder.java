package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorFinding;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorRemediationGroup;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

final class OfficialVerificationPromptComparisonRecorder {

    private final OfficialVerificationPromptComparisonWriter writer;
    private final OfficialVerificationSnapshotQueryService queryService;
    private final OfficialActualPromptProblemNarrative problemNarrative;

    OfficialVerificationPromptComparisonRecorder(
            OfficialVerificationPromptComparisonWriter writer,
            OfficialVerificationSnapshotQueryService queryService,
            OfficialActualPromptProblemNarrative problemNarrative) {
        this.writer = writer;
        this.queryService = queryService;
        this.problemNarrative = problemNarrative;
    }

    void record(
            String aggregateRunId,
            String packageId,
            List<OfficialVerificationPromptComparison> comparisons,
            List<OfficialActualPromptProblem> problems) {
        Map<String, Links> linksByField = links(aggregateRunId);
        Map<String, OfficialActualPromptProblem> problemsByField = safeList(problems).stream()
                .filter(problem -> problem != null && StringUtils.hasText(problem.fieldKey()))
                .collect(Collectors.toMap(
                        problem -> problem.fieldKey().trim(), problem -> problem,
                        (left, right) -> left, LinkedHashMap::new));
        for (OfficialVerificationPromptComparison comparison : safeList(comparisons)) {
            if (comparison == null || !StringUtils.hasText(comparison.fieldKey())) {
                continue;
            }
            String fieldKey = comparison.fieldKey().trim();
            OfficialVerificationPromptComparison enriched = enrich(
                    fieldKey, comparison, problemsByField.get(fieldKey), linksByField.get(fieldKey));
            writer.insert(new OfficialVerificationPromptComparisonWriter.PromptComparisonCommand(
                    aggregateRunId, packageId, enriched,
                    problemNarrative.displayValue(enriched.sealedEvidenceValue()),
                    problemNarrative.displayValue(enriched.promptValue()),
                    problemNarrative.displayValue(enriched.officialFactValue())));
        }
    }

    private OfficialVerificationPromptComparison enrich(
            String fieldKey,
            OfficialVerificationPromptComparison comparison,
            OfficialActualPromptProblem problem,
            Links links) {
        return new OfficialVerificationPromptComparison(
                fieldKey,
                firstNonBlank(problem == null ? null : problem.promptLabel(), comparison.fieldLabel()),
                comparison.sealedEvidenceValue(),
                firstNonBlank(problem == null ? null : problem.promptValue(), comparison.promptValue()),
                firstNonBlank(problem == null ? null : problem.expectedState(), comparison.officialFactValue()),
                comparison.state(), comparison.stateLabel(),
                firstNonBlank(problem == null ? null : problem.whyItMatters(), comparison.meaning()),
                merged(comparison.metricCodes(), links == null ? List.of() : links.metricCodes),
                merged(comparison.checkCodes(), links == null ? List.of() : links.checkCodes),
                merged(comparison.findingIds(), links == null ? List.of() : links.findingIds),
                merged(comparison.issueIds(), links == null ? List.of() : links.issueIds),
                merged(comparison.remediationGroupIds(), links == null ? List.of() : links.groupIds),
                comparison.promptLocation(), comparison.evidenceSource(),
                firstNonBlank(comparison.recommendedOwner(), links == null ? null : links.firstOwner()),
                firstNonBlank(comparison.canonicalSource(), "PROMPT_COMPARISON"));
    }

    private Map<String, Links> links(String aggregateRunId) {
        Map<String, Links> result = new LinkedHashMap<>();
        for (OperatorFinding finding : queryService.findings(aggregateRunId)) {
            String fieldKey = safe(finding.comparisonFieldKey());
            if (!StringUtils.hasText(fieldKey)) {
                throw new IllegalStateException(
                        "ENGINE_CONTRACT_ERROR: Official finding is missing actual prompt problem field key."
                                + " aggregateRunId=" + safe(aggregateRunId)
                                + ", metricCode=" + safe(finding.metricCode())
                                + ", checkCode=" + safe(finding.checkCode()));
            }
            result.computeIfAbsent(fieldKey, ignored -> new Links()).add(finding);
        }
        for (OperatorRemediationGroup group : queryService.remediationGroups(aggregateRunId)) {
            for (String fieldKey : safeList(group.comparisonFieldKeys())) {
                if (StringUtils.hasText(fieldKey)) {
                    result.computeIfAbsent(fieldKey, ignored -> new Links()).add(group);
                }
            }
        }
        return result;
    }

    private List<String> merged(List<String> left, List<String> right) {
        List<String> result = new ArrayList<>();
        safeList(left).forEach(value -> addUnique(result, value));
        safeList(right).forEach(value -> addUnique(result, value));
        return List.copyOf(result);
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }

    private <T> List<T> safeList(List<T> values) {
        return values == null ? List.of() : values;
    }

    private static void addUnique(List<String> values, String value) {
        if (StringUtils.hasText(value) && !values.contains(value.trim())) {
            values.add(value.trim());
        }
    }

    private static final class Links {
        private final List<String> metricCodes = new ArrayList<>();
        private final List<String> checkCodes = new ArrayList<>();
        private final List<String> findingIds = new ArrayList<>();
        private final List<String> issueIds = new ArrayList<>();
        private final List<String> groupIds = new ArrayList<>();
        private OperatorFinding firstFinding;

        private void add(OperatorFinding finding) {
            if (firstFinding == null) {
                firstFinding = finding;
            }
            addUnique(metricCodes, finding.metricCode());
            addUnique(checkCodes, finding.checkCode());
            addUnique(findingIds, finding.findingId());
            addUnique(issueIds, finding.issueId());
        }

        private void add(OperatorRemediationGroup group) {
            addUnique(groupIds, group.groupId());
            safeList(group.affectedMetricCodes()).forEach(code -> addUnique(metricCodes, code));
            safeList(group.affectedCheckCodes()).forEach(code -> addUnique(checkCodes, code));
        }

        private String firstOwner() {
            return firstFinding == null ? "" : firstFinding.remediationOwner();
        }

        private static <T> List<T> safeList(List<T> values) {
            return values == null ? List.of() : values;
        }
    }
}
